"""Concrete emulation of code from the loaded image, via Unicorn.

This is the part a static tool cannot do. Point it at a string-decryption
routine, a hash function or an import resolver and it gives the real answer
instead of an educated guess, without ever running the sample as a process.

Imported functions are intercepted rather than executed: every IAT slot is
redirected at a synthetic page of `ret` instructions, so a call to an api is
logged with its arguments and returns a value you control.
"""
from __future__ import annotations

import struct

import unicorn as uc
from unicorn import x86_const as x86

ARCH = {
    "x86_64": (uc.UC_ARCH_X86, uc.UC_MODE_64),
    "x86": (uc.UC_ARCH_X86, uc.UC_MODE_32),
    "arm64": (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM),
    "arm": (uc.UC_ARCH_ARM, uc.UC_MODE_ARM),
}

PAGE = 0x1000
STACK_BASE = 0x7FFF_0000_0000
STACK_SIZE = 0x40000          # 256 KiB
HEAP_BASE = 0x7FFE_0000_0000
HEAP_SIZE = 0x200000          # 2 MiB for caller-supplied buffers
API_BASE = 0x7FFD_0000_0000   # synthetic api trampolines
API_SIZE = 0x40000
MAGIC_RET = 0x7FFC_0000_1000  # pc lands here when the target function returns

X64_ARGS = [x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX,
            x86.UC_X86_REG_R8, x86.UC_X86_REG_R9]
X64_ARGS_SYSV = [x86.UC_X86_REG_RDI, x86.UC_X86_REG_RSI, x86.UC_X86_REG_RDX,
                 x86.UC_X86_REG_RCX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9]

GP64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
GP32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]


def _reg(name: str) -> int:
    return getattr(x86, f"UC_X86_REG_{name.upper()}")


class EmuError(RuntimeError):
    pass


class Emulator:
    """One emulator instance per run; cheap enough to recreate each time."""

    def __init__(self, sess, *, api_returns: dict | None = None,
                 trace: bool = False, trace_limit: int = 2000,
                 cc: str | None = None):
        self.s = sess
        self.img = sess.img
        # for a raw blob there is nothing in the file to tell us the calling
        # convention, so it has to be stated rather than guessed
        self.cc = cc or ("ms64" if self.img.fmt == "pe" else
                         ("sysv64" if self.img.bits == 64 else "cdecl"))
        if self.img.arch not in ARCH:
            raise EmuError(f"emulation not supported for {self.img.arch}")
        a, m = ARCH[self.img.arch]
        self.mu = uc.Uc(a, m)
        self.bits = self.img.bits
        self.api_returns = dict(api_returns or {})
        self.want_trace = trace
        self.trace_limit = trace_limit

        self.api_by_addr: dict[int, str] = {}
        self.calls: list[dict] = []
        self.writes: list[dict] = []
        self.trace: list[int] = []
        self.lazy_maps: list[int] = []
        self.insn_count = 0
        self.heap_next = HEAP_BASE + PAGE
        self.stopped_why = ""
        self._map_image()
        self._map_scratch()
        self._install_api_trampolines()
        self._install_hooks()

    # ------------------------------------------------------- mapping ---
    def _map_image(self) -> None:
        spans: list[tuple[int, int]] = []
        for s in self.img.sections:
            lo = s.va & ~(PAGE - 1)
            hi = (s.end + PAGE - 1) & ~(PAGE - 1)
            spans.append((lo, hi))
        spans.sort()
        merged: list[list[int]] = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        for lo, hi in merged:
            self.mu.mem_map(lo, hi - lo, uc.UC_PROT_ALL)
        for s in self.img.sections:
            if s.data:
                self.mu.mem_write(s.va, bytes(s.data))

    def _map_scratch(self) -> None:
        self.mu.mem_map(STACK_BASE, STACK_SIZE, uc.UC_PROT_ALL)
        self.mu.mem_map(HEAP_BASE, HEAP_SIZE, uc.UC_PROT_ALL)
        self.mu.mem_map(MAGIC_RET & ~(PAGE - 1), PAGE, uc.UC_PROT_ALL)

    def _install_api_trampolines(self) -> None:
        """Point every IAT slot at a unique `ret`, so api calls are observable."""
        self.mu.mem_map(API_BASE, API_SIZE, uc.UC_PROT_ALL)
        self.mu.mem_write(API_BASE, b"\xc3" * API_SIZE)
        rows = self.s.db.con.execute(
            "SELECT va, dll, name, thunk FROM imports").fetchall()
        ptr = struct.Struct("<Q" if self.bits == 64 else "<I")
        for i, r in enumerate(rows):
            if (i + 1) * 16 >= API_SIZE:
                break
            addr = API_BASE + i * 16
            label = f"{r['dll']}!{r['name']}" if r["dll"] else r["name"]
            self.api_by_addr[addr] = label
            try:
                self.mu.mem_write(r["va"], ptr.pack(addr))
            except uc.UcError:
                pass

    # --------------------------------------------------------- hooks ---
    def _install_hooks(self) -> None:
        mu = self.mu
        mu.hook_add(uc.UC_HOOK_CODE, self._on_code)
        mu.hook_add(uc.UC_HOOK_MEM_WRITE, self._on_write)
        mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED |
                    uc.UC_HOOK_MEM_WRITE_UNMAPPED |
                    uc.UC_HOOK_MEM_FETCH_UNMAPPED, self._on_unmapped)

    def _on_code(self, mu, address, size, _):
        self.insn_count += 1
        if self.want_trace and len(self.trace) < self.trace_limit:
            self.trace.append(address)
        if address == MAGIC_RET:
            self.stopped_why = "returned"
            mu.emu_stop()
            return
        api = self.api_by_addr.get(address)
        if api is not None:
            self._handle_api(mu, address, api)

    def _handle_api(self, mu, address, api: str) -> None:
        args = self._read_args(4)
        ret = self.api_returns.get(api)
        if ret is None:
            short = api.split("!")[-1]
            ret = self.api_returns.get(short, 0)
        self.calls.append({
            "api": api, "args": [f"0x{a:x}" for a in args],
            "arg_strings": [self._peek_str(a) for a in args],
            "returned": f"0x{ret:x}",
            "from": f"0x{self._caller():x}",
        })
        if self.bits == 64:
            mu.reg_write(x86.UC_X86_REG_RAX, ret)
        else:
            mu.reg_write(x86.UC_X86_REG_EAX, ret)

    def _caller(self) -> int:
        try:
            sp = self.mu.reg_read(x86.UC_X86_REG_RSP if self.bits == 64
                                  else x86.UC_X86_REG_ESP)
            n = self.bits // 8
            return int.from_bytes(self.mu.mem_read(sp, n), "little")
        except Exception:
            return 0

    def _on_write(self, mu, access, address, size, value, _):
        if len(self.writes) < 4000:
            self.writes.append({"addr": address, "size": size, "value": value})

    def _on_unmapped(self, mu, access, address, size, value, _):
        """Map zero-filled pages on demand so a missing pointer does not abort
        the whole run; every such page is reported."""
        if address > 0xFFFF_FFFF_FFFF_0000 or address < PAGE:
            return False
        base = address & ~(PAGE - 1)
        try:
            mu.mem_map(base, PAGE * 4, uc.UC_PROT_ALL)
            self.lazy_maps.append(base)
            return True
        except uc.UcError:
            return False

    # ------------------------------------------------------ arguments ---
    def _arg_regs(self):
        if self.bits != 64:
            return []
        return X64_ARGS_SYSV if self.cc == "sysv64" else X64_ARGS

    def _read_args(self, n: int) -> list[int]:
        regs = self._arg_regs()
        out = []
        for i in range(n):
            if i < len(regs):
                out.append(self.mu.reg_read(regs[i]))
            else:
                sp = self.mu.reg_read(x86.UC_X86_REG_RSP)
                w = self.bits // 8
                try:
                    out.append(int.from_bytes(
                        self.mu.mem_read(sp + (i + 1) * w, w), "little"))
                except Exception:
                    out.append(0)
        return out

    def alloc(self, data: bytes | int) -> int:
        """Place a buffer in scratch memory and return its address."""
        size = len(data) if isinstance(data, bytes) else int(data)
        addr = self.heap_next
        self.heap_next = (addr + size + 0x40) & ~0xF
        if self.heap_next > HEAP_BASE + HEAP_SIZE:
            raise EmuError("emulator scratch heap exhausted")
        if isinstance(data, bytes):
            self.mu.mem_write(addr, data)
        else:
            self.mu.mem_write(addr, b"\x00" * size)
        return addr

    def _peek_str(self, addr: int, limit: int = 100) -> str | None:
        if addr < PAGE:
            return None
        try:
            raw = bytes(self.mu.mem_read(addr, limit))
        except uc.UcError:
            return None
        a = raw.split(b"\x00")[0]
        if len(a) >= 4 and all(32 <= c < 127 or c in (9, 10, 13) for c in a):
            return a.decode("ascii", "replace")
        # utf-16le
        if len(raw) >= 8 and raw[1] == 0 and raw[3] == 0:
            i = 0
            while i + 1 < len(raw) and raw[i:i + 2] != b"\x00\x00":
                i += 2
            t = raw[:i].decode("utf-16-le", "replace")
            if len(t) >= 3 and all(32 <= ord(c) < 127 or c in "\t\r\n" for c in t):
                return t
        return None

    # ----------------------------------------------------------- run ---
    def run_function(self, va: int, args: list | None = None, *,
                     max_insn: int = 2_000_000, timeout_us: int = 10_000_000,
                     stop_at: int | None = None,
                     capture: list[tuple[int, int]] | None = None) -> dict:
        """Call `va` with `args` and report what happened.

        Each arg may be an int (passed as-is), bytes (copied into scratch memory,
        pointer passed), or {"alloc": n} for an output buffer of n zero bytes.
        """
        mu = self.mu
        args = args or []
        prepared: list[int] = []
        allocated: list[tuple[int, int]] = []
        for a in args:
            if isinstance(a, bytes):
                p = self.alloc(a)
                allocated.append((p, len(a)))
                prepared.append(p)
            elif isinstance(a, dict) and "alloc" in a:
                n = int(a["alloc"])
                p = self.alloc(n)
                allocated.append((p, n))
                prepared.append(p)
            elif isinstance(a, str):
                b = a.encode() + b"\x00"
                p = self.alloc(b)
                allocated.append((p, len(b)))
                prepared.append(p)
            else:
                prepared.append(int(a) & 0xFFFFFFFFFFFFFFFF)

        sp = STACK_BASE + STACK_SIZE - 0x2000
        regs = self._arg_regs()
        if self.bits == 64:
            # home space for the four register args, per the ms x64 abi
            sp -= 0x40
            mu.reg_write(x86.UC_X86_REG_RSP, sp)
            for i, v in enumerate(prepared):
                if i < len(regs):
                    mu.reg_write(regs[i], v)
                else:
                    mu.mem_write(sp + 8 * (i + 1), struct.pack("<Q", v))
            sp -= 8
            mu.mem_write(sp, struct.pack("<Q", MAGIC_RET))
            mu.reg_write(x86.UC_X86_REG_RSP, sp)
            mu.reg_write(x86.UC_X86_REG_RBP, sp)
        else:
            for i, v in enumerate(reversed(prepared)):
                sp -= 4
                mu.mem_write(sp, struct.pack("<I", v))
            sp -= 4
            mu.mem_write(sp, struct.pack("<I", MAGIC_RET & 0xFFFFFFFF))
            mu.reg_write(x86.UC_X86_REG_ESP, sp)

        err = None
        self.stopped_why = ""
        end = stop_at if stop_at is not None else 0
        try:
            mu.emu_start(va, end, timeout=timeout_us, count=max_insn)
            if not self.stopped_why:
                self.stopped_why = "stop_address" if stop_at else "limit"
        except uc.UcError as e:
            err = f"{e} (uc errno {e.errno})"
            self.stopped_why = "fault"

        res = {
            "entry": f"0x{va:x}",
            "stopped": self.stopped_why,
            "instructions": self.insn_count,
            "error": err,
            "api_calls": self.calls,
            "lazily_mapped_pages": [f"0x{a:x}" for a in self.lazy_maps[:20]],
        }
        if err:
            res["fault_rip"] = f"0x{self.reg('rip'):x}"
        res["return_value"] = f"0x{self.reg('rax' if self.bits == 64 else 'eax'):x}"
        res["registers"] = self.regs()
        # whatever the caller gave us as output buffers is usually the answer
        outs = []
        for p, n in allocated:
            raw = self.read(p, n)
            outs.append({"addr": f"0x{p:x}", "size": n, "hex": raw.hex(),
                         "ascii": self._printable(raw),
                         "utf16": self._printable_u16(raw)})
        if outs:
            res["buffers"] = outs
        if capture:
            res["captured"] = [
                {"addr": f"0x{a:x}", "size": n, "hex": self.read(a, n).hex(),
                 "ascii": self._printable(self.read(a, n))}
                for a, n in capture]
        if self.want_trace:
            res["trace"] = [f"0x{a:x}" for a in self.trace]
        res["memory_writes"] = self._summarize_writes()
        return res

    def _summarize_writes(self) -> list[dict]:
        """Group writes into contiguous regions; the content is what matters."""
        if not self.writes:
            return []
        ws = sorted(self.writes, key=lambda w: w["addr"])
        groups: list[list[int]] = []
        for w in ws:
            a, b = w["addr"], w["addr"] + w["size"]
            if groups and a <= groups[-1][1] + 8:
                groups[-1][1] = max(groups[-1][1], b)
            else:
                groups.append([a, b])
        out = []
        for a, b in groups[:40]:
            n = min(b - a, 256)
            raw = self.read(a, n)
            out.append({"addr": f"0x{a:x}", "size": b - a, "hex": raw.hex(),
                        "ascii": self._printable(raw),
                        "utf16": self._printable_u16(raw)})
        return out

    @staticmethod
    def _printable(b: bytes) -> str:
        return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

    @staticmethod
    def _printable_u16(b: bytes) -> str | None:
        if len(b) < 4 or b[1] != 0:
            return None
        try:
            t = b.decode("utf-16-le", "ignore")
        except Exception:
            return None
        t = t.split("\x00")[0]
        return t if len(t) >= 3 else None

    # ------------------------------------------------------- access ----
    def reg(self, name: str) -> int:
        try:
            return self.mu.reg_read(_reg(name))
        except Exception:
            return 0

    def regs(self) -> dict:
        names = GP64 if self.bits == 64 else GP32
        return {n: f"0x{self.reg(n):x}" for n in names}

    def read(self, addr: int, size: int) -> bytes:
        try:
            return bytes(self.mu.mem_read(addr, size))
        except uc.UcError:
            return b""

    def write(self, addr: int, data: bytes) -> None:
        self.mu.mem_write(addr, data)


# ------------------------------------------------------- convenience ---
def decrypt_strings(sess, func_va: int, cases: list[dict], **kw) -> list[dict]:
    """Run a decoder repeatedly. Each case is the argument list for one call,
    which keeps this useful for any signature the decoder happens to have."""
    out = []
    for c in cases:
        em = Emulator(sess, **kw)
        try:
            r = em.run_function(func_va, c.get("args", []),
                                max_insn=c.get("max_insn", 200_000))
            out.append({"args": [str(a) for a in c.get("args", [])],
                        "stopped": r["stopped"], "error": r["error"],
                        "return_value": r["return_value"],
                        "buffers": r.get("buffers", []),
                        "writes": r["memory_writes"][:6]})
        except Exception as e:
            out.append({"args": [str(a) for a in c.get("args", [])],
                        "error": f"{type(e).__name__}: {e}"})
    return out
