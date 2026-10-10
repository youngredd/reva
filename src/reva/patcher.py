"""Assembling and patching.

Patches are staged in the project database rather than written straight to the
file, so they can be listed, reviewed and reverted, and the original bytes are
always recoverable. Nothing touches the input file: writing out always produces
a new file.
"""
from __future__ import annotations

import os
import time

import keystone as ks

KS_ARCH = {
    "x86_64": (ks.KS_ARCH_X86, ks.KS_MODE_64),
    "x86": (ks.KS_ARCH_X86, ks.KS_MODE_32),
    "arm64": (ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN),
    "arm": (ks.KS_ARCH_ARM, ks.KS_MODE_ARM),
    "thumb": (ks.KS_ARCH_ARM, ks.KS_MODE_THUMB),
}

NOP = {"x86_64": b"\x90", "x86": b"\x90",
       "arm64": b"\x1f\x20\x03\xd5", "arm": b"\x00\xf0\x20\xe3"}


class PatchError(RuntimeError):
    pass


class Patcher:
    def __init__(self, sess):
        self.s = sess
        arch = sess.img.arch
        if arch not in KS_ARCH:
            raise PatchError(f"no assembler for {arch}")
        a, m = KS_ARCH[arch]
        self.ks = ks.Ks(a, m)
        self.nop = NOP.get(arch, b"\x90")

    # ----------------------------------------------------- assembling ---
    def assemble(self, asm: str, va: int = 0) -> bytes:
        """Assemble at `va` so relative branches come out right."""
        src = asm.replace("\n", "; ").strip().strip(";")
        try:
            enc, _ = self.ks.asm(src, va)
        except ks.KsError as e:
            raise PatchError(f"assembly failed: {e}") from e
        if enc is None:
            raise PatchError(f"assembly produced nothing for {asm!r}")
        return bytes(enc)

    def disasm_preview(self, va: int, data: bytes) -> list[str]:
        """Show how the patched bytes will actually decode."""
        out = []
        md = self.s.dis.md
        for i in md.disasm(data, va):
            out.append(f"{i.address:x}  {i.mnemonic} {i.op_str}".rstrip())
        return out

    # -------------------------------------------------------- staging ---
    def stage(self, va: int, data: bytes, note: str = "") -> dict:
        img = self.s.img
        off = img.va_to_off(va)
        if off is None:
            raise PatchError(f"{va:x} has no file backing (uninitialised data "
                             f"or outside the image)")
        if img.va_to_off(va + len(data) - 1) is None:
            raise PatchError(f"patch of {len(data)} bytes at {va:x} runs past "
                             f"the end of its section's file data")
        original = img.read(va, len(data))
        self.s.db.con.execute(
            "INSERT OR REPLACE INTO patches (va,original,patched,note,ts) "
            "VALUES (?,?,?,?,?)",
            (va, original, data, note, int(time.time())))
        self.s.db.commit()
        # reflect it in the in-memory image so analysis and disasm see it
        self._apply_to_image(va, data)
        return {
            "va": f"0x{va:x}", "file_offset": f"0x{off:x}",
            "size": len(data),
            "original": original.hex(), "patched": data.hex(),
            "decodes_as": self.disasm_preview(va, data),
            "note": note,
        }

    def stage_asm(self, va: int, asm: str, note: str = "",
                  pad: bool = True, max_instructions: int = 1) -> dict:
        """Assemble and stage over the instructions at `va`.

        New code shorter than what it replaces is padded with nops out to the
        next instruction boundary, so the patch never ends mid-instruction.
        Replacing more than `max_instructions` has to be asked for explicitly:
        quietly eating the following instruction is how a patch turns into a
        crash somewhere unrelated.
        """
        data = self.assemble(asm, va)
        span, n = self._cover(va, len(data))
        if span < len(data):
            raise PatchError(
                f"cannot decode enough instructions at {va:x} to cover "
                f"{len(data)} assembled bytes (only {span} available)")
        if n > max_instructions:
            raise PatchError(
                f"assembled {len(data)} bytes, which would overwrite {n} "
                f"instructions ({span} bytes) starting at {va:x}:\n"
                + "\n".join("    " + t for t in self._insn_texts(va, n))
                + f"\nPass max_instructions={n} to confirm, or write the "
                  f"longer sequence into a code cave and jump to it.")
        if pad and len(data) < span:
            data = data + self.nop * ((span - len(data)) // len(self.nop))
        res = self.stage(va, data, note)
        res["instructions_replaced"] = n
        return res

    def _cover(self, va: int, want: int) -> tuple[int, int]:
        """(bytes, instruction count) of the whole instructions needed to hold
        `want` bytes starting at `va`."""
        total = 0
        n = 0
        cur = va
        while total < want:
            i = self.s.dis.at(cur)
            if i is None:
                break
            total += i.size
            n += 1
            cur = i.end
        return total, n

    def _insn_texts(self, va: int, count: int) -> list[str]:
        out = []
        cur = va
        for _ in range(count):
            i = self.s.dis.at(cur)
            if i is None:
                break
            out.append(f"{i.va:x}  {i.text}")
            cur = i.end
        return out

    def nop_out(self, va: int, count: int = 1, note: str = "") -> dict:
        span, _ = self._cover(va, 1)
        for _ in range(count - 1):
            more, _ = self._cover(va + span, 1)
            span += more
        n = span // len(self.nop)
        return self.stage(va, self.nop * n, note or f"nop out {count} insn(s)")

    def _apply_to_image(self, va: int, data: bytes) -> None:
        sec = self.s.img.section_at(va)
        if sec is None:
            return
        off = va - sec.va
        buf = bytearray(sec.data)
        buf[off:off + len(data)] = data
        sec.data = bytes(buf)
        self.s.dis._cache.clear()

    # --------------------------------------------------------- listing ---
    def list_patches(self) -> list[dict]:
        out = []
        for r in self.s.db.con.execute(
                "SELECT va,original,patched,note,ts FROM patches ORDER BY va"):
            out.append({
                "va": f"0x{r['va']:x}", "size": len(r["patched"]),
                "original": bytes(r["original"]).hex(),
                "patched": bytes(r["patched"]).hex(),
                "note": r["note"],
                "decodes_as": self.disasm_preview(r["va"], bytes(r["patched"])),
            })
        return out

    def revert(self, va: int) -> dict:
        r = self.s.db.con.execute(
            "SELECT original FROM patches WHERE va=?", (va,)).fetchone()
        if not r:
            raise PatchError(f"no staged patch at {va:x}")
        self._apply_to_image(va, bytes(r["original"]))
        self.s.db.con.execute("DELETE FROM patches WHERE va=?", (va,))
        self.s.db.commit()
        return {"reverted": f"0x{va:x}"}

    def revert_all(self) -> dict:
        n = 0
        for r in self.s.db.con.execute(
                "SELECT va, original FROM patches").fetchall():
            self._apply_to_image(r["va"], bytes(r["original"]))
            n += 1
        self.s.db.con.execute("DELETE FROM patches")
        self.s.db.commit()
        return {"reverted": n}

    # ----------------------------------------------------------- write ---
    def write_file(self, out_path: str, overwrite: bool = False) -> dict:
        """Produce a patched copy. The input file is never modified."""
        src = self.s.path
        out_path = os.path.abspath(out_path)
        if os.path.abspath(src) == out_path:
            raise PatchError("refusing to overwrite the binary being analysed; "
                             "choose a different output path")
        if os.path.exists(out_path) and not overwrite:
            raise PatchError(f"{out_path} exists (pass overwrite=true)")
        with open(src, "rb") as f:
            data = bytearray(f.read())
        applied = []
        for r in self.s.db.con.execute(
                "SELECT va,original,patched FROM patches ORDER BY va"):
            off = self.s.img.va_to_off(r["va"])
            if off is None:
                continue
            cur = bytes(data[off:off + len(r["original"])])
            if cur != bytes(r["original"]):
                raise PatchError(
                    f"file bytes at 0x{r['va']:x} (offset 0x{off:x}) are not "
                    f"what was recorded as original: expected "
                    f"{bytes(r['original']).hex()}, found {cur.hex()}. The "
                    f"source file changed since the patch was staged.")
            data[off:off + len(r["patched"])] = r["patched"]
            applied.append({"va": f"0x{r['va']:x}", "offset": f"0x{off:x}",
                            "size": len(r["patched"])})
        with open(out_path, "wb") as f:
            f.write(bytes(data))
        return {"written": out_path, "size": len(data),
                "patches_applied": applied,
                "note": "PE checksum not recalculated; signatures are now "
                        "invalid, which matters for signed binaries"}
