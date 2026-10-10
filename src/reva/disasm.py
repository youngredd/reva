"""Capstone wrapper producing a normalised instruction model.

The point of the normalisation is that every consumer (analysis, renderer,
lifter, emulator) sees resolved branch targets and resolved rip-relative
effective addresses instead of raw operand text.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import capstone as cs
from capstone import x86 as csx

ARCH_MAP = {
    "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
    "x86":    (cs.CS_ARCH_X86, cs.CS_MODE_32),
    "arm64":  (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
    "arm":    (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
    "thumb":  (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
}

# instructions after which control flow does not continue linearly
_NORET_MNEM = {"ret", "retf", "retn", "iret", "iretd", "iretq", "ud2", "ud0", "ud1"}


@dataclass
class MemRef:
    """A resolved memory reference made by an instruction."""
    ea: int                 # effective address, if statically known
    kind: str               # read | write | offset
    size: int = 0
    rip_rel: bool = False


@dataclass
class Insn:
    va: int
    size: int
    mnem: str
    ops: str
    raw: bytes
    is_call: bool = False
    is_jump: bool = False
    is_cond: bool = False
    is_ret: bool = False
    is_int3: bool = False
    is_nop: bool = False
    is_indirect: bool = False
    is_priv: bool = False
    target: int | None = None          # direct branch/call target
    mem: list[MemRef] = field(default_factory=list)
    memops: list[dict] = field(default_factory=list)   # raw base/index/scale/disp
    imms: list[int] = field(default_factory=list)
    regs_read: tuple = ()
    regs_write: tuple = ()
    reg_ops: list[str] = field(default_factory=list)   # register operands, in order
    _ci: object = None                 # underlying capstone insn

    @property
    def end(self) -> int:
        return self.va + self.size

    @property
    def flows_on(self) -> bool:
        """Does execution fall through to the next instruction?"""
        if self.is_ret or self.mnem in _NORET_MNEM:
            return False
        if self.is_jump and not self.is_cond:
            return False
        return True

    @property
    def text(self) -> str:
        return f"{self.mnem} {self.ops}".strip()


class Disassembler:
    def __init__(self, image):
        self.image = image
        arch, mode = ARCH_MAP.get(image.arch, (cs.CS_ARCH_X86, cs.CS_MODE_64))
        self.md = cs.Cs(arch, mode)
        self.md.detail = True
        self.md.skipdata = False
        self.is_x86 = arch == cs.CS_ARCH_X86
        self._cache: dict[int, Insn | None] = {}

    # ---- single instruction -------------------------------------------
    def at(self, va: int) -> Insn | None:
        if va in self._cache:
            return self._cache[va]
        out = None
        data = self.image.read(va, 16)
        if data:
            for ci in self.md.disasm(data, va, 1):
                out = self._convert(ci)
                break
        if len(self._cache) > 400_000:
            self._cache.clear()
        self._cache[va] = out
        return out

    # ---- linear sweep --------------------------------------------------
    def sweep(self, va: int, end: int):
        """Disassemble linearly from va up to (not including) end."""
        cur = va
        while cur < end:
            i = self.at(cur)
            if i is None:
                cur += 1
                continue
            yield i
            cur = i.end

    def take(self, va: int, count: int):
        cur, n = va, 0
        while n < count:
            i = self.at(cur)
            if i is None:
                return
            yield i
            cur = i.end
            n += 1

    # ---- conversion ----------------------------------------------------
    def _convert(self, ci) -> Insn:
        groups = set(ci.groups or ())
        ins = Insn(va=ci.address, size=ci.size, mnem=ci.mnemonic,
                   ops=ci.op_str, raw=bytes(ci.bytes), _ci=ci)
        ins.is_call = cs.CS_GRP_CALL in groups
        ins.is_jump = cs.CS_GRP_JUMP in groups
        ins.is_ret = cs.CS_GRP_RET in groups or ci.mnemonic in _NORET_MNEM
        ins.is_priv = cs.CS_GRP_PRIVILEGE in groups

        if self.is_x86:
            self._x86_detail(ci, ins)
        else:
            self._generic_detail(ci, ins)
        return ins

    def _x86_detail(self, ci, ins: Insn) -> None:
        m = ci.mnemonic
        ins.is_int3 = m == "int3"
        ins.is_nop = m in ("nop", "pause") or (m == "xchg" and ci.op_str == "ax, ax")
        ins.is_cond = ins.is_jump and m not in ("jmp", "ljmp")

        try:
            r, w = ci.regs_access()
            ins.regs_read = tuple(ci.reg_name(x) for x in r)
            ins.regs_write = tuple(ci.reg_name(x) for x in w)
        except Exception:
            pass

        next_va = ci.address + ci.size
        img = self.image
        operands = getattr(ci, "operands", None) or ()

        for op in operands:
            if op.type == csx.X86_OP_IMM:
                v = op.imm
                if ins.is_call or ins.is_jump:
                    ins.target = v
                else:
                    ins.imms.append(v)
                    # an immediate that lands inside the image is probably a pointer
                    if v and img.is_valid(v):
                        ins.mem.append(MemRef(v, "offset", 0, False))
            elif op.type == csx.X86_OP_MEM:
                mem = op.mem
                ea = None
                rip = False
                ins.memops.append({
                    "base": ci.reg_name(mem.base) if mem.base else None,
                    "index": ci.reg_name(mem.index) if mem.index else None,
                    "scale": mem.scale,
                    "disp": mem.disp,
                    "size": op.size,
                    "seg": ci.reg_name(mem.segment) if mem.segment else None,
                    "access": getattr(op, "access", 0),
                })
                if mem.base == csx.X86_REG_RIP and mem.index == 0:
                    ea = next_va + mem.disp
                    rip = True
                elif mem.base == 0 and mem.index == 0:
                    ea = mem.disp & 0xFFFFFFFFFFFFFFFF
                if ea is not None and img.is_valid(ea):
                    acc = getattr(op, "access", 0)
                    if acc & cs.CS_AC_WRITE:
                        kind = "write"
                    elif acc & cs.CS_AC_READ:
                        kind = "read"
                    else:
                        kind = "offset"
                    # lea never dereferences: it takes an address
                    if m == "lea":
                        kind = "offset"
                    ins.mem.append(MemRef(ea, kind, op.size, rip))
                    # call/jmp through a known slot -> indirect call to [ea]
                    if (ins.is_call or ins.is_jump) and ins.target is None:
                        ins.target = None
                        ins.is_indirect = True
                        ins.mem[-1].kind = "read"
            elif op.type == csx.X86_OP_REG:
                ins.reg_ops.append(ci.reg_name(op.reg))
                if (ins.is_call or ins.is_jump) and ins.target is None:
                    ins.is_indirect = True

        if (ins.is_call or ins.is_jump) and ins.target is None:
            ins.is_indirect = True

    def _generic_detail(self, ci, ins: Insn) -> None:
        ins.is_cond = ins.is_jump and bool(getattr(ci, "cc", 0) not in (0, 14, 15))
        for op in getattr(ci, "operands", None) or ():
            t = getattr(op, "type", None)
            # arm/arm64 immediate branch operands
            if t in (2, 1) and (ins.is_call or ins.is_jump):
                v = getattr(op, "imm", None)
                if v is not None and ins.target is None:
                    ins.target = v
        if (ins.is_call or ins.is_jump) and ins.target is None:
            ins.is_indirect = True


# ---- prologue signatures used to recover functions in unmapped gaps ----
X64_PROLOGUES = [
    b"\x48\x89\x5c\x24",          # mov [rsp+X], rbx
    b"\x48\x89\x6c\x24",          # mov [rsp+X], rbp
    b"\x48\x89\x74\x24",          # mov [rsp+X], rsi
    b"\x48\x89\x7c\x24",          # mov [rsp+X], rdi
    b"\x48\x89\x4c\x24",          # mov [rsp+X], rcx
    b"\x48\x83\xec",              # sub rsp, imm8
    b"\x48\x81\xec",              # sub rsp, imm32
    b"\x55\x48\x8b\xec",          # push rbp; mov rbp, rsp
    b"\x55\x48\x89\xe5",          # push rbp; mov rbp, rsp (gcc)
    b"\x40\x53",                  # push rbx
    b"\x40\x55",                  # push rbp
    b"\x40\x56",                  # push rsi
    b"\x40\x57",                  # push rdi
    b"\x41\x54",                  # push r12
    b"\x41\x55",                  # push r13
    b"\x41\x56",                  # push r14
    b"\x41\x57",                  # push r15
    b"\x4c\x8b\xdc",              # mov r11, rsp
    b"\x48\x8b\xc4",              # mov rax, rsp
]

X86_PROLOGUES = [
    b"\x55\x8b\xec",              # push ebp; mov ebp, esp
    b"\x55\x89\xe5",              # push ebp; mov ebp, esp (gcc)
    b"\x83\xec",                  # sub esp, imm8
    b"\x81\xec",                  # sub esp, imm32
    b"\x53\x56\x57",              # push ebx; push esi; push edi
    b"\x8b\xff\x55\x8b\xec",      # hotpatch + frame
    b"\x6a",                      # push imm8 (frame-pointer-omission entry)
]

ARM64_PROLOGUES = [
    b"\xfd\x7b\xbf\xa9",          # stp x29, x30, [sp, #-16]!
    b"\xff\x43\x00\xd1",          # sub sp, sp, #0x10
    b"\xf3\x0f\x1e\xf8",          # str x19, [sp, #-32]!
]


def prologues_for(arch: str) -> list[bytes]:
    if arch == "x86_64":
        return X64_PROLOGUES
    if arch == "x86":
        return X86_PROLOGUES
    if arch == "arm64":
        return ARM64_PROLOGUES
    return []
