"""A pseudo-C lifter for x86 / x86-64.

Scope and honesty about it: this is expression propagation plus light control
flow structuring, not a decompiler with real type inference. What it buys over
raw assembly is that calls carry their arguments, memory accesses carry their
widths, branch conditions read as conditions, and locals keep stable names.

Deliberate approximations, all of them visible in the output when they matter:
  * A write to a sub-register (al, ax, eax) is modelled as writing the whole
    register. For compiler output this is what the source meant; it is formally
    wrong for 8/16-bit writes that meant to preserve the upper bits.
  * Each basic block starts from a clean store, so values are only propagated
    inside a block. Cross-block values show up as plain register names.
  * Flags are modelled only as "the last comparison", which covers compiler
    output but not hand-written arithmetic-flag tricks.
  * Any instruction the lifter does not model is emitted verbatim as `__asm`
    and its destination registers are invalidated, so nothing is silently wrong.
"""
from __future__ import annotations

import json
import re

PREC = {
    "*": 80, "/": 80, "%": 80,
    "+": 75, "-": 75,
    "<<": 70, ">>": 70,
    "<": 65, ">": 65, "<=": 65, ">=": 65,
    "==": 60, "!=": 60,
    "&": 55, "^": 50, "|": 45, "&&": 40, "||": 35,
}

SIZE_T = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
SIZE_S = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}

# canonical 64-bit name for every general register
_R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
CANON: dict[str, str] = {}
for _r in _R64:
    CANON[_r] = _r
for _full, _parts in {
    "rax": ("eax", "ax", "al", "ah"), "rcx": ("ecx", "cx", "cl", "ch"),
    "rdx": ("edx", "dx", "dl", "dh"), "rbx": ("ebx", "bx", "bl", "bh"),
    "rsp": ("esp", "sp", "spl"), "rbp": ("ebp", "bp", "bpl"),
    "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
}.items():
    for _p in _parts:
        CANON[_p] = _full
for _i in range(8, 16):
    for _sfx in ("d", "w", "b"):
        CANON[f"r{_i}{_sfx}"] = f"r{_i}"

REG_SIZE = {}
for _r in _R64:
    REG_SIZE[_r] = 8
for _r in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"):
    REG_SIZE[_r] = 4
for _r in ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di"):
    REG_SIZE[_r] = 2
for _r in ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
           "spl", "bpl", "sil", "dil"):
    REG_SIZE[_r] = 1
for _i in range(8, 16):
    REG_SIZE[f"r{_i}d"] = 4
    REG_SIZE[f"r{_i}w"] = 2
    REG_SIZE[f"r{_i}b"] = 1
# vector registers are modelled as opaque values of their natural width, which
# is enough to follow data flow through memcpy-style and crypto-style code
for _i in range(32):
    for _p, _w in (("xmm", 16), ("ymm", 32), ("zmm", 64)):
        CANON[f"{_p}{_i}"] = f"{_p}{_i}"
        REG_SIZE[f"{_p}{_i}"] = _w

CC_SIGNED = {"l": "<", "le": "<=", "g": ">", "ge": ">=",
             "nl": ">=", "nle": ">", "ng": "<=", "nge": "<"}
CC_UNSIGNED = {"b": "<", "be": "<=", "a": ">", "ae": ">=",
               "nb": ">=", "nbe": ">", "na": "<=", "nae": "<",
               "c": "<", "nc": ">="}
CC_EQ = {"e": "==", "z": "==", "ne": "!=", "nz": "!="}

ARG_REGS = {
    "ms64": ["rcx", "rdx", "r8", "r9"],
    "sysv64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
}

SSE_MOV = {"movups", "movaps", "movdqa", "movdqu", "movd", "movq",
           "movss", "movsd", "movlpd", "movhpd", "lddqu", "movntdq",
           "vmovups", "vmovaps", "vmovdqa", "vmovdqu", "vmovd", "vmovq"}

FLT_BIN = {"addsd": "+", "addss": "+", "subsd": "-", "subss": "-",
           "mulsd": "*", "mulss": "*", "divsd": "/", "divss": "/",
           "addps": "+", "subps": "-", "mulps": "*", "divps": "/",
           "addpd": "+", "subpd": "-", "mulpd": "*", "divpd": "/",
           "paddb": "+", "paddw": "+", "paddd": "+", "paddq": "+",
           "psubb": "-", "psubw": "-", "psubd": "-", "psubq": "-",
           "pand": "&", "por": "|", "andps": "&", "orps": "|",
           "andpd": "&", "orpd": "|"}

SSE_FN = {"cvtsi2sd": "__to_double", "cvtsi2ss": "__to_float",
          "cvttsd2si": "__to_int", "cvttss2si": "__to_int",
          "cvtsd2ss": "__to_float", "cvtss2sd": "__to_double",
          "cvtdq2pd": "__to_double", "cvtdq2ps": "__to_float",
          "sqrtsd": "__sqrt", "sqrtss": "__sqrtf",
          "punpcklbw": "__punpcklbw", "punpcklqdq": "__punpcklqdq",
          "pshufb": "__pshufb", "pshufd": "__pshufd",
          "psrldq": "__psrldq", "pslldq": "__pslldq",
          "psrld": "__psrld", "pslld": "__pslld",
          "pcmpeqb": "__pcmpeqb", "pcmpeqd": "__pcmpeqd",
          "pmovmskb": "__pmovmskb", "pminub": "__pminub",
          "unpcklpd": "__unpcklpd", "unpcklps": "__unpcklps",
          "aesenc": "__aesenc", "aesenclast": "__aesenclast",
          "aesdec": "__aesdec", "aesdeclast": "__aesdeclast",
          "aeskeygenassist": "__aeskeygen", "pclmulqdq": "__pclmulqdq",
          "crc32": "__crc32", "sha256rnds2": "__sha256rnds2",
          "sha256msg1": "__sha256msg1", "sha256msg2": "__sha256msg2"}


# ===================================================== expressions ====
# An expression tree is really a DAG: `lea rdx,[rdi+rdi]` shares one operand
# twice, and a register accumulating over a long block shares its own previous
# value. Rendering a shared subtree expands it once per reference, so without a
# cost budget the output grows exponentially. `cost` is the node count used to
# decide when to materialise a value into a named variable instead.
EXPR_BUDGET = 40
RENDER_DEPTH = 40


class E:
    __slots__ = ("op", "a", "b", "size", "txt", "signed", "cost")

    def __init__(self, op, a=None, b=None, size=0, txt="", signed=False):
        self.op, self.a, self.b = op, a, b
        self.size, self.txt, self.signed = size, txt, signed
        c = 1
        if isinstance(a, E):
            c += a.cost
        if isinstance(b, E):
            c += b.cost
        elif isinstance(b, (list, tuple)):
            c += sum(x.cost for x in b if isinstance(x, E))
        self.cost = c

    # -- constructors
    @staticmethod
    def const(v, size=8):
        return E("const", a=v, size=size)

    @staticmethod
    def name(t, size=8):
        return E("name", txt=t, size=size)

    @staticmethod
    def top(t="?", size=8):
        return E("top", txt=t, size=size)

    @staticmethod
    def load(addr, size):
        return E("load", a=addr, size=size)

    @staticmethod
    def bin(o, a, b, size=0, signed=False):
        return E("bin", a=a, b=b, txt=o, size=size or max(a.size, b.size),
                 signed=signed)

    @staticmethod
    def un(o, a):
        return E("un", a=a, txt=o, size=a.size)

    @staticmethod
    def cast(a, size, signed=False):
        # `(uint32_t)(uint32_t)x` adds nothing but noise
        if a.op == "cast" and a.size == size and a.signed == signed:
            return a
        if a.op == "const":
            return E.const(a.a & ((1 << (size * 8)) - 1), size)
        return E("cast", a=a, size=size, signed=signed)

    @staticmethod
    def call(target, args, size=8):
        return E("call", a=target, b=args, size=size)

    # -- rendering
    @property
    def prec(self) -> int:
        if self.op == "bin":
            return PREC.get(self.txt, 50)
        if self.op in ("un", "cast", "load"):
            return 90
        return 100

    def render(self, outer: int = 0, depth: int = 0) -> str:
        if depth > RENDER_DEPTH:
            return "/*deep*/"
        s = self._render(depth + 1)
        return f"({s})" if self.prec < outer else s

    def _render(self, depth: int = 0) -> str:
        op = self.op
        if op == "const":
            v = self.a
            if -9 <= v <= 9:
                return str(v)
            if v < 0:
                return f"-0x{-v:x}"
            return f"0x{v:x}"
        if op in ("name", "top"):
            return self.txt
        if op == "load":
            t = SIZE_T.get(self.size, "uint64_t")
            return f"*({t} *){self.a.render(95, depth)}"
        if op == "bin":
            return (f"{self.a.render(self.prec, depth)} {self.txt} "
                    f"{self.b.render(self.prec + 1, depth)}")
        if op == "un":
            return f"{self.txt}{self.a.render(90, depth)}"
        if op == "cast":
            t = (SIZE_S if self.signed else SIZE_T).get(self.size, "uint64_t")
            return f"({t}){self.a.render(90, depth)}"
        if op == "call":
            args = ", ".join(x.render(0, depth) for x in (self.b or []))
            return f"{self.a.render(95, depth)}({args})"
        return "?"

    def is_const(self) -> bool:
        return self.op == "const"

    def __repr__(self):
        return self.render()


def _add(a: E, b: E) -> E:
    """Fold constants so address arithmetic stays legible."""
    if a.is_const() and b.is_const():
        return E.const(a.a + b.a, max(a.size, b.size))
    if b.is_const() and b.a == 0:
        return a
    if a.is_const() and a.a == 0:
        return b
    if b.is_const() and b.a < 0:
        return E.bin("-", a, E.const(-b.a, b.size))
    return E.bin("+", a, b)


# ========================================================= lifter =====
class Lifter:
    def __init__(self, sess):
        self.s = sess

    # ------------------------------------------------------- public ---
    def decompile(self, fva: int, *, max_blocks: int = 2000) -> str:
        s = self.s
        f = s.db.func_at(fva)
        if f is None:
            raise ValueError(f"no recovered function at {fva:x}")
        blocks = s.blocks_of(fva)
        if not blocks:
            raise ValueError(f"function {fva:x} has no blocks")
        if len(blocks) > max_blocks:
            blocks = blocks[:max_blocks]

        self.cc = "ms64" if s.img.fmt == "pe" and s.img.bits == 64 else (
            "sysv64" if s.img.bits == 64 else "cdecl")
        bmap = {b["va"]: b for b in blocks}
        order = [b["va"] for b in blocks]

        # who jumps where, so we only keep labels that are needed
        preds: dict[int, set[int]] = {}
        for b in blocks:
            for t in b["succs"]:
                preds.setdefault(t, set()).add(b["va"])
        self.preds = preds

        body: list[tuple[int, int, str]] = []   # (indent, block_va, text)
        loops = self._find_loops(blocks, order)

        emitted: list[str] = []
        indent = 1
        open_loops: list[tuple[int, int]] = []   # (header, last_block_in_loop)

        for bva in order:
            # close any loop whose body ended on the previous block
            while open_loops and open_loops[-1][1] < bva:
                open_loops.pop()
                indent -= 1
                emitted.append("    " * indent + "}")
            if bva in loops:
                emitted.append("    " * indent + "while (true) {")
                open_loops.append((bva, loops[bva]))
                indent += 1

            # emit a label for every block anything branches to; the unused
            # ones get removed in postprocessing, but a missing one would leave
            # a `goto` with no target
            if bva in preds:
                emitted.append("    " * max(0, indent - 1) +
                               f"{self._label(bva)}:")
            for line in self._block(bmap[bva], order, loops, open_loops):
                emitted.append("    " * indent + line)

        while open_loops:
            open_loops.pop()
            indent -= 1
            emitted.append("    " * indent + "}")

        text = self._postprocess(emitted, order)
        return self._signature(fva, f) + " {\n" + text + "\n}\n"

    # ------------------------------------------------------ helpers ---
    def _label(self, va: int) -> str:
        return f"LAB_{va:x}"

    def _signature(self, fva: int, f) -> str:
        s = self.s
        if f["prototype"]:
            return f["prototype"]
        fp = s.fingerprint(fva)
        n = fp.get("args", 0)
        if n < 0:
            n = 0
        regs = ARG_REGS.get(self.cc, [])
        args = ", ".join(f"int64_t {regs[i] if i < len(regs) else f'a{i}'}"
                         for i in range(min(n, len(regs) or n))) or "void"
        name = s.sym(fva)
        head = f"int64_t {name}({args})"
        prof = fp.get("summary", "")
        return (f"/* {name} @ {fva:x}  ({prof}) */\n"
                f"/* lifted by reva: expression propagation, not a full "
                f"decompiler */\n{head}")

    def _find_loops(self, blocks, order) -> dict[int, int]:
        """header -> last block address of the loop body, for back edges."""
        loops: dict[int, int] = {}
        for b in blocks:
            for t in b["succs"]:
                if t <= b["va"]:
                    loops[t] = max(loops.get(t, 0), b["va"])
        # drop nested/overlapping headers we cannot emit as plain while(true)
        keep: dict[int, int] = {}
        for h in sorted(loops):
            if any(h2 < h <= e2 and loops[h] > e2 for h2, e2 in keep.items()):
                continue
            keep[h] = loops[h]
        return keep

    # -------------------------------------------------- block lifting --
    def _block(self, b, order, loops, open_loops) -> list[str]:
        s = self.s
        self.store: dict[str, E] = {}
        self.slots: dict[str, E] = {}
        self.cmp: tuple | None = None
        out: list[str] = []

        insns = list(s.dis.sweep(b["va"], b["end"]))
        for idx, ins in enumerate(insns):
            last = idx == len(insns) - 1
            try:
                self._insn(ins, out, last, b, order)
            except Exception as e:  # never let one instruction kill the output
                out.append(f"__asm(\"{ins.text}\");  /* lift error: {e} */")
                self.store.clear()
        return out

    # ---- operand access ---------------------------------------------
    def _rd_reg(self, name: str) -> E:
        c = CANON.get(name)
        if c is None:
            return E.top(name, 8)
        size = REG_SIZE.get(name, 8)
        cur = self.store.get(c)
        if cur is None:
            cur = E.name(c, 8)
        if size != 8 and size != cur.size:
            return E.cast(cur, size)
        return cur

    def _wr_reg(self, name: str, val: E, out: list[str] | None = None) -> None:
        c = CANON.get(name)
        if c is None:
            return
        size = REG_SIZE.get(name, 8)
        # writing a 32-bit register zero-extends on x86-64
        v = val if size == 8 else E.cast(val, size)
        if v.cost > EXPR_BUDGET and out is not None:
            # too big to keep propagating: name it and carry the name forward
            out.append(f"{c} = {v.render(0)};")
            v = E.name(c, 8)
        self.store[c] = v

    def _slot_key(self, mo) -> str | None:
        base = mo.get("base")
        if base in ("rsp", "esp"):
            d = mo["disp"]
            return f"sv_{d:x}" if d >= 0 else f"sv_n{-d:x}"
        if base in ("rbp", "ebp"):
            d = mo["disp"]
            return f"var_{-d:x}" if d < 0 else f"arg_{d:x}"
        return None

    def _addr_of(self, ins, mo) -> E:
        """Symbolic address for a memory operand."""
        s = self.s
        base, index = mo.get("base"), mo.get("index")
        disp = mo["disp"]
        if base == "rip":
            ea = ins.end + disp
            return E.name(f"&{s.sym(ea)}", 8)
        acc: E | None = None
        if base:
            acc = self._rd_reg(base)
        if index:
            iv = self._rd_reg(index)
            sc = mo.get("scale", 1)
            if sc and sc != 1:
                iv = E.bin("*", iv, E.const(sc, 8))
            acc = iv if acc is None else E.bin("+", acc, iv)
        if acc is None:
            ea = disp & 0xFFFFFFFFFFFFFFFF
            return E.name(f"&{s.sym(ea)}", 8)
        return _add(acc, E.const(disp, 8))

    def _rd_mem(self, ins, mo) -> E:
        k = self._slot_key(mo)
        if k is not None:
            cur = self.slots.get(k)
            return cur if cur is not None else E.name(k, mo["size"])
        return E.load(self._addr_of(ins, mo), mo["size"])

    def _wr_mem(self, ins, mo, val: E, out: list[str]) -> None:
        k = self._slot_key(mo)
        if k is not None:
            out.append(f"{k} = {val.render(0)};")
            self.slots[k] = val if val.cost <= EXPR_BUDGET \
                else E.name(k, mo["size"])
            return
        t = SIZE_T.get(mo["size"], "uint64_t")
        out.append(f"*({t} *){self._addr_of(ins, mo).render(95)} = "
                   f"{val.render(0)};")

    def _ops(self, ins) -> list:
        """Normalised operand list: ('reg',name) | ('mem',memop) | ('imm',v)."""
        ci = ins._ci
        res = []
        mi = 0
        for op in getattr(ci, "operands", None) or ():
            if op.type == 1:                     # X86_OP_REG
                res.append(("reg", ci.reg_name(op.reg)))
            elif op.type == 2:                   # X86_OP_IMM
                res.append(("imm", op.imm))
            elif op.type == 3:                   # X86_OP_MEM
                mo = ins.memops[mi] if mi < len(ins.memops) else None
                mi += 1
                res.append(("mem", mo))
            else:
                res.append(("other", None))
        return res

    def _rd(self, ins, o) -> E:
        kind, v = o
        if kind == "reg":
            return self._rd_reg(v)
        if kind == "imm":
            return E.const(v, 8)
        if kind == "mem" and v is not None:
            return self._rd_mem(ins, v)
        return E.top()

    def _wr(self, ins, o, val: E, out: list[str]) -> None:
        kind, v = o
        if kind == "reg":
            self._wr_reg(v, val, out)
        elif kind == "mem" and v is not None:
            self._wr_mem(ins, v, val, out)

    def _opsize(self, ins, o) -> int:
        kind, v = o
        if kind == "reg":
            return REG_SIZE.get(v, 8)
        if kind == "mem" and v is not None:
            return v["size"]
        return 8

    # ---- the instruction dispatcher ---------------------------------
    def _insn(self, ins, out: list[str], last: bool, b, order) -> None:
        m = ins.mnem
        ops = self._ops(ins)

        if ins.is_nop or m in ("nop", "hint_nop", "endbr64", "endbr32"):
            return

        if m == "lea":
            mo = ops[1][1] if len(ops) > 1 and ops[1][0] == "mem" else None
            if mo is not None:
                self._wr(ins, ops[0], self._addr_of(ins, mo), out)
            return

        if m in ("mov", "movabs"):
            self._wr(ins, ops[0], self._rd(ins, ops[1]), out)
            return
        if m in ("movzx", "movzxd"):
            self._wr(ins, ops[0], E.cast(self._rd(ins, ops[1]),
                                         self._opsize(ins, ops[1])), out)
            return
        if m in ("movsx", "movsxd"):
            self._wr(ins, ops[0], E.cast(self._rd(ins, ops[1]),
                                         self._opsize(ins, ops[1]),
                                         signed=True), out)
            return
        if m == "xchg":
            a, c = self._rd(ins, ops[0]), self._rd(ins, ops[1])
            self._wr(ins, ops[0], c, out)
            self._wr(ins, ops[1], a, out)
            return

        BIN = {"add": "+", "sub": "-", "imul": "*", "and": "&", "or": "|",
               "xor": "^", "shl": "<<", "sal": "<<", "shr": ">>", "sar": ">>"}
        if m in BIN and len(ops) >= 2:
            a, c = self._rd(ins, ops[0]), self._rd(ins, ops[1])
            if m == "xor" and ops[0] == ops[1]:
                self._wr(ins, ops[0], E.const(0, self._opsize(ins, ops[0])), out)
                self.cmp = ("test", E.const(0), E.const(0))
                return
            r = E.bin(BIN[m], a, c, signed=(m == "sar"))
            if a.is_const() and c.is_const():
                r = self._fold(BIN[m], a.a, c.a, self._opsize(ins, ops[0]))
            self._wr(ins, ops[0], r, out)
            self.cmp = ("sub" if m == "sub" else "logic", r, E.const(0))
            return
        if m == "imul" and len(ops) == 3:
            self._wr(ins, ops[0], E.bin("*", self._rd(ins, ops[1]),
                                        self._rd(ins, ops[2])), out)
            return
        if m in ("inc", "dec"):
            a = self._rd(ins, ops[0])
            r = E.bin("+" if m == "inc" else "-", a, E.const(1, 8))
            self._wr(ins, ops[0], r, out)
            self.cmp = ("sub", r, E.const(0))
            return
        if m == "neg":
            self._wr(ins, ops[0], E.un("-", self._rd(ins, ops[0])), out)
            return
        if m == "not":
            self._wr(ins, ops[0], E.un("~", self._rd(ins, ops[0])), out)
            return
        if m in ("rol", "ror"):
            a, c = self._rd(ins, ops[0]), self._rd(ins, ops[1])
            w = self._opsize(ins, ops[0]) * 8
            fn = "__rol" if m == "rol" else "__ror"
            self._wr(ins, ops[0],
                     E.call(E.name(f"{fn}{w}"), [a, c]), out)
            return
        if m == "bswap":
            self._wr(ins, ops[0], E.call(E.name("__builtin_bswap"),
                                         [self._rd(ins, ops[0])]), out)
            return

        if m == "cmp":
            self.cmp = ("cmp", self._rd(ins, ops[0]), self._rd(ins, ops[1]))
            return
        if m == "test":
            a, c = self._rd(ins, ops[0]), self._rd(ins, ops[1])
            self.cmp = ("test", a, c) if ops[0] != ops[1] else ("test1", a, a)
            return

        if m.startswith("set") and len(ops) >= 1:
            cond = self._cond(m[3:])
            self._wr(ins, ops[0], E.call(E.name(""), []) if cond is None
                     else E.bin("!=", E.name(f"({cond})"), E.const(0)), out)
            if cond:
                self._wr(ins, ops[0], E.name(f"({cond})"), out)
            return
        if m.startswith("cmov") and len(ops) >= 2:
            cond = self._cond(m[4:]) or "cond"
            a, c = self._rd(ins, ops[0]), self._rd(ins, ops[1])
            self._wr(ins, ops[0],
                     E.name(f"{cond} ? {c.render(0)} : {a.render(0)}"), out)
            return

        if m in ("cdq", "cqo", "cdqe", "cwde"):
            if m == "cdqe":
                self._wr_reg("rax", E.cast(self._rd_reg("eax"), 4, signed=True))
            else:
                self.store["rdx"] = E.name("(rax < 0 ? -1 : 0)")
            return

        if m == "push":
            out.append(f"__push({self._rd(ins, ops[0]).render(0)});")
            return
        if m == "pop":
            self._wr(ins, ops[0], E.call(E.name("__pop"), []), out)
            return

        if ins.is_call:
            self._do_call(ins, out)
            return

        if ins.is_ret:
            rv = self.store.get("rax")
            out.append("return " + (rv.render(0) if rv is not None else "rax")
                       + ";")
            return

        if ins.is_jump:
            self._do_jump(ins, out, b, order)
            return

        if ins.mnem in ("int3", "ud2"):
            out.append("__debugbreak();" if ins.mnem == "int3" else "__ud2();")
            return

        # ---- SSE / AVX: modelled as moves and named operations ----------
        if m in SSE_MOV and len(ops) >= 2:
            self._wr(ins, ops[0], self._rd(ins, ops[1]), out)
            return
        if m in ("xorps", "xorpd", "pxor", "vpxor") and len(ops) >= 2:
            if ops[0] == ops[1]:
                self._wr(ins, ops[0], E.const(0, self._opsize(ins, ops[0])), out)
            else:
                self._wr(ins, ops[0], E.bin("^", self._rd(ins, ops[0]),
                                            self._rd(ins, ops[1])), out)
            return
        if m in FLT_BIN and len(ops) >= 2:
            self._wr(ins, ops[0], E.bin(FLT_BIN[m], self._rd(ins, ops[0]),
                                        self._rd(ins, ops[1])), out)
            return
        if m in SSE_FN and len(ops) >= 2:
            self._wr(ins, ops[0],
                     E.call(E.name(SSE_FN[m]),
                            [self._rd(ins, o) for o in ops[1:]]), out)
            return

        # ---- carry arithmetic, wide multiply/divide, bit tests ----------
        if m in ("adc", "sbb") and len(ops) >= 2:
            o = "+" if m == "adc" else "-"
            r = E.bin(o, E.bin(o, self._rd(ins, ops[0]),
                               self._rd(ins, ops[1])), E.name("__carry", 1))
            self._wr(ins, ops[0], r, out)
            return
        if m in ("mul", "imul") and len(ops) == 1:
            a, b = self._rd_reg("rax"), self._rd(ins, ops[0])
            self._wr_reg("rax", E.bin("*", a, b, signed=(m == "imul")), out)
            self.store["rdx"] = E.name("__mul_hi", 8)
            return
        if m in ("div", "idiv") and len(ops) == 1:
            a, b = self._rd_reg("rax"), self._rd(ins, ops[0])
            sg = m == "idiv"
            self._wr_reg("rdx", E.bin("%", a, b, signed=sg), out)
            self._wr_reg("rax", E.bin("/", a, b, signed=sg), out)
            return
        if m in ("bt", "bts", "btr", "btc") and len(ops) >= 2:
            a, c = self._rd(ins, ops[0]), self._rd(ins, ops[1])
            bit = E.bin("<<", E.const(1, 8), c)
            self.cmp = ("test", a, bit)
            if m == "bts":
                self._wr(ins, ops[0], E.bin("|", a, bit), out)
            elif m == "btr":
                self._wr(ins, ops[0], E.bin("&", a, E.un("~", bit)), out)
            elif m == "btc":
                self._wr(ins, ops[0], E.bin("^", a, bit), out)
            return
        if m in ("popcnt", "lzcnt", "tzcnt", "bsf", "bsr") and len(ops) >= 2:
            self._wr(ins, ops[0],
                     E.call(E.name(f"__{m}"), [self._rd(ins, ops[1])]), out)
            return

        # unmodelled: keep it visible and forget what it wrote
        out.append(f"__asm(\"{ins.text}\");")
        for r in ins.regs_write:
            c = CANON.get(r)
            if c:
                self.store[c] = E.top(c)

    def _fold(self, op, a, b, size) -> E:
        mask = (1 << (size * 8)) - 1
        try:
            if op == "+":
                v = a + b
            elif op == "-":
                v = a - b
            elif op == "*":
                v = a * b
            elif op == "&":
                v = a & b
            elif op == "|":
                v = a | b
            elif op == "^":
                v = a ^ b
            elif op == "<<":
                v = a << (b & 63)
            elif op == ">>":
                v = (a & mask) >> (b & 63)
            else:
                return E.const(0, size)
            return E.const(v & mask, size)
        except Exception:
            return E.const(0, size)

    def _do_call(self, ins, out: list[str]) -> None:
        s = self.s
        tgt = ins.target
        name = None
        if tgt is not None:
            name = s.sym(tgt)
        elif ins.mem:
            nm = s.db.get_name(ins.mem[0].ea)
            if nm:
                name = nm[len("__imp_"):] if nm.startswith("__imp_") else nm
            else:
                name = f"(*{E.load(self._addr_of(ins, ins.memops[0]), 8).render(95)})"
        elif ins.reg_ops:
            name = f"(*{self._rd_reg(ins.reg_ops[0]).render(95)})"
        name = name or "__indirect"

        nargs = self._callee_argc(tgt, ins)
        regs = ARG_REGS.get(self.cc, [])
        args = [self._rd_reg(r) for r in regs[:nargs]]
        if nargs > len(regs):
            args.append(E.name(f"/* +{nargs - len(regs)} stack args */"))
        call = E.call(E.name(name), args)
        out.append(f"rax = {call.render(0)};")
        # the call clobbers the volatile registers
        for r in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
            self.store.pop(r, None)
        self.store["rax"] = E.name("rax")
        self.cmp = None

    def _callee_argc(self, tgt, ins) -> int:
        """Prefer what the callee looks like it reads, but never show fewer
        arguments than the caller visibly set up."""
        s = self.s
        declared = 0
        if tgt is not None:
            fp = s.fingerprint(tgt)
            n = fp.get("args")
            if isinstance(n, int) and n >= 0:
                declared = min(n, 8)
            elif s.db.con.execute(
                    "SELECT 1 FROM imports WHERE thunk=? OR va=? LIMIT 1",
                    (tgt, tgt)).fetchone():
                declared = 4
        regs = ARG_REGS.get(self.cc, [])
        setup = 0
        for i, r in enumerate(regs):
            if r in self.store:
                setup = i + 1
        return max(declared, setup)

    def _cond(self, cc: str) -> str | None:
        if self.cmp is None:
            return None
        kind, a, b = self.cmp
        if cc in CC_EQ:
            o = CC_EQ[cc]
            if kind == "test1":
                return f"{a.render(60)} {o} 0"
            if kind == "test":
                return f"({a.render(55)} & {b.render(56)}) {o} 0"
            return f"{a.render(60)} {o} {b.render(61)}"
        if cc in CC_SIGNED:
            o = CC_SIGNED[cc]
            if kind in ("test", "test1", "logic"):
                return f"(int64_t){a.render(90)} {o} 0"
            return f"(int64_t){a.render(90)} {o} (int64_t){b.render(90)}"
        if cc in CC_UNSIGNED:
            o = CC_UNSIGNED[cc]
            if kind in ("test", "test1", "logic"):
                return f"{a.render(65)} {o} 0"
            return f"{a.render(65)} {o} {b.render(66)}"
        if cc == "s":
            return f"(int64_t){a.render(90)} < 0"
        if cc == "ns":
            return f"(int64_t){a.render(90)} >= 0"
        return None

    def _do_jump(self, ins, out: list[str], b, order) -> None:
        s = self.s
        if ins.is_cond:
            cc = ins.mnem[1:]
            cond = self._cond(cc) or f"__flags_{cc}"
            tgt = ins.target
            if tgt is None:
                out.append(f"if ({cond}) goto __unknown;")
                return
            out.append(f"if ({cond}) goto {self._label(tgt)};")
            return
        if ins.target is None:
            if ins.mem:
                nm = s.db.get_name(ins.mem[0].ea)
                if nm and nm.startswith("__imp_"):
                    out.append(f"return {nm[6:]}(...);   /* tail call */")
                    return
            out.append("goto __indirect;   /* unresolved indirect jump */")
            return
        tgt = ins.target
        f = s.db.func_at(tgt)
        inside = any(x == tgt for x in order)
        if f is not None and not inside:
            out.append(f"return {s.sym(tgt)}(...);   /* tail call */")
        else:
            out.append(f"goto {self._label(tgt)};")

    # ------------------------------------------------ postprocessing ---
    def _postprocess(self, lines: list[str], order) -> str:
        # drop `goto L;` immediately followed by `L:`
        out: list[str] = []
        for i, ln in enumerate(lines):
            st = ln.strip()
            m = re.fullmatch(r"goto (LAB_[0-9a-f]+);", st)
            if m:
                for j in range(i + 1, len(lines)):
                    nxt = lines[j].strip()
                    if not nxt:
                        continue
                    if nxt == f"{m.group(1)}:":
                        st = None
                    break
                if st is None:
                    continue
            out.append(ln)
        # drop labels nobody jumps to
        used = set(re.findall(r"goto (LAB_[0-9a-f]+);", "\n".join(out)))
        res = [ln for ln in out
               if not (re.fullmatch(r"\s*LAB_[0-9a-f]+:", ln)
                       and ln.strip()[:-1] not in used)]
        return "\n".join(res)
