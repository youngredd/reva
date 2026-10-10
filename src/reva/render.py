"""Rendering tuned for a limited context window.

Raw disassembly wastes most of its tokens on numbers a reader cannot use.
Everything here is about replacing those numbers with meaning: call targets
become api names, rip-relative loads become symbols with the string they point
at, stack slots become stable variable names.
"""
from __future__ import annotations

import json
import re

from . import apiinfo

# capstone prints small displacements in decimal and larger ones in hex, so
# both forms have to be accepted here
RE_RIP = re.compile(r"\[rip ([+-]) (0x[0-9a-fA-F]+|\d+)\]")
RE_STACK = re.compile(r"\[(rsp|rbp|esp|ebp) ([+-]) (0x[0-9a-fA-F]+|\d+)\]")
RE_HEXNUM = re.compile(r"\b0x[0-9a-fA-F]{4,}\b")


def _q(s: str, limit: int = 90) -> str:
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if len(s) > limit:
        s = s[:limit] + "..."
    return f'"{s}"'


class Renderer:
    def __init__(self, sess):
        self.s = sess

    # ================================================= instructions ====
    def insn_line(self, ins, *, show_bytes: bool = False,
                  comments: dict | None = None) -> str:
        s = self.s
        ops = self._operands(ins)
        cmt = self._comments(ins, comments)
        head = f"{ins.va:x}"
        by = f" {ins.raw.hex():<22}" if show_bytes else ""
        line = f"{head}{by}  {ins.mnem:<7} {ops}".rstrip()
        if cmt:
            line = f"{line:<52} ; {'; '.join(cmt)}"
        return line

    def _operands(self, ins) -> str:
        s = self.s
        txt = ins.ops

        # a direct branch or call: show where it goes, by name
        if ins.target is not None and (ins.is_call or ins.is_jump):
            return s.sym(ins.target)

        # an indirect call/jump through a known import slot is really a call
        # to that api, so say so instead of printing the slot address
        if (ins.is_call or ins.is_jump) and ins.mem:
            nm = s.db.get_name(ins.mem[0].ea)
            if nm and nm.startswith("__imp_"):
                return nm[len("__imp_"):]

        def rip(m):
            sign = 1 if m.group(1) == "+" else -1
            ea = ins.end + sign * int(m.group(2), 0)
            return f"[{s.sym(ea)}]"
        txt = RE_RIP.sub(rip, txt)

        def stack(m):
            reg, sign, off = m.group(1), m.group(2), int(m.group(3), 0)
            if reg in ("rbp", "ebp"):
                return f"[{'var' if sign == '-' else 'arg'}_{off:x}]"
            # rsp-relative: positive offsets only, so one stable naming scheme
            return f"[sv_{off:x}]" if sign == "+" else f"[sv_n{off:x}]"
        txt = RE_STACK.sub(stack, txt)
        return txt

    def _comments(self, ins, extra: dict | None) -> list[str]:
        s = self.s
        out: list[str] = []
        for m in ins.mem:
            st = s.string_at(m.ea)
            if st:
                out.append(_q(st["text"]))
                continue
            nm = s.db.get_name(m.ea)
            if m.kind == "read" and not nm and s.img.is_valid(m.ea):
                p = s.img.ptr(m.ea)
                if p and s.img.is_valid(p):
                    pn = s.db.get_name(p)
                    if pn:
                        out.append(f"-> {pn}")
        for v in ins.imms:
            lbl = apiinfo.lookup_constant(v)
            if lbl:
                out.append(lbl)
        if ins.is_indirect and not ins.mem:
            out.append("indirect")
        if extra:
            c = extra.get(ins.va)
            if c:
                for k in ("line", "pre", "post"):
                    if k in c:
                        out.append(c[k])
        return out

    # ===================================================== functions ===
    def function(self, fva: int, *, show_bytes: bool = False,
                 max_insn: int = 4000, labels: bool = True) -> str:
        s = self.s
        f = s.db.func_at(fva)
        if f is None:
            return self.range(fva, count=40, show_bytes=show_bytes)
        blocks = s.blocks_of(fva)
        preds: dict[int, list[int]] = {}
        for b in blocks:
            for t in b["succs"]:
                preds.setdefault(t, []).append(b["va"])
        jts = {r["va"]: json.loads(r["targets"]) for r in s.db.con.execute(
            "SELECT va,targets FROM jumptables")}
        cmts = s.db.comments_in(fva, f["end"] + 1)

        lines = [self.function_header(fva)]
        shown = 0
        for b in blocks:
            if labels and (b["va"] in preds or b["va"] == fva):
                lab = s.sym(b["va"])
                if b["va"] in preds:
                    p = ", ".join(f"{x:x}" for x in sorted(preds[b["va"]])[:8])
                    lines.append(f"{lab}:  ; from {p}")
                else:
                    lines.append(f"{lab}:")
            for ins in s.dis.sweep(b["va"], b["end"]):
                lines.append("  " + self.insn_line(ins, show_bytes=show_bytes,
                                                   comments=cmts))
                shown += 1
                if ins.va in jts:
                    tg = jts[ins.va]
                    lines.append("      ; switch -> " + ", ".join(
                        f"{t:x}" for t in tg[:24]) +
                        (f" (+{len(tg)-24} more)" if len(tg) > 24 else ""))
                if shown >= max_insn:
                    lines.append(f"  ... truncated at {max_insn} instructions "
                                 f"(function has {f['ninsn']})")
                    return "\n".join(lines)
        return "\n".join(lines)

    def function_header(self, fva: int) -> str:
        s = self.s
        f = s.db.func_at(fva)
        name = s.sym(fva)
        if f is None:
            return f"; {name}  (not a recovered function)"
        fp = s.fingerprint(fva)
        parts = [f"; ==== {name} @ {fva:x} ====",
                 f"; size=0x{f['size']:x} blocks={f['nblocks']} "
                 f"insns={f['ninsn']} args~{fp.get('args', '?')} "
                 f"cc={f['cc']} src={f['source']}"]
        if f["prototype"]:
            parts.append(f"; prototype: {f['prototype']}")
        flags = json.loads(f["flags"] or "[]")
        if flags:
            parts.append(f"; flags: {', '.join(flags)}")
        callers = s.xrefs_to(fva, ["call", "jump"])
        if callers:
            who = sorted({c["in_func_name"] or f"{c['frm']:x}" for c in callers})
            parts.append(f"; callers({len(callers)}): " + ", ".join(who[:10]) +
                         (" ..." if len(who) > 10 else ""))
        else:
            parts.append("; callers: none found (entry/callback/exported?)")
        if fp.get("summary"):
            parts.append(f"; profile: {fp['summary']}")
        strs = self._function_strings(fva, f["end"])
        if strs:
            parts.append("; strings: " + ", ".join(_q(x, 50) for x in strs[:8]))
        cm = s.db.comments_in(fva, fva + 1)
        if fva in cm and "pre" in cm[fva]:
            parts.append(f"; note: {cm[fva]['pre']}")
        return "\n".join(p for p in parts if p)

    def _function_strings(self, fva: int, end: int) -> list[str]:
        rows = self.s.db.con.execute(
            """SELECT DISTINCT s.text FROM xrefs x JOIN strings s ON s.va = x.dst
               WHERE x.frm >= ? AND x.frm < ? LIMIT 24""", (fva, end)).fetchall()
        return [r["text"] for r in rows]

    # ======================================================== ranges ===
    def range(self, va: int, count: int | None = None, end: int | None = None,
              *, show_bytes: bool = False) -> str:
        s = self.s
        cmts = s.db.comments_in(va, (end or va + 0x400) + 1)
        lines = []
        it = s.dis.take(va, count) if count else s.dis.sweep(va, end)
        for ins in it:
            nm = s.db.get_name(ins.va)
            if nm:
                lines.append(f"{nm}:")
            lines.append("  " + self.insn_line(ins, show_bytes=show_bytes,
                                               comments=cmts))
        return "\n".join(lines) or f"; nothing decodable at {va:x}"

    # ========================================================== data ===
    def data(self, va: int, size: int, fmt: str = "auto") -> str:
        s = self.s
        img = s.img
        if fmt == "auto":
            st = s.string_at(va)
            fmt = "string" if st else ("ptr" if size % img.ptr_size == 0 and
                                       size >= img.ptr_size else "hex")
        if fmt == "string":
            st = s.string_at(va)
            if st:
                return f"{va:x}  {st['enc']} len={st['len']}  {_q(st['text'], 400)}"
            return f"{va:x}  {_q(img.cstr(va, size), 400)}"
        if fmt == "ptr":
            out = []
            n = size // img.ptr_size
            for i in range(n):
                a = va + i * img.ptr_size
                p = img.ptr(a)
                if p is None:
                    break
                line = f"{a:x}  {p:0{img.ptr_size*2}x}"
                if img.is_valid(p):
                    line += f"  {s.sym(p)}"
                    st = s.string_at(p)
                    if st:
                        line += f"  {_q(st['text'], 60)}"
                out.append(line)
            return "\n".join(out)
        # hex dump with an ascii gutter
        data = img.read(va, size)
        out = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            out.append(f"{va + off:x}  {hx:<47}  |{asc}|")
        return "\n".join(out)

    # =================================================== cfg as text ===
    def cfg(self, fva: int) -> str:
        s = self.s
        blocks = s.blocks_of(fva)
        if not blocks:
            return f"; no blocks for {fva:x}"
        lines = [f"; CFG of {s.sym(fva)} ({len(blocks)} blocks)"]
        for b in blocks:
            succ = ", ".join(f"{t:x}" for t in b["succs"]) or "-"
            first = next(s.dis.take(b["va"], 1), None)
            last = None
            for i in s.dis.sweep(b["va"], b["end"]):
                last = i
            tail = f"{last.mnem} {self._operands(last)}" if last else ""
            lines.append(f"  {b['va']:x}..{b['end']:x} [{b['kind']:8}] "
                         f"-> {succ:<28} ; {tail[:60]}")
        return "\n".join(lines)
