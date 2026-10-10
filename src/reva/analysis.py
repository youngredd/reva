"""Code analysis: function recovery, CFG, cross references, fingerprints."""
from __future__ import annotations

import json
import re
from collections import defaultdict

from . import apiinfo
from .disasm import Disassembler, prologues_for

# calls to these never come back, so the block ends there
NORETURN_NAMES = {
    "exit", "_exit", "_cexit", "abort", "quick_exit", "_Exit",
    "exitprocess", "exitthread", "terminateprocess", "terminatethread",
    "rtlexituserprocess", "rtlexituserthread", "ntterminateprocess",
    "raiseexception", "rtlraiseexception", "rtlraisestatus", "longjmp",
    "_invalid_parameter_noinfo_noreturn", "__stack_chk_fail", "_report_gsfailure",
    "_cxxthrowexception", "__cxa_throw", "_purecall", "__report_rangecheckfailure",
    "rtlfailfast", "__fastfail", "_invoke_watson", "kebugcheck", "kebugcheckex",
    "unreachable", "pscallsystemthread",
}

MS_ARG_REGS = ["rcx", "rdx", "r8", "r9"]
MS_ARG_REGS32 = ["ecx", "edx", "r8d", "r9d"]
SYSV_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
SYSV_ARG_REGS32 = ["edi", "esi", "edx", "ecx", "r8d", "r9d"]
ARM64_ARG_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

CRYPTO_MNEM = {"xor", "rol", "ror", "shl", "shr", "sar", "not", "bswap",
               "aesenc", "aesdec", "aesenclast", "aesdeclast", "aeskeygenassist",
               "pclmulqdq", "crc32", "sha256rnds2", "sha1rnds4", "vpxor", "pxor"}


class Function:
    __slots__ = ("va", "end", "blocks", "insns", "calls", "source", "flags",
                 "jumptables", "tailcalls")

    def __init__(self, va: int):
        self.va = va
        self.end = va
        self.blocks: dict[int, dict] = {}   # leader -> {end, succs, kind}
        self.insns: dict = {}
        self.calls: set[int] = set()
        self.tailcalls: set[int] = set()
        self.source = "auto"
        self.flags: set[str] = set()
        self.jumptables: dict[int, list[int]] = {}

    @property
    def size(self) -> int:
        return self.end - self.va


class Analyzer:
    def __init__(self, image, db, loadres=None, log=None):
        self.img = image
        self.db = db
        self.lr = loadres
        self.dis = Disassembler(image)
        self.log = log or (lambda *a: None)

        self.func_starts: set[int] = set()
        self.funcs: dict[int, Function] = {}
        self.noreturn: set[int] = set()        # VAs of noreturn funcs/thunks
        self.import_by_slot: dict[int, dict] = {}
        self.thunk_to_import: dict[int, dict] = {}
        self.xrefs: set[tuple[int, int, str]] = set()
        self.stats: dict = {}

    # =================================================== main pipeline ==
    def run(self, deep: bool = True) -> dict:
        self._seed_symbols()
        self._find_import_thunks()
        seeds = self._collect_seeds()
        self.log(f"seeds: {len(seeds)}")

        self._descend(seeds)
        self.log(f"after descent: {len(self.funcs)} functions")

        if deep:
            extra = self._scan_gaps()
            if extra:
                self.log(f"prologue scan found {len(extra)} more")
                self._descend(extra)
            ptr = self._scan_code_pointers()
            if ptr:
                self.log(f"pointer scan found {len(ptr)} more")
                self._descend(ptr)

        self._propagate_noreturn()
        self._build_xrefs()
        self._name_wrappers()
        self._persist()
        return self.stats

    # ------------------------------------------------ symbol seeding ---
    def _seed_symbols(self) -> None:
        if not self.lr:
            return
        db = self.db
        rows = []
        for imp in self.lr.imports:
            self.import_by_slot[imp["va"]] = imp
            db.set_name(imp["va"], f"__imp_{imp['name']}", "import")
            rows.append((imp["va"], imp["dll"], imp["name"], imp["ordinal"],
                         imp["kind"], None))
        if rows:
            db.con.executemany(
                "INSERT OR REPLACE INTO imports (va,dll,name,ordinal,kind,thunk) "
                "VALUES (?,?,?,?,?,?)", rows)
        exp = []
        for e in self.lr.exports:
            db.set_name(e["va"], e["name"], "export")
            exp.append((e["va"], e["name"], e["ordinal"], e["forwarder"]))
        if exp:
            db.con.executemany("INSERT INTO exports (va,name,ordinal,forwarder) "
                               "VALUES (?,?,?,?)", exp)
        # mark noreturn imports
        for imp in self.lr.imports:
            if imp["name"].lower().lstrip("_") in NORETURN_NAMES:
                self.noreturn.add(imp["va"])
        db.commit()

    def _find_import_thunks(self) -> None:
        """`jmp [rip+X]` where X is an IAT slot: name it after the api."""
        updates = []
        for s in self.img.iter_exec_sections():
            va = s.va
            end = s.end
            while va < end:
                i = self.dis.at(va)
                if i is None:
                    va += 1
                    continue
                if i.is_jump and i.is_indirect and i.mem:
                    slot = i.mem[0].ea
                    imp = self.import_by_slot.get(slot)
                    if imp:
                        self.thunk_to_import[i.va] = imp
                        self.db.set_name(i.va, imp["name"], "import")
                        updates.append((i.va, slot))
                        if imp["name"].lower().lstrip("_") in NORETURN_NAMES:
                            self.noreturn.add(i.va)
                va = i.end
        if updates:
            self.db.con.executemany("UPDATE imports SET thunk=? WHERE va=?",
                                    [(t, s) for t, s in updates])
            self.db.commit()
        self.log(f"import thunks: {len(self.thunk_to_import)}")

    def _collect_seeds(self) -> list[int]:
        hints: dict[int, dict] = {}
        if self.lr:
            for h in self.lr.func_hints:
                va = h["va"]
                cur = hints.get(va)
                if cur is None:
                    hints[va] = dict(h)
                else:
                    if "end" in h and "end" not in cur:
                        cur["end"] = h["end"]
                    # prefer the more authoritative source
                    rank = {"entry": 5, "export": 4, "pdata": 4, "tls_callback": 4,
                            "seh_handler": 3, "pdata_chain": 3, "guard_cf": 2}
                    if rank.get(h["source"], 0) > rank.get(cur["source"], 0):
                        cur["source"] = h["source"]
        self._hints = hints
        self.func_starts.update(hints.keys())
        # authoritative starts, used to cap function bodies. a .pdata `end` can
        # span many functions (separated/cold code shares one record), so the
        # next known start is the tighter and more trustworthy bound.
        self._seed_sorted = sorted(hints.keys())
        return list(self._seed_sorted)

    def _next_start(self, va: int) -> int | None:
        import bisect
        lst = getattr(self, "_seed_sorted", None)
        if not lst:
            return None
        i = bisect.bisect_right(lst, va)
        return lst[i] if i < len(lst) else None

    # ------------------------------------------------------- descent ---
    def _descend(self, seeds: list[int]) -> None:
        work = list(seeds)
        self.func_starts.update(seeds)
        seen_round = set()
        while work:
            va = work.pop()
            if va in self.funcs or va in seen_round:
                continue
            seen_round.add(va)
            if not self.img.is_exec(va):
                continue
            f = self._analyze_function(va)
            if f is None:
                continue
            self.funcs[va] = f
            for t in f.calls | f.tailcalls:
                if t not in self.funcs and self.img.is_exec(t):
                    self.func_starts.add(t)
                    work.append(t)

    def _analyze_function(self, start: int) -> Function | None:
        hint = getattr(self, "_hints", {}).get(start, {})
        bound_end = hint.get("end")
        nxt = self._next_start(start)
        if nxt is not None:
            bound_end = min(bound_end, nxt) if bound_end else nxt
        f = Function(start)
        f.source = hint.get("source", "auto")

        insns: dict[int, object] = {}
        leaders: set[int] = {start}
        terminators: dict[int, dict] = {}
        work = [start]
        max_insn = 60_000

        while work:
            va = work.pop()
            chain: list = []          # recent linear run, for jump-table lookback
            while True:
                if va in insns or len(insns) > max_insn:
                    break
                if not self.img.is_exec(va):
                    break
                if bound_end and not (start <= va < bound_end):
                    break
                i = self.dis.at(va)
                if i is None:
                    break
                insns[va] = i
                chain.append(i)
                if len(chain) > 24:
                    del chain[:-24]

                if i.is_call:
                    tgt = self._call_target(i)
                    if tgt is not None:
                        f.calls.add(tgt)
                    if tgt is not None and tgt in self.noreturn:
                        terminators[va] = {"kind": "noreturn", "succs": []}
                        break
                    va = i.end
                    continue

                if i.is_jump:
                    succs = []
                    if i.target is not None:
                        if self._is_tail_call(start, i.target, bound_end):
                            f.tailcalls.add(i.target)
                            terminators[va] = {"kind": "tail", "succs": []}
                            break
                        succs.append(i.target)
                        leaders.add(i.target)
                        work.append(i.target)
                    else:
                        tgts = self._resolve_jumptable(i, chain, start, bound_end)
                        if tgts:
                            f.jumptables[i.va] = tgts
                            for t in tgts:
                                succs.append(t)
                                leaders.add(t)
                                work.append(t)
                        else:
                            terminators[va] = {"kind": "indirect", "succs": []}
                            break
                    if i.is_cond:
                        succs.append(i.end)
                        leaders.add(i.end)
                        work.append(i.end)
                        terminators[va] = {"kind": "cond", "succs": succs}
                    else:
                        terminators[va] = {"kind": "jmp", "succs": succs}
                    break

                if i.is_ret:
                    terminators[va] = {"kind": "ret", "succs": []}
                    break
                if not i.flows_on:
                    terminators[va] = {"kind": "stop", "succs": []}
                    break
                va = i.end

        if not insns:
            return None

        # split the instruction set into basic blocks
        ordered = sorted(insns)
        f.insns = insns
        f.end = max(i.end for i in insns.values())
        if bound_end:
            f.end = max(f.end, 0)  # keep computed end; pdata end can over-span

        cur_leader = None
        cur_insns: list = []
        for va in ordered:
            i = insns[va]
            if cur_leader is None or va in leaders or (cur_insns and
                                                       cur_insns[-1].end != va):
                if cur_leader is not None and cur_insns:
                    self._close_block(f, cur_leader, cur_insns, terminators, insns)
                cur_leader = va
                cur_insns = []
            cur_insns.append(i)
            if va in terminators:
                self._close_block(f, cur_leader, cur_insns, terminators, insns)
                cur_leader, cur_insns = None, []
        if cur_leader is not None and cur_insns:
            self._close_block(f, cur_leader, cur_insns, terminators, insns)

        self._classify(f)
        return f

    def _close_block(self, f, leader, blk_insns, terminators, insns) -> None:
        last = blk_insns[-1]
        term = terminators.get(last.va)
        if term is not None:
            succs, kind = term["succs"], term["kind"]
        else:
            nxt = last.end
            succs = [nxt] if nxt in insns else []
            kind = "fall"
        f.blocks[leader] = {"end": last.end, "succs": succs, "kind": kind}

    def _call_target(self, i) -> int | None:
        if i.target is not None:
            return i.target
        if i.mem:
            slot = i.mem[0].ea
            if slot in self.import_by_slot:
                return slot
        return None

    def _is_tail_call(self, start: int, target: int, bound_end: int | None) -> bool:
        if target == start:
            return False
        # an authoritative function start is never part of another function's
        # body, even when a .pdata record claims to span it
        if target in self.func_starts or target in self.thunk_to_import:
            return True
        if bound_end is not None:
            return not (start <= target < bound_end)
        if abs(target - start) > 0x8000:
            return True
        return False

    # --------------------------------------------------- jump tables ---
    def _resolve_jumptable(self, jmp, chain: list, fstart: int,
                           bound_end) -> list[int]:
        """Recover switch targets for an indirect jmp.

        Two shapes are handled: the MSVC/clang rip-relative form, where the
        table holds int32 deltas from the table base, and the plain form where
        the table holds absolute pointers.
        """
        img = self.img
        window = chain[-20:]
        # candidates are (table_va, entry_kind, delta_origin)
        cands: list[tuple[int, str, int]] = []

        # a direct `jmp qword [rip+table + idx*8]` names its table outright
        for mo, mr in zip(jmp.memops, jmp.mem):
            if mo["index"] and mo["scale"] in (4, 8):
                cands.append((mr.ea, "abs", 0))

        # the common MSVC/clang x64 shape:
        #     lea  rbase, [rip + V]              ; V is often __ImageBase
        #     movzx eax, byte  [rbase + idx + D2] ; optional index indirection
        #     mov  ecx, dword  [rbase + idx*4 + D] ; D -> the real table
        #     add  rcx, rbase                     ; entries are deltas from V
        #     jmp  rcx
        lea_val: dict[str, int] = {}
        bound = 0
        for i in window:
            if i.mnem == "lea" and i.mem and i.mem[0].rip_rel and i.reg_ops:
                lea_val[i.reg_ops[0]] = i.mem[0].ea
            if i.mnem in ("cmp", "sub") and i.imms and bound == 0:
                v = i.imms[-1]
                if 0 < v < 0x4000:
                    bound = v + 1

        for i in window:
            if i.mnem not in ("mov", "movzx", "movsx", "movsxd"):
                continue
            for mo in i.memops:
                if not mo["index"] or mo["scale"] not in (4, 8):
                    continue
                v = lea_val.get(mo["base"]) if mo["base"] else None
                if v is None:
                    continue
                table = (v + mo["disp"]) & 0xFFFFFFFFFFFFFFFF
                if mo["scale"] == 4:
                    cands.append((table, "rel32", v))
                else:
                    cands.append((table, "abs", 0))
        if not cands:
            return []
        limit = min(bound, 4096) if bound else 1024
        sec = img.section_at(jmp.va)
        best: list[int] = []
        for table, kind, origin in cands:
            # MSVC emits switch tables into .text itself, so an executable
            # table address is normal and must not be rejected
            if not img.is_valid(table):
                continue
            out: list[int] = []
            for n in range(limit):
                if kind == "abs":
                    p = img.ptr(table + n * img.ptr_size)
                else:
                    d = img.i32(table + n * 4)
                    p = (origin + d) & 0xFFFFFFFFFFFFFFFF if d is not None else None
                if p is None or not img.is_exec(p):
                    break
                # switch arms live in the same section as the dispatch
                if sec is not None and not sec.contains(p):
                    break
                if bound_end is not None and not (fstart <= p < bound_end):
                    break
                out.append(p)
            if len(out) > len(best):
                best = out
        # a one-entry "table" is almost always a misread operand
        return best if len(best) >= 2 else []

    # ------------------------------------------------- gap/ptr scans ---
    def _claimed(self) -> list[tuple[int, int]]:
        iv = sorted((f.va, f.end) for f in self.funcs.values())
        merged: list[list[int]] = []
        for a, b in iv:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return [(a, b) for a, b in merged]

    def _scan_gaps(self) -> list[int]:
        """Look for prologues in stretches of executable bytes nobody claimed."""
        pros = prologues_for(self.img.arch)
        if not pros:
            return []
        claimed = self._claimed()
        found: list[int] = []
        for s in self.img.iter_exec_sections():
            gaps = []
            cur = s.va
            for a, b in claimed:
                if b <= s.va or a >= s.end:
                    continue
                if a > cur:
                    gaps.append((cur, min(a, s.end)))
                cur = max(cur, b)
            if cur < s.end:
                gaps.append((cur, s.end))
            for lo, hi in gaps:
                if hi - lo < 4:
                    continue
                data = s.data[lo - s.va: hi - s.va]
                n = len(data)
                off = 0
                after_pad = True      # start of a gap counts as post-padding
                while off < n:
                    if data[off] in (0xCC, 0x00, 0x90):
                        after_pad = True
                        off += 1
                        continue
                    va = lo + off
                    # a genuine start is either aligned or sits right after the
                    # padding the linker inserted between functions
                    if (after_pad or va % 16 == 0) and va not in self.func_starts \
                            and any(data.startswith(p, off) for p in pros):
                        found.append(va)
                    after_pad = False
                    i = self.dis.at(va)
                    off += i.size if i else 1
        return found

    def _scan_code_pointers(self) -> list[int]:
        """Relocated pointers / pointer-sized data that aim at code are
        callbacks, vtable slots and handler tables."""
        out: set[int] = set()
        img = self.img
        cands = list(self.lr.relocs) if self.lr else []
        if not cands:
            # no relocation table: sweep data sections at pointer granularity
            step = img.ptr_size
            for s in img.sections:
                if s.exec or not s.fsize:
                    continue
                cands.extend(range(s.va, s.va + s.fsize - step + 1, step))
        for va in cands:
            p = img.ptr(va)
            if p and img.is_exec(p) and p not in self.func_starts:
                i = self.dis.at(p)
                if i and not i.is_int3 and i.mnem != "nop":
                    out.add(p)
        return sorted(out)

    # ----------------------------------------------------- noreturn ----
    def _propagate_noreturn(self) -> None:
        for _ in range(4):
            changed = False
            for va, f in self.funcs.items():
                if va in self.noreturn:
                    continue
                has_ret = any(b["kind"] == "ret" for b in f.blocks.values())
                if has_ret or not f.blocks:
                    continue
                ends = {b["kind"] for b in f.blocks.values()}
                if ends <= {"noreturn", "stop", "indirect", "tail"} and \
                        ("noreturn" in ends or "stop" in ends):
                    self.noreturn.add(va)
                    f.flags.add("noreturn")
                    changed = True
            if not changed:
                break

    # ------------------------------------------------------- xrefs -----
    def _build_xrefs(self) -> None:
        xr = self.xrefs
        for f in self.funcs.values():
            for va, i in f.insns.items():
                if i.is_call:
                    t = self._call_target(i)
                    if t is not None:
                        xr.add((va, t, "call"))
                elif i.is_jump and i.target is not None:
                    xr.add((va, i.target, "jump"))
                for m in i.mem:
                    if i.is_call and m.kind == "read":
                        continue
                    xr.add((va, m.ea, m.kind))
            for jva, tgts in f.jumptables.items():
                for t in tgts:
                    xr.add((jva, t, "jump"))
        self.log(f"xrefs: {len(xr)}")

    # ----------------------------------------------- auto naming -------
    def _classify(self, f: Function) -> None:
        if len(f.blocks) == 1 and len(f.insns) <= 2:
            last = f.insns[max(f.insns)]
            if last.is_jump:
                f.flags.add("thunk")
        if f.va in self.noreturn:
            f.flags.add("noreturn")
        # stack frame size from the prologue
        for va in sorted(f.insns)[:8]:
            i = f.insns[va]
            if i.mnem == "sub" and i.ops.startswith(("rsp", "esp")) and i.imms:
                f.flags.add(f"frame:{i.imms[-1]}")
                break

    def _name_wrappers(self) -> None:
        """A tiny function that just forwards to one import deserves its name."""
        for va, f in self.funcs.items():
            if "thunk" not in f.flags:
                continue
            if self.db.get_name(va):
                continue
            tgt = next(iter(f.tailcalls | f.calls), None)
            if tgt is None:
                continue
            nm = self.db.get_name(tgt)
            if nm:
                self.db.set_name(va, f"j_{nm.lstrip('_')}", "guess")

    # ----------------------------------------------------- persist -----
    def _persist(self) -> None:
        db = self.db
        con = db.con
        con.execute("DELETE FROM functions")
        con.execute("DELETE FROM blocks")
        con.execute("DELETE FROM xrefs")
        con.execute("DELETE FROM jumptables")

        callers = defaultdict(int)
        for (frm, dst, kind) in self.xrefs:
            if kind == "call":
                callers[dst] += 1

        frows, brows, jrows = [], [], []
        for va, f in sorted(self.funcs.items()):
            fp = self._fingerprint(f, callers.get(va, 0))
            frame = 0
            for fl in f.flags:
                if fl.startswith("frame:"):
                    frame = int(fl.split(":")[1])
            frows.append((va, f.end, f.end - va, f.source,
                          json.dumps(sorted(fl for fl in f.flags
                                            if not fl.startswith("frame:"))),
                          fp.get("cc"), None, len(f.blocks), len(f.insns),
                          frame, json.dumps(fp)))
            for leader, b in f.blocks.items():
                brows.append((leader, va, b["end"], json.dumps(b["succs"]), b["kind"]))
            for jva, tg in f.jumptables.items():
                jrows.append((jva, 0, len(tg), json.dumps(tg)))

        con.executemany(
            "INSERT OR REPLACE INTO functions "
            "(va,end,size,source,flags,cc,prototype,nblocks,ninsn,stack_size,"
            "fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?)", frows)
        con.executemany("INSERT OR REPLACE INTO blocks (va,func,end,succs,kind) "
                        "VALUES (?,?,?,?,?)", brows)
        con.executemany("INSERT OR REPLACE INTO jumptables (va,base,count,targets) "
                        "VALUES (?,?,?,?)", jrows)
        con.executemany("INSERT OR REPLACE INTO xrefs (frm,dst,kind) VALUES (?,?,?)",
                        sorted(self.xrefs))
        db.commit()

        self.stats = {
            "functions": len(self.funcs),
            "blocks": len(brows),
            "instructions": sum(len(f.insns) for f in self.funcs.values()),
            "xrefs": len(self.xrefs),
            "jumptables": len(jrows),
            "import_thunks": len(self.thunk_to_import),
            "noreturn": len(self.noreturn),
            "code_bytes": sum(f.end - f.va for f in self.funcs.values()),
        }

    # ------------------------------------------------- fingerprints ----
    def _fingerprint(self, f: Function, ncallers: int) -> dict:
        names = self.db.names_bulk(
            list(f.calls | f.tailcalls) +
            [m.ea for i in f.insns.values() for m in i.mem])
        callees: list[str] = []
        for t in sorted(f.calls | f.tailcalls):
            nm = names.get(t)
            if nm:
                callees.append(nm.replace("__imp_", ""))
        cats: set[str] = set()
        for c in callees:
            cats.update(apiinfo.categorize_api(c))

        consts: list[str] = []
        crypto_ops = 0
        loops = 0
        indirect = 0
        for va, i in f.insns.items():
            if i.mnem in CRYPTO_MNEM:
                crypto_ops += 1
            if (i.is_call or i.is_jump) and i.is_indirect:
                indirect += 1
            for v in i.imms:
                lbl = apiinfo.lookup_constant(v)
                if lbl and lbl not in consts:
                    consts.append(lbl)
        for leader, b in f.blocks.items():
            for s in b["succs"]:
                if s <= leader:
                    loops += 1

        fp = {
            "ninsn": len(f.insns), "nblocks": len(f.blocks), "size": f.size,
            "callees": callees[:40], "ncallees": len(f.calls | f.tailcalls),
            "ncallers": ncallers, "cats": sorted(cats),
            "risk": apiinfo.api_risk(sorted(cats)),
            "loops": loops, "indirect": indirect,
            "crypto_ops": crypto_ops,
            "crypto_density": round(crypto_ops / max(1, len(f.insns)), 3),
            "consts": consts[:10],
            "args": self._guess_args(f),
            "cc": self._guess_cc(),
            "flags": sorted(f.flags),
        }
        fp["summary"] = self._summarize(fp)
        return fp

    def _guess_cc(self) -> str:
        if self.img.arch in ("x86_64",):
            return "ms64" if self.img.fmt == "pe" else "sysv64"
        if self.img.arch == "x86":
            return "cdecl"
        return self.img.arch

    def _guess_args(self, f: Function) -> int:
        """Count argument registers read before being written in the entry block."""
        if self.img.arch == "x86_64":
            regs = MS_ARG_REGS if self.img.fmt == "pe" else SYSV_ARG_REGS
            regs32 = MS_ARG_REGS32 if self.img.fmt == "pe" else SYSV_ARG_REGS32
        elif self.img.arch == "arm64":
            regs, regs32 = ARM64_ARG_REGS, [f"w{i}" for i in range(8)]
        else:
            return -1
        alias = {}
        for idx, (r64, r32) in enumerate(zip(regs, regs32)):
            for nm in (r64, r32, r32.rstrip("d"), r64[1:] if r64[0] == "r" else r64):
                alias[nm] = idx
        written: set[int] = set()
        used: set[int] = set()
        # walk the entry block only; good enough and avoids loop noise
        blk = f.blocks.get(f.va)
        end = blk["end"] if blk else f.end
        for va in sorted(f.insns):
            if va >= end:
                break
            i = f.insns[va]
            for r in i.regs_read:
                k = alias.get(r)
                if k is not None and k not in written:
                    used.add(k)
            for r in i.regs_write:
                k = alias.get(r)
                if k is not None:
                    written.add(k)
            if i.is_call:
                break
        return (max(used) + 1) if used else 0

    def _summarize(self, fp: dict) -> str:
        bits = []
        if "thunk" in fp["flags"]:
            bits.append("thunk")
        if "noreturn" in fp["flags"]:
            bits.append("noreturn")
        bits.append(f"{fp['ninsn']}i/{fp['nblocks']}bb")
        if fp["args"] > 0:
            bits.append(f"{fp['args']}args")
        if fp["loops"]:
            bits.append(f"{fp['loops']}loop")
        if fp["cats"]:
            bits.append("+".join(fp["cats"][:4]))
        if fp["crypto_density"] > 0.12 and fp["ninsn"] > 10:
            bits.append(f"bitops{int(fp['crypto_density'] * 100)}%")
        if fp["consts"]:
            bits.append(fp["consts"][0])
        if fp["indirect"]:
            bits.append(f"{fp['indirect']}indirect")
        key = [c for c in fp["callees"] if apiinfo.categorize_api(c)][:3]
        if key:
            bits.append("calls:" + ",".join(key))
        return " ".join(bits)
