"""Search that understands code, not just bytes.

The byte and string searches are table stakes. The ones that matter for working
through an unfamiliar binary are `behavior` (find the function that calls these
apis, in this order) and `similar` (find the other functions that look like
this one), because those are the questions you actually have.
"""
from __future__ import annotations

import json
import re
import struct


def _parse_pattern(pat: str) -> tuple[bytes, bytes]:
    """IDA-style pattern -> (bytes, mask). Accepts '48 8b ?? 24 ?' and
    '488b??24', and 'xx ?? xx' style wildcards."""
    t = pat.strip().replace("0x", "").replace(",", " ")
    if " " in t:
        toks = t.split()
    else:
        if len(t) % 2:
            raise ValueError("odd number of hex digits")
        toks = [t[i:i + 2] for i in range(0, len(t), 2)]
    out = bytearray()
    mask = bytearray()
    for tok in toks:
        if tok in ("?", "??", "*", "**"):
            out.append(0)
            mask.append(0)
            continue
        if len(tok) == 1:
            tok = "0" + tok
        try:
            out.append(int(tok, 16))
        except ValueError as e:
            raise ValueError(f"bad pattern token {tok!r}") from e
        mask.append(0xFF)
    if not out:
        raise ValueError("empty pattern")
    return bytes(out), bytes(mask)


class Search:
    def __init__(self, sess):
        self.s = sess

    # ---------------------------------------------------------- bytes ---
    def bytes_pattern(self, pattern: str, *, limit: int = 200,
                      exec_only: bool = False) -> list[dict]:
        pat, mask = _parse_pattern(pattern)
        n = len(pat)
        hits: list[dict] = []
        if all(m == 0xFF for m in mask):
            for va in self.s.img.find_all(pat, exec_only=exec_only):
                hits.append(self._hit(va))
                if len(hits) >= limit:
                    break
            return hits
        # with wildcards, anchor on the longest fixed run to keep it fast
        best_i, best_len = 0, 0
        i = 0
        while i < n:
            if mask[i] == 0xFF:
                j = i
                while j < n and mask[j] == 0xFF:
                    j += 1
                if j - i > best_len:
                    best_i, best_len = i, j - i
                i = j
            else:
                i += 1
        anchor = pat[best_i:best_i + best_len] if best_len else None
        for sec in self.s.img.sections:
            if exec_only and not sec.exec:
                continue
            data = sec.data
            start = 0
            while True:
                if anchor:
                    k = data.find(anchor, start)
                    if k < 0:
                        break
                    pos = k - best_i
                    start = k + 1
                    if pos < 0 or pos + n > len(data):
                        continue
                else:
                    pos = start
                    start += 1
                    if pos + n > len(data):
                        break
                seg = data[pos:pos + n]
                if all((seg[x] & mask[x]) == pat[x] for x in range(n)):
                    hits.append(self._hit(sec.va + pos))
                    if len(hits) >= limit:
                        return hits
        return hits

    def _hit(self, va: int) -> dict:
        s = self.s
        f = s.func_of(va)
        sec = s.img.section_at(va)
        d = {"va": f"0x{va:x}", "section": sec.name if sec else None,
             "symbol": s.db.get_name(va)}
        if f:
            d["in_function"] = s.sym(f["va"])
            d["func_va"] = f"0x{f['va']:x}"
        return d

    # ------------------------------------------------------ immediate ---
    def immediate(self, value: int, *, limit: int = 200) -> list[dict]:
        """Find the value as an operand and as stored data of every width."""
        out: list[dict] = []
        seen: set[int] = set()
        img = self.s.img
        for width, fmt in ((4, "<I"), (8, "<Q"), (2, "<H")):
            if value >= (1 << (width * 8)):
                continue
            try:
                needle = struct.pack(fmt, value)
            except struct.error:
                continue
            for va in img.find_all(needle):
                if va in seen:
                    continue
                seen.add(va)
                h = self._hit(va)
                h["as"] = f"u{width * 8}"
                out.append(h)
                if len(out) >= limit:
                    return out
        return out

    # --------------------------------------------------------- strings ---
    def text(self, needle: str, *, limit: int = 200, regex: bool = False,
             case: bool = False) -> list[dict]:
        s = self.s
        if regex:
            rx = re.compile(needle, 0 if case else re.I)
            rows = s.db.con.execute("SELECT va,enc,len,text FROM strings").fetchall()
            rows = [r for r in rows if rx.search(r["text"])][:limit]
        else:
            op = "LIKE" if not case else "GLOB"
            arg = f"%{needle}%" if not case else f"*{needle}*"
            rows = s.db.con.execute(
                f"SELECT va,enc,len,text FROM strings WHERE text {op} ? LIMIT ?",
                (arg, limit)).fetchall()
        out = []
        for r in rows:
            refs = s.xrefs_to(r["va"])
            out.append({
                "va": f"0x{r['va']:x}", "enc": r["enc"], "len": r["len"],
                "text": r["text"][:300], "symbol": s.db.get_name(r["va"]),
                "xrefs": [{"from": f"0x{x['frm']:x}",
                           "in": x["in_func_name"]} for x in refs[:8]],
                "nxrefs": len(refs),
            })
        return out

    # -------------------------------------------------------- behavior ---
    def behavior(self, calls: list[str], *, mode: str = "all",
                 ordered: bool = False, categories: list[str] | None = None,
                 min_risk: int = 0, limit: int = 60) -> list[dict]:
        """Find functions by what they do.

        `calls` are matched case-insensitively as substrings of callee names, so
        'virtualalloc' matches VirtualAlloc and VirtualAllocEx. With
        `ordered=True` the calls must appear in the given order in the
        function's call sequence.
        """
        s = self.s
        want = [c.lower() for c in calls]
        res = []
        for r in s.db.con.execute(
                "SELECT va, fingerprint FROM functions WHERE fingerprint IS NOT NULL"):
            fp = json.loads(r["fingerprint"])
            if fp.get("risk", 0) < min_risk:
                continue
            if categories and not set(categories) & set(fp.get("cats", [])):
                continue
            callees = [c.lower() for c in fp.get("callees", [])]
            if want:
                hits = [any(w in c for c in callees) for w in want]
                if mode == "all" and not all(hits):
                    continue
                if mode == "any" and not any(hits):
                    continue
                if ordered:
                    pos = -1
                    ok = True
                    for w in want:
                        nxt = next((i for i, c in enumerate(callees)
                                    if i > pos and w in c), None)
                        if nxt is None:
                            ok = False
                            break
                        pos = nxt
                    if not ok:
                        continue
            res.append({
                "va": f"0x{r['va']:x}", "name": s.sym(r["va"]),
                "risk": fp.get("risk", 0), "summary": fp.get("summary", ""),
                "matched": [c for c in fp.get("callees", [])
                            if any(w in c.lower() for w in want)][:8],
            })
        res.sort(key=lambda x: -x["risk"])
        return res[:limit]

    # --------------------------------------------------------- similar ---
    def similar(self, fva: int, *, limit: int = 20) -> list[dict]:
        """Functions whose shape and callee set resemble this one. Useful for
        spotting duplicated/variant code and for porting names across builds."""
        s = self.s
        base = s.fingerprint(fva)
        if not base:
            raise ValueError(f"no fingerprint for {fva:x}")
        bc = set(c.lower() for c in base.get("callees", []))
        bn, bb = base.get("ninsn", 0), base.get("nblocks", 0)
        out = []
        for r in s.db.con.execute(
                "SELECT va, fingerprint FROM functions WHERE va != ?", (fva,)):
            fp = json.loads(r["fingerprint"])
            cc = set(c.lower() for c in fp.get("callees", []))
            jac = len(bc & cc) / len(bc | cc) if (bc | cc) else 0.0
            n, b = fp.get("ninsn", 0), fp.get("nblocks", 0)
            size_sim = 1 - abs(n - bn) / max(n, bn, 1)
            blk_sim = 1 - abs(b - bb) / max(b, bb, 1)
            score = 0.55 * jac + 0.25 * size_sim + 0.20 * blk_sim
            if score < 0.55:
                continue
            out.append({"va": f"0x{r['va']:x}", "name": s.sym(r["va"]),
                        "score": round(score, 3),
                        "shared_callees": sorted(bc & cc)[:8],
                        "summary": fp.get("summary", "")})
        out.sort(key=lambda x: -x["score"])
        return out[:limit]

    # ------------------------------------------------------- constants ---
    def constants(self, *, limit: int = 100) -> list[dict]:
        """Every recognised magic constant and algorithm table in the image."""
        s = self.s
        out = []
        for r in s.db.con.execute(
                "SELECT va, text FROM comments WHERE text LIKE 'algorithm table:%' "
                "OR text LIKE 'EFI_GUID%' ORDER BY va LIMIT ?", (limit,)):
            out.append({"va": f"0x{r['va']:x}", "what": r["text"],
                        "symbol": s.db.get_name(r["va"]),
                        "xrefs": len(s.xrefs_to(r["va"]))})
        for r in s.db.con.execute(
                "SELECT va, fingerprint FROM functions "
                "WHERE fingerprint LIKE '%\"consts\": [\"%'"):
            fp = json.loads(r["fingerprint"])
            if fp.get("consts"):
                out.append({"va": f"0x{r['va']:x}", "name": s.sym(r["va"]),
                            "what": "uses " + ", ".join(fp["consts"][:4]),
                            "summary": fp.get("summary", "")})
        return out[:limit]
