"""A session ties a binary, its project database and the analysis together."""
from __future__ import annotations

import hashlib
import json
import os
import re

from . import analysis, loader, scan
from .db import ProjectDB
from .disasm import Disassembler

def project_dir() -> str:
    """Where project databases live. REVA_PROJECT_DIR overrides it, which is
    what tests and throwaway analysis use to stay out of the real store."""
    return os.environ.get(
        "REVA_PROJECT_DIR",
        os.path.join(os.path.expanduser("~"), ".local", "reva", "projects"))


class Session:
    def __init__(self):
        self.path: str | None = None
        self.img = None
        self.db: ProjectDB | None = None
        self.dis: Disassembler | None = None
        self.lr = None
        self.logs: list[str] = []
        self.analyzed = False

    # ------------------------------------------------------------------
    @property
    def open(self) -> bool:
        return self.img is not None

    def require(self):
        if not self.open:
            raise RuntimeError("no binary open - call open_binary first")
        return self

    def log(self, *a) -> None:
        self.logs.append(" ".join(str(x) for x in a))
        if len(self.logs) > 500:
            del self.logs[:-500]

    # ------------------------------------------------------------------
    def project_path(self, binpath: str) -> str:
        with open(binpath, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()[:16]
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(binpath))
        return os.path.join(project_dir(), f"{stem}.{h}.reva")

    def open_binary(self, path: str, arch: str | None = None,
                    base: int | None = None, reanalyze: bool = False) -> dict:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        self.close()
        self.lr = loader.load(path, arch, base)
        self.img = self.lr.image
        self.path = path
        self.dis = Disassembler(self.img)
        dbp = self.project_path(path)
        fresh = not os.path.exists(dbp)
        self.db = ProjectDB(dbp)
        self.db.set_meta("binary", path)
        for k, v in self.img.meta.items():
            self.db.set_meta(f"img.{k}", v)
        self.db.touch()

        did = False
        if fresh or reanalyze:
            self.analyze()
            did = True
        else:
            self.analyzed = bool(self.db.get_meta("analysis"))
        return {
            "path": path, "project_db": dbp, "fresh_project": fresh,
            "analyzed_now": did, "image": repr(self.img),
            "meta": {k: v for k, v in self.img.meta.items() if k != "sections"},
            "sections": self.img.meta.get("sections", []),
            "notes": self.lr.notes,
            "counts": self.db.counts(),
        }

    def analyze(self, deep: bool = True) -> dict:
        self.require()
        az = analysis.Analyzer(self.img, self.db, self.lr, log=self.log)
        st = az.run(deep=deep)
        sc = scan.Scanner(self.img, self.db, log=self.log)
        st.update(sc.run())
        self.db.set_meta("analysis", st)
        self.db.commit()
        self.analyzed = True
        return st

    def close(self) -> None:
        if self.db:
            self.db.close()
        self.img = self.db = self.dis = self.lr = None
        self.path = None
        self.analyzed = False

    # ------------------------------------------------ address resolve --
    def resolve(self, spec) -> int:
        """Accept an int, '0x...', a decimal string, a symbol name, or
        'name+0x10' / 'section:+0x20'."""
        if isinstance(spec, int):
            return spec
        s = str(spec).strip()
        if not s:
            raise ValueError("empty address")
        m = re.match(r"^(.*?)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$", s)
        delta = 0
        if m and m.group(1):
            s = m.group(1).strip()
            delta = int(m.group(3), 0) * (1 if m.group(2) == "+" else -1)
        try:
            return int(s, 0) + delta
        except ValueError:
            pass
        va = self.db.resolve_name(s)
        if va is not None:
            return va + delta
        # an import referenced by bare api name resolves to its thunk
        r = self.db.con.execute(
            "SELECT va, thunk FROM imports WHERE name=? COLLATE NOCASE", (s,)
        ).fetchone()
        if r:
            return (r["thunk"] or r["va"]) + delta
        sec = self.img.section_by_name(s) if self.img else None
        if sec:
            return sec.va + delta
        raise ValueError(f"cannot resolve address: {spec!r}")

    # ------------------------------------------------------- symbols ---
    def sym(self, va: int, short: bool = False) -> str:
        """Best available label for an address."""
        nm = self.db.get_name(va)
        if nm:
            return nm
        f = self.db.func_at(va)
        if f:
            return f"sub_{va:x}"
        if self.db.func_containing(va):
            return f"loc_{va:x}"
        if self.img.is_exec(va):
            return f"loc_{va:x}"
        if self.img.is_valid(va):
            return f"off_{va:x}"
        return f"unk_{va:x}" if not short else f"{va:x}"

    def syms_bulk(self, vas) -> dict[int, str]:
        known = self.db.names_bulk(vas)
        out = {}
        for va in set(vas):
            out[va] = known.get(va) or self.sym(va)
        return out

    def string_at(self, va: int) -> dict | None:
        r = self.db.con.execute(
            "SELECT va,enc,len,text FROM strings WHERE va=?", (va,)).fetchone()
        return dict(r) if r else None

    def func_of(self, va: int):
        return self.db.func_at(va) or self.db.func_containing(va)

    def fingerprint(self, va: int) -> dict:
        r = self.db.func_at(va)
        if not r or not r["fingerprint"]:
            return {}
        return json.loads(r["fingerprint"])

    def xrefs_to(self, va: int, kinds=None) -> list[dict]:
        q = "SELECT frm,kind FROM xrefs WHERE dst=?"
        args = [va]
        if kinds:
            q += " AND kind IN (%s)" % ",".join("?" * len(kinds))
            args += list(kinds)
        out = []
        for r in self.db.con.execute(q + " ORDER BY frm", args):
            f = self.func_of(r["frm"])
            out.append({"frm": r["frm"], "kind": r["kind"],
                        "in_func": f["va"] if f else None,
                        "in_func_name": self.sym(f["va"]) if f else None})
        return out

    def xrefs_from(self, va: int) -> list[dict]:
        out = []
        for r in self.db.con.execute(
                "SELECT dst,kind FROM xrefs WHERE frm=? ORDER BY dst", (va,)):
            d = {"dst": r["dst"], "kind": r["kind"], "name": self.sym(r["dst"])}
            s = self.string_at(r["dst"])
            if s:
                d["string"] = s["text"][:120]
            out.append(d)
        return out

    def blocks_of(self, fva: int) -> list[dict]:
        rows = self.db.con.execute(
            "SELECT va,end,succs,kind FROM blocks WHERE func=? ORDER BY va",
            (fva,)).fetchall()
        return [{"va": r["va"], "end": r["end"], "kind": r["kind"],
                 "succs": json.loads(r["succs"])} for r in rows]
