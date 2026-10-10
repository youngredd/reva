"""Data-side discovery: strings, C++ RTTI, vtables, UEFI GUIDs, algo tables."""
from __future__ import annotations

import json
import re
import struct

from . import apiinfo

RE_ASCII = re.compile(rb"[\x20-\x7e\t]{4,}")
RE_UTF16 = re.compile(rb"(?:[\x20-\x7e\t]\x00){4,}")
RE_MANGLED = re.compile(rb"\.\?A[VUW][\x21-\x7e]{1,250}?@@")


def _ident(s: str, limit: int = 28) -> str:
    out = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_")
    return (out[:limit] or "str")


class Scanner:
    def __init__(self, image, db, log=None):
        self.img = image
        self.db = db
        self.log = log or (lambda *a: None)
        self.stats: dict = {}

    def run(self, min_len: int = 4, include_code: bool = False) -> dict:
        self.strings(min_len, include_code)
        self.rtti()
        self.vtables()
        self.guids()
        self.algo_tables()
        self.db.commit()
        return self.stats

    # ------------------------------------------------------- strings ---
    def strings(self, min_len: int = 4, include_code: bool = False) -> None:
        rows: list[tuple] = []
        seen: set[int] = set()
        for s in self.img.sections:
            # instruction bytes trivially match the printable-run regex
            # (`40 55 53 56 57` reads as "@USVW"), so code is off limits unless
            # explicitly asked for
            if s.exec and not include_code:
                continue
            data = s.data[: s.fsize] if s.fsize else s.data
            if not data:
                continue
            # utf-16 first so its bytes are not also reported as short ascii
            taken: list[tuple[int, int]] = []
            for m in RE_UTF16.finditer(data):
                txt = m.group().decode("utf-16-le", "replace")
                if len(txt) < min_len:
                    continue
                va = s.va + m.start()
                rows.append((va, "utf16", len(txt), txt))
                seen.add(va)
                taken.append((m.start(), m.end()))
            tk = sorted(taken)

            def covered(a: int, b: int) -> bool:
                import bisect
                i = bisect.bisect_right([t[0] for t in tk], a) - 1
                return i >= 0 and tk[i][1] >= b

            for m in RE_ASCII.finditer(data):
                if covered(m.start(), m.end()):
                    continue
                txt = m.group().decode("ascii", "replace")
                if len(txt) < min_len:
                    continue
                va = s.va + m.start()
                if va in seen:
                    continue
                rows.append((va, "ascii", len(txt), txt))
                seen.add(va)

        self.db.con.execute("DELETE FROM strings")
        self.db.con.executemany(
            "INSERT OR REPLACE INTO strings (va,enc,len,text) VALUES (?,?,?,?)", rows)
        self.stats["strings"] = len(rows)
        self.log(f"strings: {len(rows)}")
        self._name_referenced_strings()

    def _name_referenced_strings(self) -> None:
        """Give a symbol to strings that code actually points at, IDA style."""
        q = """SELECT s.va, s.enc, s.text FROM strings s
               WHERE EXISTS (SELECT 1 FROM xrefs x WHERE x.dst = s.va)"""
        n = 0
        for r in self.db.con.execute(q).fetchall():
            if self.db.get_name(r["va"]):
                continue
            # a "string" that lives inside a recovered function is really code
            if self.db.func_containing(r["va"]):
                continue
            pre = "a" if r["enc"] == "ascii" else "w"
            nm = pre + _ident(r["text"])
            base = nm
            k = 1
            while self.db.resolve_name(nm) not in (None, r["va"]):
                k += 1
                nm = f"{base}_{k}"
            if self.db.set_name(r["va"], nm, "string_ref"):
                n += 1
        self.stats["named_strings"] = n

    # ---------------------------------------------------------- RTTI ---
    def rtti(self) -> None:
        """Recover MSVC class names and bind them to their vtables."""
        img = self.img
        base = img.base
        ptr = img.ptr_size
        is64 = ptr == 8
        tds: dict[int, str] = {}        # TypeDescriptor VA -> class name

        for s in img.sections:
            data = s.data[: s.fsize] if s.fsize else s.data
            for m in RE_MANGLED.finditer(data):
                strva = s.va + m.start()
                td = strva - 2 * ptr
                if not img.is_valid(td):
                    continue
                tds[td] = m.group().decode("ascii", "replace")

        classes: list[dict] = []
        vt_rows: list[tuple] = []
        for td, mangled in tds.items():
            name = demangle_rtti(mangled)
            self.db.set_name(td, f"TypeDescriptor_{_ident(name)}", "rtti")
            # locate the complete-object-locators that reference this descriptor
            if is64:
                needle = struct.pack("<I", (td - base) & 0xFFFFFFFF)
            else:
                needle = struct.pack("<I", td & 0xFFFFFFFF)
            for a in img.find_all(needle):
                col = a - 12
                if not img.is_valid(col):
                    continue
                sig = img.u32(col)
                if sig is None or sig != (1 if is64 else 0):
                    continue
                if is64:
                    pself = img.u32(col + 20)
                    if pself is None or pself != ((col - base) & 0xFFFFFFFF):
                        continue
                self.db.set_name(col, f"RTTI_COL_{_ident(name)}", "rtti")
                # a pointer to the COL sits immediately before the vtable
                pneedle = struct.pack("<Q" if is64 else "<I", col)
                for p in img.find_all(pneedle):
                    vt = p + ptr
                    slots = self._read_vtable(vt)
                    if len(slots) < 1:
                        continue
                    off = img.u32(col + 4) or 0
                    nm = f"vt_{_ident(name)}" + (f"_{off:x}" if off else "")
                    self.db.set_name(vt, nm, "rtti")
                    vt_rows.append((vt, len(slots), name, json.dumps(slots)))
                    classes.append({"name": name, "vtable": vt,
                                    "nslots": len(slots), "offset": off})
        if vt_rows:
            self.db.con.executemany(
                "INSERT OR REPLACE INTO vtables (va,nslots,class_name,slots) "
                "VALUES (?,?,?,?)", vt_rows)
        # name the virtual methods we just identified
        for c in classes:
            vt = c["vtable"]
            slots = json.loads(self.db.con.execute(
                "SELECT slots FROM vtables WHERE va=?", (vt,)).fetchone()["slots"])
            for idx, t in enumerate(slots):
                if self.db.get_name(t) or self._directly_called(t):
                    continue
                self.db.set_name(t, f"{_ident(c['name'])}__vf{idx:02d}", "rtti")
        self.stats["rtti_classes"] = len(tds)
        self.stats["rtti_vtables"] = len(vt_rows)
        self.log(f"rtti: {len(tds)} type descriptors, {len(vt_rows)} vtables")

    def _read_vtable(self, va: int, max_slots: int = 512) -> list[int]:
        """Read consecutive code pointers, stopping at the next object.

        A run of code pointers in .rdata does not all belong to one vtable:
        unrelated function-pointer tables sit right next to each other. The
        boundary signal is that something else in the image points directly at
        the slot address, which only happens for the start of a new object.
        """
        img = self.img
        out: list[int] = []
        for n in range(max_slots):
            a = va + n * img.ptr_size
            if n:
                if self.db.get_name(a):
                    break           # ran into the next labelled object
                if self.db.con.execute(
                        "SELECT 1 FROM xrefs WHERE dst=? LIMIT 1", (a,)).fetchone():
                    break           # referenced on its own: a different table
            p = img.ptr(a)
            if p is None or not img.is_exec(p):
                break
            out.append(p)
        return out

    def _directly_called(self, va: int) -> bool:
        """True when code calls this address outright, which means it is an
        ordinary function rather than a virtual-only slot."""
        return self.db.con.execute(
            "SELECT 1 FROM xrefs WHERE dst=? AND kind='call' LIMIT 1",
            (va,)).fetchone() is not None

    def vtables(self) -> None:
        """Generic fallback: runs of code pointers in read-only data."""
        img = self.img
        ptr = img.ptr_size
        found = 0
        rows = []
        known = {r["va"] for r in self.db.con.execute("SELECT va FROM vtables")}
        for s in img.sections:
            if s.exec or "w" in s.perms or not s.fsize:
                continue
            off = 0
            n = s.fsize - (s.fsize % ptr)
            while off < n:
                va = s.va + off
                p = img.ptr(va)
                if p is None or not img.is_exec(p):
                    off += ptr
                    continue
                run = []
                a = va
                while a < s.va + n:
                    q = img.ptr(a)
                    if q is None or not img.is_exec(q):
                        break
                    run.append(q)
                    a += ptr
                if len(run) >= 4 and va not in known:
                    rows.append((va, len(run), None, json.dumps(run)))
                    if not self.db.get_name(va):
                        self.db.set_name(va, f"vtbl_{va:x}", "guess")
                    found += 1
                off = (a - s.va) if len(run) else off + ptr
        if rows:
            self.db.con.executemany(
                "INSERT OR REPLACE INTO vtables (va,nslots,class_name,slots) "
                "VALUES (?,?,?,?)", rows)
        self.stats["ptr_tables"] = found

    # ---------------------------------------------------- UEFI GUIDs ---
    def guids(self) -> None:
        hits: list[dict] = []
        for gb, name in apiinfo.EFI_GUIDS.items():
            for va in self.img.find_all(gb):
                hits.append({"va": va, "name": name})
                self.db.set_name(va, f"g{name}", "auto")
                self.db.set_comment(va, f"EFI_GUID {apiinfo.bytes_to_guid(gb)} "
                                        f"= {name}", "line")
        self.stats["efi_guids"] = len(hits)
        if hits:
            self.log(f"efi guids: {len(hits)}")
        self.efi_guid_hits = hits

    # -------------------------------------------------- algo tables ----
    def algo_tables(self) -> None:
        hits = []
        for name, pat in apiinfo.TABLES:
            for va in self.img.find_all(pat):
                hits.append({"va": va, "name": name})
                self.db.set_comment(va, f"algorithm table: {name}", "line")
                if not self.db.get_name(va):
                    self.db.set_name(va, f"tbl_{_ident(name)}", "auto")
        self.stats["algo_tables"] = len(hits)
        if hits:
            self.log(f"algo tables: {[h['name'] for h in hits]}")
        self.algo_hits = hits


# ----------------------------------------------------------- helpers ---
def demangle_rtti(mangled: str) -> str:
    """'.?AVFoo@Bar@@' -> 'Bar::Foo'. Handles the common nested-name case."""
    s = mangled
    if s.startswith(".?A"):
        s = s[4:] if len(s) > 4 and s[3] in "VUW" else s[3:]
    s = s.rstrip("@")
    parts = [p for p in s.split("@") if p]
    if not parts:
        return mangled
    return "::".join(reversed(parts))
