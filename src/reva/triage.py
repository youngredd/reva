"""First-look report: what is this binary, and where should I start reading.

Answers the questions you have before you have read a single instruction, and
ranks the functions worth opening first so a large binary does not have to be
read in address order.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from . import apiinfo

RE_URL = re.compile(r"\b(?:https?|ftp|ws)://[^\s\"'<>|]{4,}", re.I)
RE_UNC = re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\s\"'|]{2,}")
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_REGKEY = re.compile(
    r"\b(?:HKEY_[A-Z_]+|SOFTWARE\\\\?[\w .\\-]{3,}|SYSTEM\\\\?CurrentControlSet"
    r"[\w\\-]*)", re.I)
RE_PATH = re.compile(r"\b[A-Za-z]:\\\\?[\w .\\$()-]{3,}")
RE_CMD = re.compile(r"\b(?:cmd\.exe|powershell|wscript|cscript|rundll32|regsvr32"
                    r"|schtasks|net\s+user|vssadmin|bcdedit|wmic|certutil|mshta"
                    r"|bitsadmin|sc\s+create)\b", re.I)
RE_DLL = re.compile(r"\b\w{2,}\.(?:dll|sys|exe|efi)\b", re.I)
RE_MUTEX = re.compile(r"\b(?:Global|Local)\\[\w .{}-]{3,}")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
RE_B64 = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".nsp0": "NsPack",
    ".taz": "PESpin", ".packed": "generic packer", "pebundle": "PEBundle",
    ".boom": "BoomerangLib", ".ccg": "CCG", ".charmve": "PIN",
    ".winapi": "AHTeam", ".y0da": "Yoda", ".shrink": "Shrinker",
}


class Triage:
    def __init__(self, sess):
        self.s = sess

    def report(self, *, top_functions: int = 20,
               max_strings: int = 14) -> dict:
        s = self.s
        m = s.img.meta
        out: dict = {}
        out["identity"] = self._identity(m)
        out["sections"] = self._sections(m)
        out["packing"] = self._packing(m)
        out["imports"] = self._imports()
        out["entry_chain"] = self._entry_chain()
        out["interesting_strings"] = self._strings(max_strings)
        out["crypto_and_tables"] = self._crypto()
        out["start_here"] = self._ranked(top_functions)
        if m.get("is_efi"):
            out["uefi"] = self._uefi()
        if m.get("is_dll") or m.get("is_driver"):
            out["exports"] = self._exports()
        out["coverage"] = self._coverage()
        return out

    # ------------------------------------------------------------------
    def _identity(self, m: dict) -> dict:
        kind = "DLL" if m.get("is_dll") else "EXE"
        if m.get("is_efi"):
            kind = f"UEFI image ({m.get('subsystem')})"
        elif m.get("is_driver"):
            kind = "kernel driver / native"
        d = {
            "file": self.s.path, "format": m.get("format"),
            "kind": kind, "arch": m.get("arch"), "bits": m.get("bits"),
            "subsystem": m.get("subsystem"),
            "image_base": hex(m.get("image_base", 0)),
            "entry": hex(m.get("entry", 0)),
            "size": m.get("file_size"), "sha256": m.get("sha256"),
            "md5": m.get("md5"), "imphash": m.get("imphash"),
            "entropy": m.get("entropy"),
            "mitigations": m.get("dll_characteristics", []),
        }
        if m.get("pdb"):
            d["pdb"] = m["pdb"]
            d["note_pdb"] = ("the pdb path often leaks the original project "
                             "name and build layout")
        if m.get("timestamp"):
            import datetime
            try:
                d["timestamp"] = datetime.datetime.fromtimestamp(
                    m["timestamp"], datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%SZ")
            except Exception:
                pass
        if m.get("overlay"):
            d["overlay"] = m["overlay"]
            d["note_overlay"] = ("data appended after the last section: "
                                 "installer payload, config or signature")
        return d

    def _sections(self, m: dict) -> list[dict]:
        out = []
        for sec in m.get("sections", []):
            flags = []
            if "w" in sec["perms"] and "x" in sec["perms"]:
                flags.append("WRITE+EXEC (self-modifying or unpacking)")
            if sec["entropy"] > 7.2 and sec["fsize"] > 0x400:
                flags.append("very high entropy (packed/encrypted/compressed)")
            if sec["fsize"] == 0 and sec["vsize"] > 0x1000:
                flags.append("no file data but large virtual size "
                             "(unpacking target)")
            if sec["vsize"] > 4 * max(sec["fsize"], 1) and sec["fsize"]:
                flags.append("virtual size far exceeds raw size")
            low = sec["name"].lower()
            if low in PACKER_SECTIONS:
                flags.append(f"packer section: {PACKER_SECTIONS[low]}")
            d = dict(sec)
            d["va"] = hex(sec["va"])
            if flags:
                d["flags"] = flags
            out.append(d)
        return out

    def _packing(self, m: dict) -> dict:
        hints = []
        names = {s["name"].lower() for s in m.get("sections", [])}
        for n in names & set(PACKER_SECTIONS):
            hints.append(f"section {n} -> {PACKER_SECTIONS[n]}")
        nimp = self.s.db.con.execute(
            "SELECT COUNT(*) c FROM imports").fetchone()["c"]
        if nimp and nimp < 12 and not m.get("is_efi"):
            hints.append(f"only {nimp} imports: imports are probably resolved "
                         f"at runtime")
        dyn = self.s.db.con.execute(
            "SELECT COUNT(*) c FROM imports WHERE name IN "
            "('LoadLibraryA','LoadLibraryW','GetProcAddress','LdrLoadDll')"
        ).fetchone()["c"]
        if dyn:
            hints.append("imports LoadLibrary/GetProcAddress: dynamic api "
                         "resolution, expect names to be hidden")
        txt = next((s for s in m.get("sections", [])
                    if s["name"].lower() in (".text", "code")), None)
        if txt and txt["entropy"] > 7.0:
            hints.append("code section entropy > 7.0: likely packed")
        ep = m.get("entry", 0)
        sec = self.s.img.section_at(ep) if ep else None
        if sec and sec.name.lower() not in (".text", "code", ".init", "fothk"):
            hints.append(f"entry point is in '{sec.name}', not the code "
                         f"section")
        if sec and "w" in sec.perms:
            hints.append("entry point sits in a writable section")
        return {"likely_packed": bool(hints), "hints": hints}

    def _imports(self) -> dict:
        rows = self.s.db.con.execute(
            "SELECT dll, name, kind FROM imports").fetchall()
        by_dll = Counter(r["dll"] for r in rows)
        cats: dict[str, list[str]] = defaultdict(list)
        for r in rows:
            for c in apiinfo.categorize_api(r["name"]):
                cats[c].append(r["name"])
        ranked = sorted(cats.items(),
                        key=lambda kv: -apiinfo.CATEGORY_WEIGHT.get(kv[0], 0))
        return {
            "total": len(rows),
            "dlls": dict(by_dll.most_common(20)),
            "delay_loaded": sum(1 for r in rows if r["kind"] == "delay_import"),
            "capabilities": {
                c: {"weight": apiinfo.CATEGORY_WEIGHT.get(c, 0),
                    "apis": sorted(set(v))[:14], "count": len(set(v))}
                for c, v in ranked if apiinfo.CATEGORY_WEIGHT.get(c, 0) > 0
            },
        }

    def _entry_chain(self) -> list[dict]:
        """The entry point and the first things it reaches, plus TLS callbacks
        (which run before the entry point and are a classic hiding place)."""
        s = self.s
        out = []
        seeds = []
        if s.img.entry:
            seeds.append(("entry", s.img.entry))
        for r in s.db.con.execute(
                "SELECT va, source FROM functions WHERE source='tls_callback'"):
            seeds.append(("tls_callback (runs BEFORE entry)", r["va"]))
        for label, va in seeds:
            fp = s.fingerprint(va)
            callees = []
            for x in s.xrefs_from(va):
                pass
            for r in s.db.con.execute(
                    "SELECT DISTINCT dst FROM xrefs WHERE kind='call' AND "
                    "frm >= ? AND frm < ? LIMIT 12",
                    (va, va + max(1, fp.get("size", 0x200)))):
                callees.append(s.sym(r["dst"]))
            out.append({"role": label, "va": f"0x{va:x}", "name": s.sym(va),
                        "summary": fp.get("summary", ""), "calls": callees})
        return out

    def _strings(self, limit: int) -> dict:
        s = self.s
        rows = s.db.con.execute("SELECT va, text FROM strings").fetchall()
        buckets: dict[str, list[dict]] = defaultdict(list)
        pats = [("urls", RE_URL), ("unc_paths", RE_UNC), ("ip_addresses", RE_IPV4),
                ("registry", RE_REGKEY), ("file_paths", RE_PATH),
                ("commands", RE_CMD), ("modules", RE_DLL),
                ("mutex_or_event", RE_MUTEX), ("emails", RE_EMAIL),
                ("long_base64ish", RE_B64)]
        for r in rows:
            t = r["text"]
            for name, rx in pats:
                if rx.search(t):
                    if len(buckets[name]) < limit:
                        refs = len(s.xrefs_to(r["va"]))
                        buckets[name].append(
                            {"va": f"0x{r['va']:x}", "text": t[:200],
                             "xrefs": refs})
                    break
        # ip_addresses matches version strings too, so filter the obvious noise
        buckets["ip_addresses"] = [
            b for b in buckets.get("ip_addresses", [])
            if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", b["text"].strip())
            or all(0 <= int(x) <= 255 for x in b["text"].strip().split("."))]
        return {k: v for k, v in buckets.items() if v}

    def _crypto(self) -> list[dict]:
        s = self.s
        out = []
        for r in s.db.con.execute(
                "SELECT va, text FROM comments WHERE text LIKE 'algorithm table:%'"):
            out.append({"va": f"0x{r['va']:x}", "finding": r["text"],
                        "xrefs": len(s.xrefs_to(r["va"]))})
        seen = set()
        for r in s.db.con.execute("SELECT va, fingerprint FROM functions"):
            fp = json.loads(r["fingerprint"] or "{}")
            for c in fp.get("consts", []):
                if c in seen:
                    continue
                seen.add(c)
                out.append({"va": f"0x{r['va']:x}", "name": s.sym(r["va"]),
                            "finding": f"constant: {c}"})
        heavy = []
        for r in s.db.con.execute("SELECT va, fingerprint FROM functions"):
            fp = json.loads(r["fingerprint"] or "{}")
            if fp.get("crypto_density", 0) > 0.18 and fp.get("ninsn", 0) > 25:
                heavy.append({"va": f"0x{r['va']:x}", "name": s.sym(r["va"]),
                              "finding": f"bit-operation heavy "
                                         f"({int(fp['crypto_density']*100)}% of "
                                         f"instructions)",
                              "summary": fp.get("summary", "")})
        heavy.sort(key=lambda x: x["name"])
        return out[:40] + heavy[:15]

    def _ranked(self, n: int) -> list[dict]:
        s = self.s
        rows = []
        for r in s.db.con.execute(
                "SELECT va, ninsn, fingerprint FROM functions "
                "WHERE fingerprint IS NOT NULL"):
            fp = json.loads(r["fingerprint"])
            if "thunk" in fp.get("flags", []):
                continue
            score = fp.get("risk", 0) * 3
            score += min(fp.get("ninsn", 0), 400) / 40
            score += 4 * len(set(fp.get("cats", [])))
            score += 3 if fp.get("consts") else 0
            score += 2 * min(fp.get("loops", 0), 5)
            if fp.get("crypto_density", 0) > 0.15:
                score += 6
            if fp.get("ncallers", 0) == 0:
                score += 2          # unreferenced: callback or entry
            rows.append((score, r["va"], fp))
        rows.sort(key=lambda x: -x[0])
        out = []
        for score, va, fp in rows[:n]:
            out.append({
                "va": f"0x{va:x}", "name": s.sym(va),
                "score": round(score, 1), "risk": fp.get("risk", 0),
                "why": fp.get("summary", ""),
                "callers": fp.get("ncallers", 0),
            })
        return out

    def _uefi(self) -> dict:
        s = self.s
        guids = []
        for r in s.db.con.execute(
                "SELECT va, text FROM comments WHERE text LIKE 'EFI_GUID%'"):
            guids.append({"va": f"0x{r['va']:x}", "guid": r["text"],
                          "xrefs": len(s.xrefs_to(r["va"]))})
        return {
            "protocol_guids_found": len(guids),
            "guids": guids[:30],
            "note": ("UEFI images have no import table: services are reached "
                     "through EFI_SYSTEM_TABLE (passed as the 2nd argument to "
                     "the entry point) and protocols are located by GUID. "
                     "Look for calls through offsets of the boot services "
                     "table, and for the GUIDs listed above."),
            "entry_signature": "EFI_STATUS entry(EFI_HANDLE ImageHandle, "
                               "EFI_SYSTEM_TABLE *SystemTable)",
        }

    def _exports(self) -> dict:
        s = self.s
        rows = s.db.con.execute(
            "SELECT va, name, ordinal, forwarder FROM exports ORDER BY name"
        ).fetchall()
        fwd = [{"name": r["name"], "to": r["forwarder"]}
               for r in rows if r["forwarder"]]
        notable = []
        for r in rows:
            if r["forwarder"]:
                continue
            cats = apiinfo.categorize_api(r["name"])
            if cats or r["name"] in ("DllMain", "ServiceMain", "DriverEntry",
                                     "DllRegisterServer", "DllInstall"):
                notable.append({"va": f"0x{r['va']:x}", "name": r["name"],
                                "categories": cats})
        return {"total": len(rows), "forwarders": fwd[:20],
                "notable": notable[:30]}

    def _coverage(self) -> dict:
        s = self.s
        st = s.db.get_meta("analysis", {}) or {}
        exec_bytes = sum(sec.vsize for sec in s.img.iter_exec_sections())
        code = st.get("code_bytes", 0)
        return {
            "functions": st.get("functions"),
            "instructions": st.get("instructions"),
            "executable_bytes": exec_bytes,
            "bytes_in_recovered_functions": code,
            "coverage_pct": round(100 * code / exec_bytes, 1) if exec_bytes else 0,
            "jump_tables_resolved": st.get("jumptables"),
            "strings": st.get("strings"),
            "note": ("coverage well under 100% on a packed or obfuscated "
                     "binary is expected; on a normal compiled binary it "
                     "suggests unreached code worth hunting for"),
        }
