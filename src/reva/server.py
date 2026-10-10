"""REVA MCP server: the reverse-engineering toolset exposed as tools.

Every tool that takes an address accepts an int, a hex or decimal string, a
symbol name, an imported api name, a section name, or any of those with an
offset: 0x140001000, "MessageBoxW", "sub_140001234", ".text+0x200".
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

import functools
import traceback

try:
    # mcp >= 2.0 renamed FastMCP to MCPServer; the decorator API is the same
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:  # pragma: no cover - mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server
    from mcp.server.fastmcp.exceptions import ToolError

from . import __version__
from .emu import Emulator, decrypt_strings
from .lifter import Lifter
from .patcher import Patcher, PatchError
from .render import Renderer
from .search import Search
from .session import Session
from .triage import Triage

INSTRUCTIONS = """\
REVA is a reverse-engineering workbench for PE/COFF binaries (exe, dll, sys,
efi) with live debugging. Typical flow:

  1. open_binary(path)      - loads and analyses; the project database persists
                              across sessions, so names and comments you set
                              are still there next time.
  2. triage()               - what this binary is, and a ranked "start here"
                              list so you need not read it in address order.
  3. list_functions / search / list_strings  - narrow down.
  4. decompile(at)          - pseudo-C. disasm(at) when you need the real thing.
  5. annotate(at, name=..., comment=...)     - record what you worked out. Do
                              this as you go; it is what makes the next pass
                              cheaper, and it feeds every later listing.
  6. emulate(at, args=[..]) - run a function for real to settle what static
                              reading cannot: string decoders, hash routines,
                              import resolvers.
  7. dbg_* tools            - launch or attach to a live process, breakpoints
                              (software and hardware), stepping, memory.

Notes that save time:
  * decompile output marks its own approximations; __asm(...) lines are
    instructions the lifter does not model, shown verbatim rather than guessed.
  * search(kind="behavior", calls=[...]) finds functions by the apis they call,
    which is usually the question you actually have.
  * patches are staged in the database and reviewable; write_patched_file
    produces a new file and never modifies the input.
"""

mcp = _Server("reva", instructions=INSTRUCTIONS, version=__version__)

SESS = Session()
_DBG: Any = None
_DBG_ERR: Optional[str] = None

# Only ToolError carries its message back to the caller; every other exception
# is treated as a server crash and its text is kept server-side. A diagnostic
# that never reaches the caller is worthless, so each tool is wrapped to
# re-raise with the real reason, plus a short traceback when the failure was
# not one we deliberately raise.
_EXPECTED = (ValueError, FileNotFoundError, KeyError, NotImplementedError,
             PatchError)


def tool(*targs, **tkw):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except ToolError:
                raise
            except Exception as e:
                detail = f"{type(e).__name__}: {e}"
                if not isinstance(e, _EXPECTED):
                    detail += "\n" + traceback.format_exc(limit=4)[-900:]
                raise ToolError(detail) from e
        return mcp.tool(*targs, **tkw)(wrapper)
    return deco


def _hexkeys(d: dict) -> dict:
    """Addresses used as dict keys become JSON strings, so make them hex."""
    return {(f"0x{k:x}" if isinstance(k, int) else str(k)): v
            for k, v in d.items()}


# ============================================================ helpers ===
def _s() -> Session:
    if not SESS.open:
        raise ValueError("no binary is open; call open_binary(path) first")
    return SESS


def _at(spec) -> int:
    return _s().resolve(spec)


def _hex(v: int) -> str:
    return f"0x{v:x}"


def _dbg():
    global _DBG, _DBG_ERR
    if _DBG is None:
        try:
            from .debug import Debugger
        except Exception as e:                       # pragma: no cover
            _DBG_ERR = f"debugger unavailable: {type(e).__name__}: {e}"
            raise ValueError(_DBG_ERR)
        _DBG = Debugger()
    return _DBG


def _live():
    if _DBG is None:
        raise ValueError("no debug session; call dbg_start first")
    return _DBG


# ============================================================ project ===
@tool()
def open_binary(path: str, arch: Optional[str] = None,
                base: Optional[int] = None,
                reanalyze: bool = False) -> dict:
    """Load a binary and analyse it. Reopening an already-analysed binary
    restores its project database instead of re-analysing.

    arch/base are only needed for raw blobs with no headers (firmware dumps):
    arch is one of x86_64, x86, arm64, arm, thumb.
    """
    return SESS.open_binary(path, arch, base, reanalyze)


@tool()
def project_info() -> dict:
    """Image metadata, section layout, analysis statistics and database counts."""
    s = _s()
    return {
        "reva_version": __version__,
        "binary": s.path,
        "project_db": s.project_path(s.path),
        "image": repr(s.img),
        "meta": {k: v for k, v in s.img.meta.items() if k != "sections"},
        "sections": [
            {**sec, "va": _hex(sec["va"]),
             "end": _hex(sec["va"] + sec["vsize"])}
            for sec in s.img.meta.get("sections", [])],
        "analysis": s.db.get_meta("analysis", {}),
        "counts": s.db.counts(),
        "notes": s.lr.notes if s.lr else [],
    }


@tool()
def analyze(deep: bool = True) -> dict:
    """Re-run analysis. User-assigned names and comments are preserved."""
    return _s().analyze(deep=deep)


@tool()
def triage(top_functions: int = 20) -> dict:
    """First-look report: identity, packing signs, capabilities by api
    category, entry chain, notable strings, crypto findings, and a ranked list
    of the functions worth reading first."""
    return Triage(_s()).report(top_functions=top_functions)


@tool()
def close_binary() -> dict:
    """Close the current project, committing the database."""
    p = SESS.path
    SESS.close()
    return {"closed": p}


# ============================================================ listings ===
@tool()
def list_functions(name_filter: Optional[str] = None,
                   categories: Optional[list[str]] = None,
                   min_insn: int = 0, max_insn: int = 0,
                   sort: str = "risk", limit: int = 60,
                   offset: int = 0, named_only: bool = False) -> dict:
    """Recovered functions with their behavioural profile.

    sort: risk | size | addr | callers | name.
    categories filters on api categories such as network, crypto, injection,
    antidebug, registry, file, process, memory, keylog, privilege, driver.
    """
    s = _s()
    rows = s.db.con.execute(
        "SELECT va, size, nblocks, ninsn, source, flags, prototype, "
        "fingerprint FROM functions").fetchall()
    out = []
    for r in rows:
        fp = json.loads(r["fingerprint"] or "{}")
        nm = s.sym(r["va"])
        if name_filter and name_filter.lower() not in nm.lower():
            continue
        if named_only and not s.db.get_name(r["va"]):
            continue
        if min_insn and r["ninsn"] < min_insn:
            continue
        if max_insn and r["ninsn"] > max_insn:
            continue
        if categories and not set(categories) & set(fp.get("cats", [])):
            continue
        out.append({
            "va": _hex(r["va"]), "name": nm, "size": r["size"],
            "insns": r["ninsn"], "blocks": r["nblocks"],
            "risk": fp.get("risk", 0), "callers": fp.get("ncallers", 0),
            "args": fp.get("args"), "source": r["source"],
            "prototype": r["prototype"],
            "profile": fp.get("summary", ""),
        })
    keys = {"risk": lambda x: (-x["risk"], -x["insns"]),
            "size": lambda x: -x["size"],
            "addr": lambda x: int(x["va"], 16),
            "callers": lambda x: -x["callers"],
            "name": lambda x: x["name"]}
    out.sort(key=keys.get(sort, keys["risk"]))
    return {"total_matching": len(out), "offset": offset,
            "functions": out[offset:offset + limit]}


@tool()
def list_strings(filter: Optional[str] = None, min_len: int = 4,
                 enc: Optional[str] = None, referenced_only: bool = False,
                 limit: int = 80, offset: int = 0) -> dict:
    """Strings found in the image, with the code that references them."""
    s = _s()
    q = "SELECT va, enc, len, text FROM strings WHERE len >= ?"
    args: list = [min_len]
    if filter:
        q += " AND text LIKE ?"
        args.append(f"%{filter}%")
    if enc:
        q += " AND enc = ?"
        args.append(enc)
    q += " ORDER BY va"
    rows = s.db.con.execute(q, args).fetchall()
    out = []
    for r in rows:
        refs = s.xrefs_to(r["va"])
        if referenced_only and not refs:
            continue
        out.append({"va": _hex(r["va"]), "enc": r["enc"], "len": r["len"],
                    "text": r["text"][:400],
                    "symbol": s.db.get_name(r["va"]),
                    "nxrefs": len(refs),
                    "referenced_by": [x["in_func_name"] or _hex(x["frm"])
                                      for x in refs[:6]]})
    return {"total_matching": len(out), "offset": offset,
            "strings": out[offset:offset + limit]}


@tool()
def list_symbols(kind: str = "imports", filter: Optional[str] = None,
                 limit: int = 100, offset: int = 0) -> dict:
    """kind: imports | exports | names | vtables | jumptables | patches |
    bookmarks | notes."""
    s = _s()
    f = f"%{filter}%" if filter else "%"
    if kind == "imports":
        rows = s.db.con.execute(
            "SELECT va, dll, name, ordinal, kind, thunk FROM imports "
            "WHERE name LIKE ? OR dll LIKE ? ORDER BY dll, name",
            (f, f)).fetchall()
        items = [{"iat_slot": _hex(r["va"]), "dll": r["dll"], "name": r["name"],
                  "ordinal": r["ordinal"], "kind": r["kind"],
                  "thunk": _hex(r["thunk"]) if r["thunk"] else None}
                 for r in rows]
    elif kind == "exports":
        rows = s.db.con.execute(
            "SELECT va, name, ordinal, forwarder FROM exports "
            "WHERE name LIKE ? ORDER BY name", (f,)).fetchall()
        items = [{"va": _hex(r["va"]), "name": r["name"],
                  "ordinal": r["ordinal"], "forwarder": r["forwarder"]}
                 for r in rows]
    elif kind == "names":
        rows = s.db.con.execute(
            "SELECT va, name, source FROM names WHERE name LIKE ? "
            "ORDER BY va", (f,)).fetchall()
        items = [{"va": _hex(r["va"]), "name": r["name"],
                  "source": r["source"]} for r in rows]
    elif kind == "vtables":
        rows = s.db.con.execute(
            "SELECT va, nslots, class_name, slots FROM vtables "
            "WHERE COALESCE(class_name,'') LIKE ? OR ? = '%' "
            "ORDER BY nslots DESC", (f, f)).fetchall()
        items = [{"va": _hex(r["va"]), "class": r["class_name"],
                  "slots": r["nslots"],
                  "methods": [s.sym(v) for v in json.loads(r["slots"])[:12]]}
                 for r in rows]
    elif kind == "jumptables":
        rows = s.db.con.execute(
            "SELECT va, count, targets FROM jumptables ORDER BY va").fetchall()
        items = [{"indirect_jmp": _hex(r["va"]), "entries": r["count"],
                  "in_function": (lambda fn: s.sym(fn["va"]) if fn else None)(
                      s.func_of(r["va"])),
                  "targets": [_hex(t) for t in json.loads(r["targets"])[:16]]}
                 for r in rows]
    elif kind == "patches":
        items = Patcher(s).list_patches()
    elif kind == "bookmarks":
        rows = s.db.con.execute(
            "SELECT va, note FROM bookmarks ORDER BY va").fetchall()
        items = [{"va": _hex(r["va"]), "name": s.sym(r["va"]),
                  "note": r["note"]} for r in rows]
    elif kind == "notes":
        rows = s.db.con.execute("SELECT topic, body FROM notes").fetchall()
        items = [{"topic": r["topic"], "body": r["body"]} for r in rows]
    else:
        raise ValueError(f"unknown kind {kind!r}")
    return {"kind": kind, "total": len(items), "offset": offset,
            "items": items[offset:offset + limit]}


# ============================================================= reading ===
@tool()
def disasm(at: str, count: int = 0, end: Optional[str] = None,
           show_bytes: bool = False, whole_function: bool = False,
           max_insn: int = 3000) -> str:
    """Annotated disassembly: call targets and data references resolved to
    symbols, referenced strings inlined as comments, stack slots named.

    Give `count` instructions, an `end` address, or whole_function=True.
    """
    s = _s()
    va = _at(at)
    r = Renderer(s)
    if whole_function:
        f = s.func_of(va)
        if f is None:
            raise ValueError(f"{_hex(va)} is not inside a recovered function; "
                             f"use count/end, or make_function first")
        return r.function(f["va"], show_bytes=show_bytes, max_insn=max_insn)
    if end:
        return r.range(va, end=_at(end), show_bytes=show_bytes)
    return r.range(va, count=count or 40, show_bytes=show_bytes)


@tool()
def decompile(at: str, max_blocks: int = 600) -> str:
    """Pseudo-C for the function containing `at`.

    This is expression propagation with light control-flow structuring, not a
    full decompiler: it has no type inference, propagates values only inside a
    basic block, and models flags as the last comparison. Anything it does not
    model appears as __asm("...") rather than being guessed at. The header
    comment restates these limits.
    """
    s = _s()
    va = _at(at)
    f = s.func_of(va)
    if f is None:
        raise ValueError(f"{_hex(va)} is not inside a recovered function; "
                         f"try make_function({at!r})")
    return Lifter(s).decompile(f["va"], max_blocks=max_blocks)


@tool()
def function_info(at: str) -> dict:
    """Everything known about one function: bounds, profile, callers, callees,
    strings it uses, and its basic-block layout."""
    s = _s()
    va = _at(at)
    f = s.func_of(va)
    if f is None:
        return {"va": _hex(va), "recovered": False,
                "section": (lambda x: x.name if x else None)(
                    s.img.section_at(va)),
                "symbol": s.db.get_name(va),
                "hint": "not a recovered function; make_function() can force it"}
    fva = f["va"]
    fp = s.fingerprint(fva)
    callers = s.xrefs_to(fva, ["call", "jump"])
    callees = []
    for r in s.db.con.execute(
            "SELECT DISTINCT dst, kind FROM xrefs WHERE frm >= ? AND frm < ? "
            "AND kind IN ('call','jump')", (fva, f["end"])):
        if not (fva <= r["dst"] < f["end"]):
            callees.append({"va": _hex(r["dst"]), "name": s.sym(r["dst"]),
                            "kind": r["kind"]})
    strs = s.db.con.execute(
        "SELECT DISTINCT s.va, s.text FROM xrefs x JOIN strings s "
        "ON s.va = x.dst WHERE x.frm >= ? AND x.frm < ? LIMIT 40",
        (fva, f["end"])).fetchall()
    return {
        "va": _hex(fva), "name": s.sym(fva), "recovered": True,
        "end": _hex(f["end"]), "size": f["size"],
        "blocks": f["nblocks"], "instructions": f["ninsn"],
        "discovered_by": f["source"], "cc": f["cc"],
        "prototype": f["prototype"], "flags": json.loads(f["flags"] or "[]"),
        "stack_frame": f["stack_size"], "profile": fp,
        "callers": [{"from": _hex(c["frm"]), "in": c["in_func_name"],
                     "kind": c["kind"]} for c in callers[:40]],
        "ncallers": len(callers),
        "callees": callees[:60],
        "strings_used": [{"va": _hex(r["va"]), "text": r["text"][:160]}
                         for r in strs],
        "comments": _hexkeys(s.db.comments_in(fva, f["end"] + 1)),
    }


@tool()
def read_data(at: str, size: int = 64, format: str = "auto") -> str:
    """Read data. format: auto | hex | string | ptr.
    ptr formats the range as pointers with symbol and string resolution, which
    is what you want for vtables and function-pointer tables."""
    s = _s()
    return Renderer(s).data(_at(at), size, format)


@tool()
def cfg(at: str) -> str:
    """Basic-block layout of a function: ranges, terminators, successors."""
    s = _s()
    f = s.func_of(_at(at))
    if f is None:
        raise ValueError(f"{at} is not inside a recovered function")
    return Renderer(s).cfg(f["va"])


# ========================================================== navigation ===
@tool()
def xrefs(at: str, direction: str = "to") -> dict:
    """Cross references. direction: to | from | both."""
    s = _s()
    va = _at(at)
    out: dict = {"va": _hex(va), "symbol": s.sym(va)}
    if direction in ("to", "both"):
        refs = s.xrefs_to(va)
        out["xrefs_to"] = [{"from": _hex(r["frm"]), "kind": r["kind"],
                            "in_function": r["in_func_name"]} for r in refs]
        out["n_to"] = len(refs)
    if direction in ("from", "both"):
        out["xrefs_from"] = s.xrefs_from(va)
    return out


@tool()
def search(kind: str, query: Optional[str] = None,
           calls: Optional[list[str]] = None,
           value: Optional[int] = None, at: Optional[str] = None,
           mode: str = "all", ordered: bool = False,
           categories: Optional[list[str]] = None,
           min_risk: int = 0, regex: bool = False,
           exec_only: bool = False, limit: int = 60) -> dict:
    """Search the image.

    kind="bytes"      query is an IDA-style pattern: "48 8b ?? 24" or "488b05".
    kind="text"       query is a substring (or regex with regex=True).
    kind="immediate"  value is the number to find, as operand and as data.
    kind="behavior"   calls is a list of api name fragments; mode all|any,
                      ordered=True requires them in sequence. Optionally
                      filter by categories and min_risk.
    kind="similar"    at is a function; finds functions that resemble it.
    kind="constants"  recognised crypto constants and algorithm tables.
    """
    s = _s()
    se = Search(s)
    if kind == "bytes":
        if not query:
            raise ValueError("bytes search needs query")
        return {"kind": kind, "hits": se.bytes_pattern(
            query, limit=limit, exec_only=exec_only)}
    if kind == "text":
        if not query:
            raise ValueError("text search needs query")
        return {"kind": kind, "hits": se.text(query, limit=limit, regex=regex)}
    if kind == "immediate":
        if value is None:
            raise ValueError("immediate search needs value")
        return {"kind": kind, "hits": se.immediate(value, limit=limit)}
    if kind == "behavior":
        return {"kind": kind, "hits": se.behavior(
            calls or [], mode=mode, ordered=ordered, categories=categories,
            min_risk=min_risk, limit=limit)}
    if kind == "similar":
        if not at:
            raise ValueError("similar search needs at")
        f = s.func_of(_at(at))
        if f is None:
            raise ValueError(f"{at} is not a recovered function")
        return {"kind": kind, "of": s.sym(f["va"]),
                "hits": se.similar(f["va"], limit=limit)}
    if kind == "constants":
        return {"kind": kind, "hits": se.constants(limit=limit)}
    raise ValueError(f"unknown search kind {kind!r}")


# ========================================================== annotation ===
@tool()
def annotate(at: str, name: Optional[str] = None,
             comment: Optional[str] = None,
             pre_comment: Optional[str] = None,
             prototype: Optional[str] = None,
             bookmark: Optional[str] = None) -> dict:
    """Record a conclusion in the project database, where it persists and feeds
    every later listing and disassembly. Names set here outrank anything
    analysis infers and survive re-analysis.

    name       symbol for this address
    comment    inline comment on the instruction
    pre_comment  block comment shown above a function
    prototype  C signature, used by decompile for the call sites
    bookmark   adds the address to the bookmark list with this note
    """
    s = _s()
    va = _at(at)
    done: dict = {"va": _hex(va)}
    if name:
        s.db.set_name(va, name, "user")
        done["name"] = name
    if comment is not None:
        s.db.set_comment(va, comment, "line")
        done["comment"] = comment
    if pre_comment is not None:
        s.db.set_comment(va, pre_comment, "pre")
        done["pre_comment"] = pre_comment
    if prototype:
        f = s.func_of(va)
        if f is None:
            raise ValueError(f"{_hex(va)} is not a recovered function")
        s.db.con.execute("UPDATE functions SET prototype=? WHERE va=?",
                         (prototype, f["va"]))
        done["prototype"] = prototype
    if bookmark is not None:
        import time
        s.db.con.execute(
            "INSERT OR REPLACE INTO bookmarks VALUES (?,?,?)",
            (va, bookmark, int(time.time())))
        done["bookmark"] = bookmark
    s.db.commit()
    if len(done) == 1:
        raise ValueError("nothing to do: pass at least one of name, comment, "
                         "pre_comment, prototype, bookmark")
    return done


@tool()
def note(topic: str, body: str) -> dict:
    """Keep a free-form finding in the project, keyed by topic. Use it for the
    conclusions that do not belong at a single address: the protocol you worked
    out, the key derivation, what still needs checking."""
    import time
    s = _s()
    s.db.con.execute("INSERT OR REPLACE INTO notes VALUES (?,?,?)",
                     (topic, body, int(time.time())))
    s.db.commit()
    return {"topic": topic, "saved": True}


@tool()
def make_function(at: str) -> dict:
    """Force function recovery at an address that analysis did not reach.
    Useful for obfuscated entry points and hand-written code."""
    s = _s()
    va = _at(at)
    if not s.img.is_exec(va):
        raise ValueError(f"{_hex(va)} is not in an executable section")
    from .analysis import Analyzer
    az = Analyzer(s.img, s.db, s.lr, log=s.log)
    az._seed_symbols()
    az._find_import_thunks()
    az._collect_seeds()
    az._descend([va])
    az._build_xrefs()
    az._persist()
    f = s.db.func_at(va)
    return {"created": f is not None, "va": _hex(va),
            "size": f["size"] if f else 0,
            "blocks": f["nblocks"] if f else 0,
            "note": "re-ran recovery from this address; existing names kept"}


# ========================================================== emulation ===
@tool()
def emulate(at: str, args: Optional[list] = None, max_insn: int = 200000,
            cc: Optional[str] = None, api_returns: Optional[dict] = None,
            trace: bool = False, stop_at: Optional[str] = None,
            capture: Optional[list[list[int]]] = None) -> dict:
    """Actually run a function in an emulator and report what it did.

    Each arg may be a number (passed as-is), a string (copied into scratch
    memory as a nul-terminated buffer, pointer passed), or {"alloc": n} for an
    output buffer of n zero bytes. Allocated buffers come back decoded in the
    result, which is how you read out a decrypted string.

    Imported functions are not executed: each call is logged with its arguments
    and returns 0, or whatever you set in api_returns {"ApiName": value}.

    cc overrides the calling convention (ms64 | sysv64); it is only a guess for
    raw blobs. capture is a list of [address, size] pairs to dump afterwards.
    """
    s = _s()
    va = _at(at)
    em = Emulator(s, api_returns=api_returns, trace=trace, cc=cc)
    return em.run_function(
        va, args or [], max_insn=max_insn,
        stop_at=_at(stop_at) if stop_at else None,
        capture=[(a, b) for a, b in (capture or [])])


@tool()
def emulate_batch(at: str, cases: list[dict], cc: Optional[str] = None) -> dict:
    """Run one function over many argument sets, each in a fresh emulator.
    Built for sweeping a string decoder over every encrypted blob it is called
    with. Each case is {"args": [...], "max_insn": n}."""
    s = _s()
    return {"function": s.sym(_at(at)),
            "results": decrypt_strings(s, _at(at), cases, cc=cc)}


# ============================================================ patching ===
@tool()
def assemble(asm: str, at: str = "0") -> dict:
    """Assemble instructions. Assembling at the real address matters because
    relative branches depend on it. Separate instructions with newlines or ';'."""
    s = _s()
    va = _at(at) if at not in ("0", 0) else 0
    p = Patcher(s)
    data = p.assemble(asm, va)
    return {"at": _hex(va), "bytes": data.hex(), "length": len(data),
            "decodes_as": p.disasm_preview(va, data)}


@tool()
def patch(at: str, asm: Optional[str] = None, hex_bytes: Optional[str] = None,
          nop_instructions: int = 0, note: str = "",
          max_instructions: int = 1) -> dict:
    """Stage a patch. Nothing reaches disk until patch_control(action="write").

    Give exactly one of: asm (assembled at `at` so relative branches are right,
    padded with nops to the next instruction boundary), hex_bytes (raw bytes,
    checked only for staying inside the section), or nop_instructions (nop out
    that many whole instructions).

    An asm patch that would overwrite more than max_instructions instructions
    is refused and tells you what it would have clobbered; raise the limit to
    confirm you mean it.
    """
    s = _s()
    va = _at(at)
    p = Patcher(s)
    given = sum(x is not None and x != "" and x != 0
                for x in (asm, hex_bytes, nop_instructions or None))
    if given != 1:
        raise ValueError("pass exactly one of asm, hex_bytes, nop_instructions")
    if asm:
        return p.stage_asm(va, asm, note, max_instructions=max_instructions)
    if hex_bytes:
        data = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", ""))
        return p.stage(va, data, note)
    return p.nop_out(va, nop_instructions, note)


@tool()
def patch_control(action: str, at: Optional[str] = None,
                  path: Optional[str] = None,
                  overwrite: bool = False) -> dict:
    """action: list | revert (needs at) | revert_all | write (needs path).
    write produces a new file; the analysed binary is never modified."""
    s = _s()
    p = Patcher(s)
    if action == "list":
        return {"patches": p.list_patches()}
    if action == "revert":
        if not at:
            raise ValueError("revert needs at")
        return p.revert(_at(at))
    if action == "revert_all":
        return p.revert_all()
    if action == "write":
        if not path:
            raise ValueError("write needs path")
        return p.write_file(path, overwrite=overwrite)
    raise ValueError(f"unknown action {action!r}")


# =========================================================== debugging ===
@tool()
def dbg_start(path: Optional[str] = None, pid: Optional[int] = None,
              args: str = "", cwd: Optional[str] = None) -> dict:
    """Launch a process under the debugger, or attach to a running pid.
    Launching stops at the initial loader breakpoint. x64 targets only."""
    d = _dbg()
    if pid is not None:
        return d.attach(pid)
    if not path:
        raise ValueError("pass path to launch, or pid to attach")
    return d.launch(path, args=args, cwd=cwd)


@tool()
def dbg_control(action: str, at: Optional[str] = None,
                timeout: float = 15.0) -> dict:
    """action: cont | step | step_over | run_to (needs at) | interrupt.

    step_over only recognises real call opcodes; on anything else it behaves
    like step. If a call never returns to the temporary breakpoint you get
    status=running with reason=timeout, and the target keeps running.
    """
    d = _live()
    if action == "cont":
        return d.cont(timeout=timeout)
    if action == "step":
        return d.step(timeout=timeout)
    if action == "step_over":
        return d.step_over(timeout=timeout)
    if action == "run_to":
        if not at:
            raise ValueError("run_to needs at")
        return d.run_to(_resolve_live(at), timeout=timeout)
    if action == "interrupt":
        return d.interrupt()
    raise ValueError(f"unknown action {action!r}")


def _resolve_live(at) -> int:
    """Addresses for the debugger: a number, or a static symbol when a project
    is open and the module is mapped at its preferred base."""
    try:
        return int(str(at), 0)
    except ValueError:
        pass
    if SESS.open:
        return SESS.resolve(at)
    raise ValueError(f"cannot resolve {at!r}; open_binary first or pass a number")


@tool()
def dbg_bp(action: str = "list", at: Optional[str] = None,
           hardware: bool = False, size: int = 1, kind: str = "w") -> dict:
    """action: set | del | list.
    hardware=True uses a debug register, which is how you watch for a write to
    an address (kind: x execute, w write, rw read/write; size 1,2,4,8 and the
    address must be aligned to size). Only four hardware breakpoints exist, and
    they are applied to threads created later as well."""
    d = _live()
    if action == "list":
        return {"software": d.list_bps(), "hardware": d.list_hw_bps()}
    if not at:
        raise ValueError(f"{action} needs at")
    va = _resolve_live(at)
    if action == "set":
        return d.set_hw_bp(va, size=size, kind=kind) if hardware \
            else d.set_bp(va)
    if action == "del":
        return d.del_hw_bp(va) if hardware else d.del_bp(va)
    raise ValueError(f"unknown action {action!r}")


@tool()
def dbg_inspect(what: str = "state", count: int = 16,
                limit: int = 60) -> dict:
    """what: state | regs | stack | backtrace | threads | modules | memmap |
    events. Numeric fields come with _hex companions and resolved symbols."""
    d = _live()
    if what == "state":
        return d.state()
    if what == "regs":
        return d.regs()
    if what == "stack":
        return {"stack": d.stack(count=count)}
    if what == "backtrace":
        return {"frames": d.backtrace(max_frames=count)}
    if what == "threads":
        return {"threads": d.threads()}
    if what == "modules":
        return {"modules": d.modules()}
    if what == "memmap":
        mm = d.memmap()
        return {"total": len(mm), "regions": mm[:limit]}
    if what == "events":
        return {"events": d.events(limit=limit)}
    raise ValueError(f"unknown what {what!r}")


@tool()
def dbg_mem(action: str, at: str, size: int = 64,
            hex_bytes: Optional[str] = None) -> dict:
    """Read or write live process memory. action: read | write.
    Writing to a read-only page is handled by changing protection and restoring
    it. Reads mask out any breakpoint bytes so you see the real instructions."""
    d = _live()
    va = _resolve_live(at)
    if action == "read":
        data = d.read(va, size)
        return {"at": _hex(va), "size": len(data), "hex": data.hex(),
                "ascii": "".join(chr(c) if 32 <= c < 127 else "."
                                 for c in data)}
    if action == "write":
        if not hex_bytes:
            raise ValueError("write needs hex_bytes")
        data = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", ""))
        d.write(va, data)
        return {"at": _hex(va), "written": len(data)}
    raise ValueError(f"unknown action {action!r}")


@tool()
def dbg_disasm(at: Optional[str] = None, count: int = 16) -> str:
    """Disassemble live process memory, defaulting to the current RIP. This
    reads the real bytes from the running process, so it reflects anything the
    target unpacked or self-modified."""
    d = _live()
    s = d.state()
    va = _resolve_live(at) if at else s["rip"]
    data = d.read(va, min(count * 15 + 16, 4096))
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = False
    out = []
    rip = s.get("rip")
    for i, ins in enumerate(md.disasm(data, va)):
        if i >= count:
            break
        mark = "->" if ins.address == rip else "  "
        out.append(f"{mark} {ins.address:x}  {ins.mnemonic:<8} {ins.op_str}")
    return "\n".join(out) or f"; nothing decodable at {_hex(va)}"


@tool()
def dbg_exception_policy(code: str = "all", action: str = "stop") -> dict:
    """How to handle an exception in the target. code is "all" or a hex status
    such as 0xc0000005. action: stop (report it), ignore (pass it to the
    target's own handler), swallow (pretend it was handled, which will loop
    forever on a faulting instruction)."""
    d = _live()
    c = code if code == "all" else int(code, 0)
    return d.set_exception_policy(c, action)


@tool()
def dbg_stop(terminate: bool = False) -> dict:
    """Detach from the target, optionally terminating it. Detaching restores
    every patched breakpoint byte first."""
    global _DBG
    d = _live()
    try:
        if terminate:
            res = d.detach(terminate=True)
        else:
            res = d.detach()
    finally:
        _DBG = None
    return res


# =============================================================== entry ===
def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
