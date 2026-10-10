"""Loader, analysis, rendering and lifting, checked against real binaries."""
import json
import re

import pytest

from conftest import needs_kernel32, needs_notepad


# ----------------------------------------------------------- loader ----
@needs_notepad
def test_loader_maps_image_correctly(notepad_session):
    s = notepad_session
    m = s.img.meta
    assert m["format"] == "pe"
    assert m["arch"] == "x86_64"
    assert m["image_base"] == 0x140000000
    assert s.img.entry > s.img.base
    # headers plus the usual sections, with permissions parsed
    text = s.img.section_by_name(".text")
    assert text is not None and text.exec and not text.write
    rdata = s.img.section_by_name(".rdata")
    assert rdata is not None and not rdata.exec
    # a read at the entry point must land on real instructions
    assert s.img.read(s.img.entry, 4) != b"\x00\x00\x00\x00"
    # va <-> file offset round-trips inside a mapped section
    off = s.img.va_to_off(s.img.entry)
    assert off is not None and s.img.off_to_va(off) == s.img.entry


@needs_notepad
def test_loader_extracts_pe_metadata(notepad_session):
    m = notepad_session.img.meta
    assert len(m["sha256"]) == 64
    assert m["subsystem"] == "windows_gui"
    assert m["is_dll"] is False
    assert m["is_efi"] is False
    assert "nx_compat" in m["dll_characteristics"]
    assert m["pdb"] == ["notepad.pdb"]


# --------------------------------------------------------- analysis ----
@needs_notepad
def test_function_recovery(notepad_session):
    s = notepad_session
    st = s.db.get_meta("analysis")
    assert st["functions"] > 300
    assert st["instructions"] > 20000
    # .pdata should be the dominant source on an x64 PE
    srcs = dict(s.db.con.execute(
        "SELECT source, COUNT(*) FROM functions GROUP BY source").fetchall())
    assert srcs.get("pdata", 0) > 200
    assert srcs.get("entry", 0) == 1


@needs_notepad
def test_pdata_end_does_not_swallow_following_functions(notepad_session):
    """A .pdata record can span many functions; bodies must stop at the next
    authoritative start instead of absorbing it."""
    s = notepad_session
    rows = s.db.con.execute(
        "SELECT va, end FROM functions ORDER BY va").fetchall()
    starts = {r["va"] for r in rows}
    swallowed = [r["va"] for r in rows
                 if any(r["va"] < o < r["end"] for o in starts)]
    assert not swallowed, f"functions contain other function starts: {swallowed[:5]}"


@needs_notepad
def test_import_thunks_are_named(notepad_session):
    s = notepad_session
    row = s.db.con.execute(
        "SELECT thunk, name FROM imports WHERE thunk IS NOT NULL LIMIT 1"
    ).fetchone()
    assert row is not None, "no import thunks recognised"
    assert s.db.get_name(row["thunk"]) == row["name"]
    # the IAT slot itself keeps the __imp_ prefix
    slot = s.db.con.execute(
        "SELECT va, name FROM imports WHERE thunk IS NOT NULL LIMIT 1").fetchone()
    assert s.db.get_name(slot["va"]) == f"__imp_{slot['name']}"


@needs_kernel32
def test_jump_tables_resolve(kernel32_session):
    """MSVC emits switch tables into .text with int32 deltas from __ImageBase;
    rejecting executable table addresses loses every switch."""
    s = kernel32_session
    rows = s.db.con.execute(
        "SELECT va, count, targets FROM jumptables").fetchall()
    assert rows, "no jump tables resolved in kernel32"
    for r in rows:
        tg = json.loads(r["targets"])
        assert len(tg) >= 2
        assert all(s.img.is_exec(t) for t in tg)


@needs_notepad
def test_xrefs_are_bidirectional(notepad_session):
    s = notepad_session
    row = s.db.con.execute(
        "SELECT frm, dst FROM xrefs WHERE kind='call' LIMIT 1").fetchone()
    assert any(x["frm"] == row["frm"] for x in s.xrefs_to(row["dst"]))
    assert any(x["dst"] == row["dst"] for x in s.xrefs_from(row["frm"]))


# ---------------------------------------------------------- strings ----
@needs_notepad
def test_strings_exclude_code(notepad_session):
    """Instruction bytes match a printable-run regex (`40 55 53 56 57` reads as
    '@USVW'), so code must not be scanned for strings by default."""
    s = notepad_session
    text = s.img.section_by_name(".text")
    inside = s.db.con.execute(
        "SELECT COUNT(*) c FROM strings WHERE va >= ? AND va < ?",
        (text.va, text.end)).fetchone()["c"]
    assert inside == 0
    assert s.db.con.execute(
        "SELECT COUNT(*) c FROM strings").fetchone()["c"] > 500


@needs_notepad
def test_no_code_address_is_named_after_a_string(notepad_session):
    s = notepad_session
    for r in s.db.con.execute(
            "SELECT va, name FROM names WHERE source='string_ref'"):
        assert s.db.func_containing(r["va"]) is None, (
            f"{r['name']} at {r['va']:x} is inside a function")


# ------------------------------------------------------- resolution ----
@needs_notepad
def test_address_resolution_forms(notepad_session):
    s = notepad_session
    assert s.resolve("0x140001000") == 0x140001000
    assert s.resolve(0x140001000) == 0x140001000
    assert s.resolve(".text") == s.img.section_by_name(".text").va
    assert s.resolve(".text+0x10") == s.img.section_by_name(".text").va + 0x10
    name = s.db.con.execute(
        "SELECT name FROM names WHERE source='import' LIMIT 1").fetchone()["name"]
    assert s.resolve(name) == s.db.resolve_name(name)
    with pytest.raises(ValueError):
        s.resolve("definitely_not_a_symbol")


# -------------------------------------------------------- rendering ----
@needs_notepad
def test_rendering_annotates(notepad_session):
    from reva.render import Renderer
    s = notepad_session
    r = Renderer(s)
    # find a function that calls an import, and check the name appears
    for row in s.db.con.execute(
            "SELECT va, fingerprint FROM functions WHERE ninsn BETWEEN 8 AND 80"):
        fp = json.loads(row["fingerprint"])
        if not fp.get("callees"):
            continue
        txt = r.function(row["va"])
        callee = fp["callees"][0]
        if callee in txt:
            # a raw address must not be left where a symbol was available
            assert "; ====" in txt
            assert re.search(r"\b(call|jmp)\s+\S", txt)
            break
    else:
        pytest.fail("no function with resolvable callees found")


@needs_notepad
def test_stack_operands_get_names(notepad_session):
    """Capstone prints small displacements in decimal and large ones in hex;
    both have to be rewritten or half the stack slots stay raw."""
    from reva.render import Renderer
    s = notepad_session
    r = Renderer(s)
    seen = set()
    for row in s.db.con.execute("SELECT va FROM functions LIMIT 120"):
        for m in re.finditer(r"\[(sv|var|arg)_[0-9a-f]+\]",
                             r.function(row["va"])):
            seen.add(m.group(0))
        if len(seen) > 5:
            break
    assert len(seen) > 5, f"stack slots not named: {seen}"
    # and nothing should still look like a raw rsp displacement
    txt = "\n".join(r.function(row["va"])
                    for row in s.db.con.execute(
                        "SELECT va FROM functions LIMIT 40"))
    assert not re.search(r"\[rsp \+ (0x[0-9a-f]+|\d+)\]", txt)


# ----------------------------------------------------------- lifter ----
@needs_notepad
def test_lifter_handles_every_function(notepad_session):
    from reva.lifter import Lifter
    s = notepad_session
    L = Lifter(s)
    total = asm_lines = 0
    failures = []
    for row in s.db.con.execute("SELECT va FROM functions ORDER BY va"):
        try:
            txt = L.decompile(row["va"], max_blocks=400)
        except Exception as e:
            failures.append((row["va"], f"{type(e).__name__}: {e}"))
            continue
        for ln in txt.splitlines():
            total += 1
            if "__asm(" in ln:
                asm_lines += 1
    assert not failures, f"lifter failed on {len(failures)}: {failures[:3]}"
    assert asm_lines / total < 0.02, (
        f"{asm_lines}/{total} lines fell back to __asm")


@needs_notepad
def test_lifter_terminates_on_a_huge_function(notepad_session):
    """Expression trees are DAGs: `x = x + x` doubles the tree each time, so
    without a cost budget rendering never finishes."""
    import time
    from reva.lifter import Lifter
    s = notepad_session
    row = s.db.con.execute(
        "SELECT va, ninsn FROM functions ORDER BY ninsn DESC LIMIT 1").fetchone()
    assert row["ninsn"] > 2000, "expected a large function to stress"
    t0 = time.time()
    txt = Lifter(s).decompile(row["va"], max_blocks=400)
    assert time.time() - t0 < 30
    assert len(max(txt.splitlines(), key=len)) < 4000


@needs_notepad
def test_lifter_emits_no_dangling_goto(notepad_session):
    from reva.lifter import Lifter
    s = notepad_session
    L = Lifter(s)
    for row in s.db.con.execute("SELECT va FROM functions LIMIT 200"):
        txt = L.decompile(row["va"], max_blocks=400)
        targets = set(re.findall(r"goto (LAB_[0-9a-f]+);", txt))
        labels = set(re.findall(r"^\s*(LAB_[0-9a-f]+):", txt, re.M))
        missing = targets - labels
        assert not missing, f"0x{row['va']:x} jumps to absent labels: {missing}"


@needs_notepad
def test_lifter_recovers_call_arguments(notepad_session):
    from reva.lifter import Lifter
    s = notepad_session
    L = Lifter(s)
    found = False
    for row in s.db.con.execute(
            "SELECT va, fingerprint FROM functions WHERE ninsn BETWEEN 20 AND 200"):
        txt = L.decompile(row["va"])
        if re.search(r"\w+\([^)]*,[^)]*\);", txt):
            found = True
            break
    assert found, "no call rendered with multiple arguments"
