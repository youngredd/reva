"""Emulation, patching, search and the live debugger."""
import os
import struct
import sys

import pytest

from conftest import needs_cmd, needs_notepad, needs_windows

SECRET = b"ReverseEngineering!"
KEY = 0x5A


# ------------------------------------------------------- emulation ----
def test_emulation_decodes_for_real(xor_decoder_blob):
    """The oracle: a hand-assembled xor decoder must produce the plaintext."""
    from reva.emu import Emulator
    from reva.session import Session

    s = Session()
    s.open_binary(xor_decoder_blob, arch="x86_64", base=0x10000)
    try:
        enc = bytes(c ^ KEY for c in SECRET)
        em = Emulator(s, cc="ms64")
        r = em.run_function(0x10000, [enc, len(enc), KEY], max_insn=100_000)
        assert r["error"] is None
        assert r["stopped"] == "returned"
        assert int(r["return_value"], 16) == len(enc)
        assert any(b["ascii"].startswith(SECRET.decode())
                   for b in r["buffers"])
        assert any(w["ascii"].startswith(SECRET.decode())
                   for w in r["memory_writes"])
    finally:
        s.close()


def test_emulation_reports_faults_instead_of_hiding_them(xor_decoder_blob):
    from reva.emu import Emulator
    from reva.session import Session

    s = Session()
    s.open_binary(xor_decoder_blob, arch="x86_64", base=0x10000)
    try:
        em = Emulator(s, cc="ms64")
        r = em.run_function(0x10000, [1, 16, KEY], max_insn=10_000)
        assert r["stopped"] == "fault"
        assert r["error"] and "UNMAPPED" in r["error"].upper()
        assert "fault_rip" in r
    finally:
        s.close()


def test_calling_convention_is_explicit(xor_decoder_blob):
    """A raw blob carries no convention, so the wrong guess must be visible
    rather than silently producing nonsense."""
    from reva.emu import Emulator
    from reva.session import Session

    s = Session()
    s.open_binary(xor_decoder_blob, arch="x86_64", base=0x10000)
    try:
        enc = bytes(c ^ KEY for c in SECRET)
        ok = Emulator(s, cc="ms64").run_function(
            0x10000, [enc, len(enc), KEY], max_insn=100_000)
        bad = Emulator(s, cc="sysv64").run_function(
            0x10000, [enc, len(enc), KEY], max_insn=100_000)
        assert ok["error"] is None
        assert bad["stopped"] == "fault"
    finally:
        s.close()


@needs_notepad
def test_emulation_intercepts_imports(notepad_session):
    """Imported functions must be logged with their arguments, not executed."""
    import json

    from reva.emu import Emulator
    s = notepad_session
    for row in s.db.con.execute(
            "SELECT va, fingerprint FROM functions WHERE ninsn BETWEEN 5 AND 60"):
        fp = json.loads(row["fingerprint"])
        if fp.get("ncallees", 0) < 1:
            continue
        r = Emulator(s).run_function(row["va"], [0, 0], max_insn=50_000)
        if r["api_calls"]:
            c = r["api_calls"][0]
            assert "!" in c["api"] or c["api"]
            assert c["returned"] == "0x0"
            return
    pytest.skip("no small function reached an import under emulation")


@needs_notepad
def test_api_returns_are_controllable(notepad_session):
    import json

    from reva.emu import Emulator
    s = notepad_session
    for row in s.db.con.execute(
            "SELECT va, fingerprint FROM functions WHERE ninsn BETWEEN 5 AND 60"):
        fp = json.loads(row["fingerprint"])
        if not fp.get("callees"):
            continue
        name = fp["callees"][0].split("!")[-1]
        r = Emulator(s, api_returns={name: 0x1234}).run_function(
            row["va"], [0, 0], max_insn=50_000)
        hit = [c for c in r["api_calls"] if c["api"].endswith(name)]
        if hit:
            assert hit[0]["returned"] == "0x1234"
            return
    pytest.skip("no controllable api call reached")


# --------------------------------------------------------- patching ----
@pytest.fixture
def clean_patches(notepad_session):
    """Patch tests mutate the shared in-memory image, so undo either way."""
    from reva.patcher import Patcher
    Patcher(notepad_session).revert_all()
    yield
    Patcher(notepad_session).revert_all()


@needs_notepad
def test_patch_is_staged_and_revertible(notepad_session, clean_patches):
    from reva.patcher import Patcher
    s = notepad_session
    p = Patcher(s)
    va = s.img.entry
    before = s.img.read(va, 8)
    res = p.stage_asm(va, "xor eax, eax", note="test")
    assert res["original"] == before.hex()[:len(res["original"])]
    assert "xor eax, eax" in " ".join(res["decodes_as"])
    assert len(p.list_patches()) == 1
    # the in-memory image reflects it immediately
    assert s.img.read(va, 2) == b"\x31\xc0"
    p.revert_all()
    assert p.list_patches() == []
    assert s.img.read(va, 8) == before


@needs_notepad
def test_patch_refuses_to_overrun_following_instructions(notepad_session,
                                                         clean_patches):
    """Silently eating the next instruction is how a patch becomes a crash
    somewhere unrelated, so it has to be opted into."""
    from reva.patcher import Patcher, PatchError
    s = notepad_session
    p = Patcher(s)
    long_asm = ("mov rax, 0x1122334455667788; mov rbx, rax; "
                "mov rcx, rax; mov rdx, rax; mov rsi, rax")
    with pytest.raises(PatchError, match="would overwrite"):
        p.stage_asm(s.img.entry, long_asm)
    assert p.list_patches() == []
    # and it tells you the number that would make it go through
    try:
        p.stage_asm(s.img.entry, long_asm)
    except PatchError as e:
        n = int(str(e).split("max_instructions=")[1].split(" ")[0].rstrip(","))
    res = p.stage_asm(s.img.entry, long_asm, max_instructions=n)
    assert res["instructions_replaced"] == n


@needs_notepad
def test_patched_file_is_written_elsewhere(notepad_session, clean_patches,
                                           tmp_path):
    from reva.patcher import Patcher, PatchError
    s = notepad_session
    p = Patcher(s)
    p.stage_asm(s.img.entry, "xor eax, eax", note="t")
    out = tmp_path / "patched.exe"
    r = p.write_file(str(out))
    assert out.exists()
    assert os.path.getsize(out) == os.path.getsize(s.path)
    assert r["patches_applied"]
    # the patched bytes really are in the output, and only there
    off = s.img.va_to_off(s.img.entry)
    assert out.read_bytes()[off:off + 2] == b"\x31\xc0"
    with open(s.path, "rb") as f:
        f.seek(off)
        assert f.read(2) != b"\x31\xc0"
    with pytest.raises(PatchError, match="refusing to overwrite"):
        p.write_file(s.path)


# ----------------------------------------------------------- search ----
@needs_notepad
def test_byte_pattern_with_wildcards(notepad_session):
    from reva.search import Search
    s = notepad_session
    se = Search(s)
    # the limit has to be high enough that neither result set is truncated,
    # or the subset check compares two different prefixes
    exact = se.bytes_pattern("48 89 5c 24", limit=5000)
    wild = se.bytes_pattern("48 89 ?? 24", limit=5000)
    assert exact and len(wild) > len(exact)
    assert {h["va"] for h in exact} <= {h["va"] for h in wild}
    assert all(s.img.read(int(h["va"], 16), 1) == b"\x48" for h in wild[:50])


@needs_notepad
def test_behavior_search_ordering(notepad_session):
    from reva.search import Search
    s = notepad_session
    se = Search(s)
    loose = se.behavior(["memset"], mode="any", limit=200)
    assert loose
    # an impossible ordering must return nothing rather than everything
    strict = se.behavior(["memset", "zzz_no_such_api"], mode="all", limit=50)
    assert strict == []


@needs_notepad
def test_similarity_finds_itself_excluded(notepad_session):
    from reva.search import Search
    s = notepad_session
    row = s.db.con.execute(
        "SELECT va FROM functions WHERE ninsn > 40 LIMIT 1").fetchone()
    hits = Search(s).similar(row["va"], limit=10)
    assert all(int(h["va"], 16) != row["va"] for h in hits)


# ---------------------------------------------------------- triage ----
@needs_notepad
def test_triage_report_shape(notepad_session):
    from reva.triage import Triage
    r = Triage(notepad_session).report(top_functions=5)
    assert r["identity"]["arch"] == "x86_64"
    assert r["identity"]["kind"] == "EXE"
    assert r["coverage"]["coverage_pct"] > 50
    assert len(r["start_here"]) == 5
    assert r["start_here"][0]["score"] >= r["start_here"][-1]["score"]
    assert "capabilities" in r["imports"]
    assert any(s["name"] == ".text" for s in r["sections"])


# -------------------------------------------------------- debugger ----
@needs_windows
@needs_cmd
def test_debugger_core():
    """One session covering the parts that are easy to get wrong: breakpoint
    re-arming, stepping, and writing to a read-only page."""
    from conftest import CMD
    from reva.debug import Debugger

    d = Debugger()
    st = d.launch(CMD, args="/c ping -n 20 127.0.0.1 >nul")
    try:
        assert st["status"] == "stopped"
        assert st["reason"] == "initial_breakpoint"
        assert st["wow64"] is False
        assert st["rip_module"] == "ntdll.dll"

        r = d.regs()
        assert r["context_aligned_16"] is True
        assert r["context_size"] == 1232

        mods = {m["name"].lower(): m for m in d.modules() if m.get("name")}
        assert "ntdll.dll" in mods
        nt = mods["ntdll.dll"]["base"]

        mm = d.memmap()
        here = [m for m in mm if m["base"] <= r["rip"] < m["base"] + m["size"]]
        assert here and here[0]["executable"]

        # resolve an export out of the mapped image, then prove the 0xCC
        # breakpoint is correctly re-armed by hitting it repeatedly
        target = _export(d, nt, "NtAllocateVirtualMemory")
        assert target
        d.set_bp(target)
        hits = 0
        for _ in range(4):
            s2 = d.cont(timeout=25)
            if s2.get("reason") == "breakpoint" and s2["rip"] == target:
                hits += 1
            else:
                break
        assert hits >= 3, f"breakpoint re-arm failed after {hits} hits"
        d.del_bp(target)

        rips = [d.regs()["rip"]]
        for _ in range(3):
            d.step(timeout=10)
            rips.append(d.regs()["rip"])
        assert all(b != a for a, b in zip(rips, rips[1:]))

        sp = d.regs()["rsp"]
        d.write(sp - 0x200, b"REVA-RW")
        assert d.read(sp - 0x200, 7) == b"REVA-RW"

        ro = nt + 0x2                      # inside the read-only PE header
        orig = d.read(ro, 8)
        d.write(ro, b"PATCHED!")
        assert d.read(ro, 8) == b"PATCHED!"
        d.write(ro, orig)
        assert d.read(ro, 8) == orig

        d.set_hw_bp(sp - 0x100, size=4, kind="w")
        assert d.regs()["dr"]["dr0"] == sp - 0x100
        assert d.regs()["dr"]["dr7"] != 0
        d.del_hw_bp(sp - 0x100)
        assert d.regs()["dr"]["dr7"] == 0

        assert d.backtrace()
        assert d.events(limit=50)
    finally:
        d.detach(terminate=True)


def _export(d, base, want):
    def u32(a):
        return struct.unpack("<I", d.read(a, 4))[0]

    def u16(a):
        return struct.unpack("<H", d.read(a, 2))[0]

    opt = base + u32(base + 0x3C) + 0x18
    exp = base + u32(opt + 0x70)
    nnames = u32(exp + 0x18)
    afun, anam, aord = (base + u32(exp + 0x1C), base + u32(exp + 0x20),
                        base + u32(exp + 0x24))
    for i in range(nnames):
        nm = d.read(base + u32(anam + 4 * i), 64).split(b"\x00")[0]
        if nm.decode("latin1") == want:
            return base + u32(afun + 4 * u16(aord + 2 * i))
    return None
