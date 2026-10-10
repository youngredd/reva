import os
import sys

import pytest

WINDOWS = sys.platform == "win32"
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
NOTEPAD = os.path.join(SYSTEM32, "notepad.exe")
KERNEL32 = os.path.join(SYSTEM32, "kernel32.dll")
CMD = os.path.join(SYSTEM32, "cmd.exe")

needs_windows = pytest.mark.skipif(not WINDOWS, reason="needs Windows")


def _have(p):
    return os.path.isfile(p)


needs_notepad = pytest.mark.skipif(
    not _have(NOTEPAD), reason="needs a stock notepad.exe to analyse")
needs_kernel32 = pytest.mark.skipif(
    not _have(KERNEL32), reason="needs a stock kernel32.dll to analyse")
needs_cmd = pytest.mark.skipif(
    not _have(CMD), reason="needs cmd.exe as a debug target")


@pytest.fixture(scope="session", autouse=True)
def isolated_project_store(tmp_path_factory):
    """Keep test analysis out of the user's real project store."""
    d = tmp_path_factory.mktemp("reva-projects")
    os.environ["REVA_PROJECT_DIR"] = str(d)
    yield str(d)
    os.environ.pop("REVA_PROJECT_DIR", None)


@pytest.fixture(scope="session")
def notepad_session(isolated_project_store):
    from reva.session import Session
    s = Session()
    s.open_binary(NOTEPAD)
    yield s
    s.close()


@pytest.fixture(scope="session")
def kernel32_session(isolated_project_store):
    from reva.session import Session
    s = Session()
    s.open_binary(KERNEL32)
    yield s
    s.close()


@pytest.fixture
def xor_decoder_blob(tmp_path, isolated_project_store):
    """A tiny hand-assembled x64 xor decoder, so emulation has an oracle.

    rcx = buffer, rdx = length, r8 = key; decodes in place and returns length.
    """
    ks = pytest.importorskip("keystone")
    src = """
        xor r9, r9
    loop:
        cmp r9, rdx
        jge done
        mov al, byte ptr [rcx + r9]
        xor al, r8b
        mov byte ptr [rcx + r9], al
        inc r9
        jmp loop
    done:
        mov rax, rdx
        ret
    """
    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_64)
    code, _ = eng.asm(src, 0x10000)
    p = tmp_path / "xor_decoder.bin"
    p.write_bytes(bytes(code))
    return str(p)
