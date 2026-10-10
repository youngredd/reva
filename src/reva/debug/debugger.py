"""Self-contained Windows x64 user-mode debugger built on pure ``ctypes``.

This module deliberately has **no** dependency on any other project module and no
third-party dependency.  Everything (structures, prototypes, PE/PEB parsing,
instruction-length guessing) is implemented locally.

Threading model
---------------
The Win32 debug API is *thread affine*: ``WaitForDebugEvent`` and
``ContinueDebugEvent`` must be issued from the very thread that called
``CreateProcess(DEBUG_ONLY_THIS_PROCESS)`` or ``DebugActiveProcess``.  Because
this class is meant to be driven from an async server making discrete blocking
calls from arbitrary threads, *all* Win32 work happens on one dedicated worker
thread (``_worker_main``).  Public methods merely push a ``(name, args, kwargs,
reply_queue)`` tuple onto a command ``queue.Queue`` and block on the reply queue
until the worker answers or the timeout expires.  Every ``_w_*`` method in this
file runs on, and only on, that worker thread.

Scope
-----
x64 debuggee on x64 Windows only.  WOW64 / 32-bit debuggees are **not
supported**: ``Wow64GetThreadContext`` and the 32-bit ``CONTEXT`` layout are not
implemented, and ``attach``/``launch`` will report the target as ``wow64`` when
detected so a caller can refuse it.
"""

from __future__ import annotations

import collections
import ctypes
import ctypes.wintypes as wt
import os
import queue
import struct
import threading
import time

__all__ = ["Debugger", "DebugError"]


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class DebugError(Exception):
    """Any failure raised by this module.

    ``winerror`` holds the Win32 error code when the failure came from a Win32
    call, otherwise ``None``.
    """

    def __init__(self, message, winerror=None):
        super().__init__(message)
        self.winerror = winerror


# ---------------------------------------------------------------------------
# raw Win32 bindings
# ---------------------------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

LPVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
ULONG_PTR = ctypes.c_ulonglong
DWORD64 = ctypes.c_ulonglong
NTSTATUS = ctypes.c_long

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010
CREATE_UNICODE_ENVIRONMENT = 0x00000400

# debug event codes
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EVENT_NAMES = {
    EXCEPTION_DEBUG_EVENT: "exception",
    CREATE_THREAD_DEBUG_EVENT: "create_thread",
    CREATE_PROCESS_DEBUG_EVENT: "create_process",
    EXIT_THREAD_DEBUG_EVENT: "exit_thread",
    EXIT_PROCESS_DEBUG_EVENT: "exit_process",
    LOAD_DLL_DEBUG_EVENT: "load_dll",
    UNLOAD_DLL_DEBUG_EVENT: "unload_dll",
    OUTPUT_DEBUG_STRING_EVENT: "output_debug_string",
    RIP_EVENT: "rip",
}

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

ERROR_SEM_TIMEOUT = 121

# exception codes
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_GUARD_PAGE = 0x80000001
STATUS_WX86_BREAKPOINT = 0x4000001F
STATUS_WX86_SINGLE_STEP = 0x4000001E

EXCEPTION_NAMES = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0x80000003: "EXCEPTION_BREAKPOINT",
    0x80000004: "EXCEPTION_SINGLE_STEP",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
    0xC0000096: "EXCEPTION_PRIV_INSTRUCTION",
    0x80000001: "EXCEPTION_GUARD_PAGE",
    0xE06D7363: "CPP_EH_EXCEPTION",
    0xE0434352: "CLR_EXCEPTION",
    # extras, handy in practice
    0xC0000006: "EXCEPTION_IN_PAGE_ERROR",
    0xC0000008: "EXCEPTION_INVALID_HANDLE",
    0xC000001E: "EXCEPTION_ACCESS_DENIED",
    0xC0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
    0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0xC000008E: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    0xC0000090: "EXCEPTION_FLT_INVALID_OPERATION",
    0xC0000095: "EXCEPTION_INT_OVERFLOW",
    0xC00000FE: "EXCEPTION_INVALID_DISPOSITION",
    0x4000001F: "STATUS_WX86_BREAKPOINT",
    0x4000001E: "STATUS_WX86_SINGLE_STEP",
    0x406D1388: "MS_VC_THREAD_NAME",
}

# CONTEXT flags (AMD64)
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = (
    CONTEXT_CONTROL
    | CONTEXT_INTEGER
    | CONTEXT_SEGMENTS
    | CONTEXT_FLOATING_POINT
    | CONTEXT_DEBUG_REGISTERS
)  # == 0x0010001F

# EFLAGS
EFLAGS_TF = 0x00000100
EFLAGS_RF = 0x00010000

EFLAGS_BITS = [
    (0, "CF"),
    (2, "PF"),
    (4, "AF"),
    (6, "ZF"),
    (7, "SF"),
    (8, "TF"),
    (9, "IF"),
    (10, "DF"),
    (11, "OF"),
    (14, "NT"),
    (16, "RF"),
    (17, "VM"),
    (18, "AC"),
    (19, "VIF"),
    (20, "VIP"),
    (21, "ID"),
]

# memory
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

_PROTECT_NAMES = {
    PAGE_NOACCESS: "NOACCESS",
    PAGE_READONLY: "R",
    PAGE_READWRITE: "RW",
    PAGE_WRITECOPY: "WC",
    PAGE_EXECUTE: "X",
    PAGE_EXECUTE_READ: "RX",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "XWC",
}
_STATE_NAMES = {MEM_COMMIT: "COMMIT", MEM_RESERVE: "RESERVE", MEM_FREE: "FREE"}
_TYPE_NAMES = {MEM_PRIVATE: "PRIVATE", MEM_MAPPED: "MAPPED", MEM_IMAGE: "IMAGE"}
_EXEC_PROTECTS = (
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
)

THREAD_ALL_ACCESS = 0x1FFFFF
PROCESS_ALL_ACCESS = 0x1FFFFF


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wt.WORD),
        ("StatusWord", wt.WORD),
        ("TagWord", wt.BYTE),
        ("Reserved1", wt.BYTE),
        ("ErrorOpcode", wt.WORD),
        ("ErrorOffset", wt.DWORD),
        ("ErrorSelector", wt.WORD),
        ("Reserved2", wt.WORD),
        ("DataOffset", wt.DWORD),
        ("DataSelector", wt.WORD),
        ("Reserved3", wt.WORD),
        ("MxCsr", wt.DWORD),
        ("MxCsr_Mask", wt.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", wt.BYTE * 96),
    ]


class CONTEXT(ctypes.Structure):
    """AMD64 ``CONTEXT``.

    The real structure is ``DECLSPEC_ALIGN(16)``; ctypes cannot express that on
    3.12, so instances are never created directly -- use
    :func:`_new_context`, which hands back a 16-byte-aligned view.  A
    misaligned CONTEXT makes ``GetThreadContext`` fail with ERROR_NOACCESS
    (998).
    """

    _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", wt.DWORD),
        ("MxCsr", wt.DWORD),
        ("SegCs", wt.WORD),
        ("SegDs", wt.WORD),
        ("SegEs", wt.WORD),
        ("SegFs", wt.WORD),
        ("SegGs", wt.WORD),
        ("SegSs", wt.WORD),
        ("EFlags", wt.DWORD),
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64),
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),
    ]


CONTEXT_SIZE = ctypes.sizeof(CONTEXT)


def _new_context(flags=CONTEXT_ALL):
    """Return a 16-byte aligned :class:`CONTEXT` with ``ContextFlags`` set."""
    buf = (ctypes.c_char * (CONTEXT_SIZE + 16))()
    pad = (-ctypes.addressof(buf)) % 16
    ctx = CONTEXT.from_buffer(buf, pad)  # from_buffer keeps buf alive via _objects
    if ctypes.addressof(ctx) % 16 != 0:  # pragma: no cover - defensive
        raise DebugError("failed to allocate a 16-byte aligned CONTEXT")
    ctx.ContextFlags = flags
    return ctx


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wt.DWORD),
    ("ExceptionFlags", wt.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", LPVOID),
    ("NumberParameters", wt.DWORD),
    ("ExceptionInformation", ULONG_PTR * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wt.DWORD)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wt.HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wt.HANDLE),
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", wt.DWORD),
        ("nDebugInfoSize", wt.DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
        ("lpImageName", LPVOID),
        ("fUnicode", wt.WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wt.DWORD)]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wt.DWORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wt.HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", wt.DWORD),
        ("nDebugInfoSize", wt.DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", wt.WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", LPVOID)]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", LPVOID),
        ("fUnicode", wt.WORD),
        ("nDebugStringLength", wt.WORD),
    ]


class RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", wt.DWORD), ("dwType", wt.DWORD)]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wt.DWORD),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
        ("u", _DEBUG_EVENT_UNION),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("lpReserved", wt.LPWSTR),
        ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),
        ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD),
        ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD),
        ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.POINTER(wt.BYTE)),
        ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationBase", LPVOID),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", SIZE_T),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("_pad0", wt.DWORD),
        ("PebBaseAddress", LPVOID),
        ("AffinityMask", ULONG_PTR),
        ("BasePriority", ctypes.c_long),
        ("_pad1", wt.DWORD),
        ("UniqueProcessId", ULONG_PTR),
        ("InheritedFromUniqueProcessId", ULONG_PTR),
    ]


def _proto(fn, restype, argtypes):
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


CreateProcessW = _proto(
    kernel32.CreateProcessW,
    wt.BOOL,
    [
        wt.LPCWSTR,
        wt.LPWSTR,
        LPVOID,
        LPVOID,
        wt.BOOL,
        wt.DWORD,
        LPVOID,
        wt.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ],
)
DebugActiveProcess = _proto(kernel32.DebugActiveProcess, wt.BOOL, [wt.DWORD])
DebugActiveProcessStop = _proto(kernel32.DebugActiveProcessStop, wt.BOOL, [wt.DWORD])
DebugSetProcessKillOnExit = _proto(
    kernel32.DebugSetProcessKillOnExit, wt.BOOL, [wt.BOOL]
)
DebugBreakProcess = _proto(kernel32.DebugBreakProcess, wt.BOOL, [wt.HANDLE])
WaitForDebugEvent = _proto(
    kernel32.WaitForDebugEvent, wt.BOOL, [ctypes.POINTER(DEBUG_EVENT), wt.DWORD]
)
ContinueDebugEvent = _proto(
    kernel32.ContinueDebugEvent, wt.BOOL, [wt.DWORD, wt.DWORD, wt.DWORD]
)
GetThreadContext = _proto(kernel32.GetThreadContext, wt.BOOL, [wt.HANDLE, LPVOID])
SetThreadContext = _proto(kernel32.SetThreadContext, wt.BOOL, [wt.HANDLE, LPVOID])
ReadProcessMemory = _proto(
    kernel32.ReadProcessMemory,
    wt.BOOL,
    [wt.HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)],
)
WriteProcessMemory = _proto(
    kernel32.WriteProcessMemory,
    wt.BOOL,
    [wt.HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)],
)
VirtualQueryEx = _proto(
    kernel32.VirtualQueryEx,
    SIZE_T,
    [wt.HANDLE, LPVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T],
)
VirtualProtectEx = _proto(
    kernel32.VirtualProtectEx,
    wt.BOOL,
    [wt.HANDLE, LPVOID, SIZE_T, wt.DWORD, ctypes.POINTER(wt.DWORD)],
)
FlushInstructionCache = _proto(
    kernel32.FlushInstructionCache, wt.BOOL, [wt.HANDLE, LPVOID, SIZE_T]
)
CloseHandle = _proto(kernel32.CloseHandle, wt.BOOL, [wt.HANDLE])
SuspendThread = _proto(kernel32.SuspendThread, wt.DWORD, [wt.HANDLE])
ResumeThread = _proto(kernel32.ResumeThread, wt.DWORD, [wt.HANDLE])
TerminateProcess = _proto(kernel32.TerminateProcess, wt.BOOL, [wt.HANDLE, wt.UINT])
OpenProcess = _proto(kernel32.OpenProcess, wt.HANDLE, [wt.DWORD, wt.BOOL, wt.DWORD])
GetExitCodeProcess = _proto(
    kernel32.GetExitCodeProcess, wt.BOOL, [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
)
GetFinalPathNameByHandleW = _proto(
    kernel32.GetFinalPathNameByHandleW,
    wt.DWORD,
    [wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD],
)
IsWow64Process = _proto(
    kernel32.IsWow64Process, wt.BOOL, [wt.HANDLE, ctypes.POINTER(wt.BOOL)]
)
FormatMessageW = _proto(
    kernel32.FormatMessageW,
    wt.DWORD,
    [wt.DWORD, LPVOID, wt.DWORD, wt.DWORD, wt.LPWSTR, wt.DWORD, LPVOID],
)
NtQueryInformationProcess = _proto(
    ntdll.NtQueryInformationProcess,
    NTSTATUS,
    [wt.HANDLE, ctypes.c_ulong, LPVOID, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)],
)


def _win_error_text(code):
    buf = ctypes.create_unicode_buffer(1024)
    n = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        None,
        code,
        0,
        buf,
        len(buf),
        None,
    )
    if not n:
        return "(no description)"
    return buf.value.strip()


def _fail(what, code=None):
    if code is None:
        code = ctypes.get_last_error()
    raise DebugError(f"{what} failed: [{code}] {_win_error_text(code)}", code)


# ---------------------------------------------------------------------------
# tiny helpers
# ---------------------------------------------------------------------------

_PREFIXES = frozenset(
    (0x66, 0x67, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0xF0, 0xF2, 0xF3)
)


def _call_length(code):
    """Return the length of the CALL instruction at ``code[0]`` or ``None``.

    Only ``E8 rel32`` (near relative), ``FF /2`` and ``FF /3`` (indirect
    near/far) and ``9A`` (far absolute, invalid in long mode but accepted) are
    recognised -- everything else, including every form of ``JMP``, is reported
    as "not a call".  No disassembler is used.
    """
    i = 0
    n = len(code)
    while i < n and (code[i] in _PREFIXES or 0x40 <= code[i] <= 0x4F):
        i += 1
    if i >= n:
        return None
    op = code[i]
    i += 1
    if op == 0xE8:
        return i + 4 if i + 4 <= n else None
    if op == 0x9A:
        return i + 6 if i + 6 <= n else None
    if op == 0xFF:
        if i >= n:
            return None
        modrm = code[i]
        i += 1
        reg = (modrm >> 3) & 7
        if reg not in (2, 3):
            return None
        mod = modrm >> 6
        rm = modrm & 7
        if mod == 3:
            return i
        if rm == 4:  # SIB
            if i >= n:
                return None
            sib = code[i]
            i += 1
            base = sib & 7
            if mod == 0 and base == 5:
                i += 4
        elif mod == 0 and rm == 5:
            i += 4  # RIP-relative disp32
        if mod == 1:
            i += 1
        elif mod == 2:
            i += 4
        return i if i <= n else None
    return None


def _decode_eflags(v):
    return [name for bit, name in EFLAGS_BITS if v & (1 << bit)]


def _protect_name(p):
    base = p & 0xFF
    name = _PROTECT_NAMES.get(base, hex(base))
    if p & PAGE_GUARD:
        name += "+GUARD"
    if p & PAGE_NOCACHE:
        name += "+NOCACHE"
    if p & PAGE_WRITECOMBINE:
        name += "+WC"
    return name


# ---------------------------------------------------------------------------
# the debugger
# ---------------------------------------------------------------------------

_HW_RW = {"x": 0, "w": 1, "rw": 3}
_HW_LEN = {1: 0, 2: 1, 4: 3, 8: 2}


class Debugger:
    """A Windows x64 user-mode debugger.

    Every public method is safe to call from any thread; the call is marshalled
    to the single dedicated worker thread that owns the debug session.
    """

    def __init__(self, event_log_size=2000, timeout=30.0):
        self.timeout = float(timeout)
        self._cmd_q = queue.Queue()
        self._worker = None
        self._worker_lock = threading.Lock()
        self._events = collections.deque(maxlen=int(event_log_size))
        self._events_lock = threading.Lock()
        self._event_seq = 0

        # --- worker-owned state (touch only from the worker thread) ---
        self._pid = None
        self._hproc = None
        self._threads = {}  # tid -> dict(handle, teb, entry)
        self._modules = {}  # base -> dict(base, size, path, name)
        self._bps = {}  # addr -> dict
        self._hw_bps = {}  # slot -> dict(addr,size,kind)
        self._rearm = {}  # tid -> addr  (byte removed, must re-arm after 1 step)
        self._user_step = None  # tid the user asked a single step for
        self._pending = None  # un-continued DEBUG_EVENT
        self._pending_status = DBG_CONTINUE
        self._status = "no_target"  # no_target|stopped|running|exited
        self._reason = None
        self._stop_info = {}
        self._cur_tid = None
        self._exit_code = None
        self._initial_bp_seen = False
        self._exc_policy = {}
        self._image_base = None
        self._peb = None
        self._peb_walk_count = -1
        self._wow64 = False
        self._attached = False
        self._set_rf = False
        self._break_in_pending = False

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------

    def _start_worker(self):
        with self._worker_lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._worker_main, name="reva-debug-worker", daemon=True
                )
                self._worker.start()

    def _worker_main(self):
        while True:
            item = self._cmd_q.get()
            if item is None:
                break
            name, args, kwargs, rq = item
            try:
                fn = getattr(self, "_w_" + name)
                rq.put((True, fn(*args, **kwargs)))
            except BaseException as exc:  # noqa: BLE001 - relayed to the caller
                rq.put((False, exc))

    def _call(self, _name, *args, _timeout=None, **kwargs):
        self._start_worker()
        rq = queue.Queue(1)
        self._cmd_q.put((_name, args, kwargs, rq))
        try:
            ok, val = rq.get(timeout=self.timeout if _timeout is None else _timeout)
        except queue.Empty:
            raise DebugError(
                f"debug worker did not answer {_name!r} within "
                f"{self.timeout if _timeout is None else _timeout}s"
            ) from None
        if ok:
            return val
        raise val

    def _log(self, _event, **data):
        self._event_seq += 1
        rec = {"seq": self._event_seq, "time": time.time(), "event": _event}
        rec.update(data)
        with self._events_lock:
            self._events.append(rec)
        return rec

    # ------------------------------------------------------------------
    # public API -- lifecycle
    # ------------------------------------------------------------------

    def launch(self, path, args="", cwd=None, suspended_at_entry=True):
        """Create ``path`` under the debugger (``DEBUG_ONLY_THIS_PROCESS``).

        Runs until the initial (loader) breakpoint in ntdll and returns the
        stopped state.  With ``suspended_at_entry=False`` the loader breakpoint
        is continued through automatically and the process is left running.
        """
        return self._call(
            "launch", path, args, cwd, suspended_at_entry, _timeout=self.timeout + 30
        )

    def attach(self, pid):
        """``DebugActiveProcess`` on ``pid`` and run to the injected breakpoint."""
        return self._call("attach", int(pid), _timeout=self.timeout + 30)

    def detach(self, terminate=False):
        """Detach.  With ``terminate=True`` the debuggee is killed instead."""
        return self._call("detach", bool(terminate))

    def kill(self):
        """Terminate the debuggee and end the session."""
        return self._call("detach", True)

    def close(self, terminate=True):
        """Detach/kill and stop the worker thread."""
        try:
            if self._worker is not None and self._worker.is_alive():
                self._call("detach", bool(terminate))
        except DebugError:
            pass
        with self._worker_lock:
            if self._worker is not None and self._worker.is_alive():
                self._cmd_q.put(None)
                self._worker.join(timeout=5)
            self._worker = None

    def state(self):
        """Current session state: status, stop reason, thread, RIP and module."""
        return self._call("state")

    # ------------------------------------------------------------------
    # public API -- breakpoints
    # ------------------------------------------------------------------

    def set_bp(self, addr):
        """Arm a software (0xCC) breakpoint at ``addr``."""
        return self._call("set_bp", int(addr))

    def del_bp(self, addr):
        """Remove the software breakpoint at ``addr``, restoring the byte."""
        return self._call("del_bp", int(addr))

    def list_bps(self):
        return self._call("list_bps")

    def set_hw_bp(self, addr, size=1, kind="w"):
        """Arm a Dr0-Dr3 hardware breakpoint.  ``kind`` in {'x','w','rw'}."""
        return self._call("set_hw_bp", int(addr), int(size), str(kind))

    def del_hw_bp(self, addr):
        return self._call("del_hw_bp", int(addr))

    def list_hw_bps(self):
        return self._call("list_hw_bps")

    # ------------------------------------------------------------------
    # public API -- execution
    # ------------------------------------------------------------------

    def cont(self, timeout=10.0):
        """Resume and wait for the next reportable event."""
        return self._call("cont", float(timeout), _timeout=float(timeout) + 15)

    def step(self, timeout=10.0):
        """Single instruction step using the EFLAGS trap flag."""
        return self._call("step", float(timeout), _timeout=float(timeout) + 15)

    def step_over(self, timeout=10.0):
        """Step, but step *over* a CALL by breaking on the return address."""
        return self._call("step_over", float(timeout), _timeout=float(timeout) + 15)

    def run_to(self, addr, timeout=10.0):
        """Temporary breakpoint at ``addr`` + continue."""
        return self._call(
            "run_to", int(addr), float(timeout), _timeout=float(timeout) + 15
        )

    def interrupt(self, timeout=5.0):
        """``DebugBreakProcess`` to force a running debuggee to stop."""
        return self._call("interrupt", float(timeout), _timeout=float(timeout) + 15)

    # ------------------------------------------------------------------
    # public API -- inspection
    # ------------------------------------------------------------------

    def regs(self, tid=None):
        """Full register snapshot of ``tid`` (default: the stopped thread)."""
        return self._call("regs", tid)

    def set_reg(self, name, value, tid=None):
        return self._call("set_reg", str(name), int(value), tid)

    def read(self, addr, size):
        """Read ``size`` bytes.  Armed 0xCC bytes are masked back to originals.

        May return *fewer* than ``size`` bytes when the range runs into
        unreadable memory; raises :class:`DebugError` only if nothing at all
        could be read.
        """
        return self._call("read", int(addr), int(size))

    def write(self, addr, data):
        """Write ``data``, temporarily VirtualProtectEx'ing the pages to RWX."""
        return self._call("write", int(addr), bytes(data))

    def memmap(self):
        return self._call("memmap", _timeout=max(self.timeout, 60.0))

    def modules(self):
        return self._call("modules")

    def threads(self):
        return self._call("threads")

    def backtrace(self, max_frames=32):
        return self._call("backtrace", int(max_frames))

    def stack(self, count=16):
        return self._call("stack", int(count))

    def events(self, limit=100):
        """Most recent ``limit`` entries of the bounded event log."""
        with self._events_lock:
            items = list(self._events)
        return items[-int(limit) :] if limit else items

    def set_exception_policy(self, code_or_all, action):
        """``action`` in {'ignore','stop','swallow'}.

        ``'ignore'`` -> ``DBG_EXCEPTION_NOT_HANDLED`` (hand it to the app and
        keep running), ``'swallow'`` -> ``DBG_CONTINUE`` (pretend the debugger
        handled it), ``'stop'`` -> report to the caller.  ``code_or_all`` may be
        the literal string ``'all'``.
        """
        return self._call("set_exception_policy", code_or_all, str(action))

    def get_exception_policy(self):
        return self._call("get_exception_policy")

    # ==================================================================
    # worker-side implementation
    # ==================================================================

    # ---- small worker utilities --------------------------------------

    def _require_target(self):
        if self._hproc is None:
            raise DebugError("no target: call launch() or attach() first")
        if self._status == "exited":
            raise DebugError("the debuggee has exited")

    def _thread_handle(self, tid):
        t = self._threads.get(tid)
        if t is None:
            raise DebugError(f"unknown thread id {tid}")
        return t["handle"]

    def _get_ctx(self, tid, flags=CONTEXT_ALL):
        ctx = _new_context(flags)
        if not GetThreadContext(self._thread_handle(tid), ctypes.byref(ctx)):
            _fail(f"GetThreadContext(tid={tid})")
        return ctx

    def _set_ctx(self, tid, ctx):
        if not SetThreadContext(self._thread_handle(tid), ctypes.byref(ctx)):
            _fail(f"SetThreadContext(tid={tid})")

    def _ctx_any(self, tid, flags=CONTEXT_ALL):
        """Get a context even while the process runs free (suspend/resume)."""
        h = self._thread_handle(tid)
        if self._status == "running":
            if SuspendThread(h) == 0xFFFFFFFF:
                _fail("SuspendThread")
            try:
                return self._get_ctx(tid, flags)
            finally:
                ResumeThread(h)
        return self._get_ctx(tid, flags)

    # ---- raw memory ---------------------------------------------------

    def _read_raw(self, addr, size):
        if size <= 0:
            return b""
        buf = (ctypes.c_char * size)()
        got = SIZE_T(0)
        ok = ReadProcessMemory(
            self._hproc, LPVOID(addr), ctypes.byref(buf), size, ctypes.byref(got)
        )
        if not ok and got.value == 0:
            _fail(f"ReadProcessMemory(0x{addr:x}, {size})")
        return bytes(buf[: got.value])

    def _write_raw(self, addr, data):
        """Write, lifting page protection if needed, then restoring it."""
        size = len(data)
        if size == 0:
            return 0
        buf = (ctypes.c_char * size).from_buffer_copy(data)
        done = SIZE_T(0)
        if WriteProcessMemory(
            self._hproc, LPVOID(addr), ctypes.byref(buf), size, ctypes.byref(done)
        ) and done.value == size:
            FlushInstructionCache(self._hproc, LPVOID(addr), size)
            return done.value

        # protection dance: flip every page we touch to RWX, write, restore.
        page = 0x1000
        first = addr & ~(page - 1)
        last = (addr + size - 1) & ~(page - 1)
        saved = []
        try:
            p = first
            while p <= last:
                mbi = MEMORY_BASIC_INFORMATION()
                if not VirtualQueryEx(
                    self._hproc, LPVOID(p), ctypes.byref(mbi), ctypes.sizeof(mbi)
                ):
                    _fail(f"VirtualQueryEx(0x{p:x})")
                old = wt.DWORD(0)
                if not VirtualProtectEx(
                    self._hproc,
                    LPVOID(p),
                    page,
                    PAGE_EXECUTE_READWRITE,
                    ctypes.byref(old),
                ):
                    _fail(f"VirtualProtectEx(0x{p:x}, RWX)")
                saved.append((p, old.value))
                p += page
            done = SIZE_T(0)
            if not WriteProcessMemory(
                self._hproc, LPVOID(addr), ctypes.byref(buf), size, ctypes.byref(done)
            ):
                _fail(f"WriteProcessMemory(0x{addr:x}, {size})")
            FlushInstructionCache(self._hproc, LPVOID(addr), size)
            return done.value
        finally:
            for p, old in saved:
                tmp = wt.DWORD(0)
                VirtualProtectEx(self._hproc, LPVOID(p), page, old, ctypes.byref(tmp))

    def _read_clean(self, addr, size):
        data = bytearray(self._read_raw(addr, size))
        for a, bp in self._bps.items():
            if bp["armed"] and addr <= a < addr + len(data):
                data[a - addr] = bp["orig"][0]
        return bytes(data)

    # ---- modules ------------------------------------------------------

    def _pe_info(self, base):
        """Return (size_of_image, entry_point_va) read from the mapped PE."""
        try:
            hdr = self._read_raw(base, 0x40)
            if len(hdr) < 0x40 or hdr[:2] != b"MZ":
                return (0, 0)
            e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
            if e_lfanew > 0x1000:
                return (0, 0)
            nt = self._read_raw(base + e_lfanew, 0x78)
            if len(nt) < 0x78 or nt[:4] != b"PE\0\0":
                return (0, 0)
            entry = struct.unpack_from("<I", nt, 0x28)[0]
            size = struct.unpack_from("<I", nt, 0x50)[0]
            return (size, base + entry if entry else 0)
        except DebugError:
            return (0, 0)

    @staticmethod
    def _path_from_handle(hfile):
        if not hfile or hfile == INVALID_HANDLE_VALUE:
            return None
        buf = ctypes.create_unicode_buffer(32768)
        n = GetFinalPathNameByHandleW(hfile, buf, len(buf), 0)
        if not n or n >= len(buf):
            return None
        p = buf.value
        if p.startswith("\\\\?\\UNC\\"):
            p = "\\\\" + p[8:]
        elif p.startswith("\\\\?\\"):
            p = p[4:]
        return p

    def _add_module(self, base, path=None, size=None, entry=None):
        if not base:
            return None
        cur = self._modules.get(base, {})
        if size is None or entry is None:
            pe_size, pe_entry = self._pe_info(base)
            size = size if size else (cur.get("size") or pe_size)
            entry = entry if entry else (cur.get("entry") or pe_entry)
        path = path or cur.get("path")
        mod = {
            "base": base,
            "size": size or 0,
            "end": base + (size or 0),
            "path": path,
            "name": os.path.basename(path).lower() if path else None,
            "entry": entry or 0,
        }
        self._modules[base] = mod
        return mod

    def _walk_peb_modules(self):
        """Populate the module list by reading the PEB loader list."""
        if self._hproc is None:
            return 0
        if self._peb is None:
            pbi = PROCESS_BASIC_INFORMATION()
            retlen = ctypes.c_ulong(0)
            st = NtQueryInformationProcess(
                self._hproc, 0, ctypes.byref(pbi), ctypes.sizeof(pbi),
                ctypes.byref(retlen),
            )
            if st < 0:
                raise DebugError(
                    f"NtQueryInformationProcess(ProcessBasicInformation) -> "
                    f"0x{st & 0xFFFFFFFF:08x}"
                )
            self._peb = pbi.PebBaseAddress or 0
        if not self._peb:
            return 0
        try:
            ldr = struct.unpack("<Q", self._read_raw(self._peb + 0x18, 8))[0]
            if not ldr:
                return 0
            head = ldr + 0x10  # PEB_LDR_DATA.InLoadOrderModuleList
            cur = struct.unpack("<Q", self._read_raw(head, 8))[0]
        except DebugError:
            return 0
        found = 0
        seen = set()
        while cur and cur != head and cur not in seen and found < 512:
            seen.add(cur)
            try:
                ent = self._read_raw(cur, 0x60)
            except DebugError:
                break
            if len(ent) < 0x60:
                break
            flink = struct.unpack_from("<Q", ent, 0x00)[0]
            dll_base = struct.unpack_from("<Q", ent, 0x30)[0]
            entry_pt = struct.unpack_from("<Q", ent, 0x38)[0]
            size = struct.unpack_from("<I", ent, 0x40)[0]
            nlen = struct.unpack_from("<H", ent, 0x48)[0]
            nbuf = struct.unpack_from("<Q", ent, 0x50)[0]
            path = None
            if nbuf and 0 < nlen <= 0x1000:
                try:
                    path = self._read_raw(nbuf, nlen).decode("utf-16-le", "replace")
                except DebugError:
                    path = None
            if dll_base:
                self._add_module(dll_base, path=path, size=size, entry=entry_pt)
                found += 1
            cur = flink
        if found != self._peb_walk_count:
            self._peb_walk_count = found
            self._log("peb_walk", peb=self._peb, ldr=ldr, modules=found)
        return found

    def _module_of(self, addr):
        for mod in self._modules.values():
            if mod["size"] and mod["base"] <= addr < mod["base"] + mod["size"]:
                return mod
        return None

    def _sym(self, addr):
        mod = self._module_of(addr)
        if mod is None:
            return None
        return f"{mod['name'] or hex(mod['base'])}+0x{addr - mod['base']:x}"

    # ---- hardware breakpoints ----------------------------------------

    def _compose_dr(self, ctx):
        dr = [0, 0, 0, 0]
        dr7 = 0
        for slot, hb in self._hw_bps.items():
            dr[slot] = hb["addr"]
            dr7 |= 1 << (2 * slot)
            dr7 |= _HW_RW[hb["kind"]] << (16 + 4 * slot)
            ln = 0 if hb["kind"] == "x" else _HW_LEN[hb["size"]]
            dr7 |= ln << (18 + 4 * slot)
        ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 = dr
        ctx.Dr7 = dr7
        ctx.Dr6 = 0
        return dr7

    def _apply_hw_to_thread(self, tid):
        try:
            ctx = self._get_ctx(tid, CONTEXT_ALL)
        except DebugError:
            return False
        self._compose_dr(ctx)
        try:
            self._set_ctx(tid, ctx)
        except DebugError:
            return False
        return True

    def _apply_hw_all(self):
        n = 0
        for tid in list(self._threads):
            if self._apply_hw_to_thread(tid):
                n += 1
        return n

    # ---- software breakpoints ----------------------------------------

    def _arm_bp(self, bp):
        if bp["armed"]:
            return
        orig = self._read_raw(bp["addr"], 1)
        if len(orig) != 1:
            raise DebugError(f"cannot read byte at 0x{bp['addr']:x}")
        if orig != b"\xcc":
            bp["orig"] = orig
        self._write_raw(bp["addr"], b"\xcc")
        bp["armed"] = True

    def _disarm_bp(self, bp):
        if not bp["armed"]:
            return
        self._write_raw(bp["addr"], bp["orig"])
        bp["armed"] = False

    def _remove_all_bps(self):
        for bp in list(self._bps.values()):
            try:
                self._disarm_bp(bp)
            except DebugError:
                pass
        self._bps.clear()
        self._rearm.clear()

    # ---- state dicts --------------------------------------------------

    def _state_dict(self):
        out = {
            "status": self._status,
            "reason": self._reason,
            "pid": self._pid,
            "tid": self._cur_tid,
            # computed on the worker, so this is proof of where the Win32 debug
            # API is actually being driven from.
            "worker_thread_id": threading.get_ident(),
            "attached": self._attached,
            "wow64": self._wow64,
            "thread_count": len(self._threads),
            "module_count": len(self._modules),
            "bp_count": len(self._bps),
            "hw_bp_count": len(self._hw_bps),
        }
        if self._exit_code is not None:
            out["exit_code"] = self._exit_code
        out.update(self._stop_info)
        if self._status in ("stopped", "running") and self._cur_tid in self._threads:
            try:
                ctx = self._ctx_any(self._cur_tid, CONTEXT_ALL)
            except DebugError:
                ctx = None
            if ctx is not None:
                out["rip"] = ctx.Rip
                out["rip_hex"] = f"0x{ctx.Rip:016x}"
                out["rsp"] = ctx.Rsp
                out["rbp"] = ctx.Rbp
                mod = self._module_of(ctx.Rip)
                out["rip_module"] = mod["name"] if mod else None
                out["rip_module_path"] = mod["path"] if mod else None
                out["rip_offset"] = (ctx.Rip - mod["base"]) if mod else None
                out["rip_sym"] = self._sym(ctx.Rip)
        return out

    # ---- event pump ---------------------------------------------------

    def _close_thread(self, tid):
        t = self._threads.pop(tid, None)
        if t and t.get("handle"):
            CloseHandle(t["handle"])
        self._rearm.pop(tid, None)

    def _teardown(self, close_proc=True):
        for tid in list(self._threads):
            self._close_thread(tid)
        if close_proc and self._hproc:
            CloseHandle(self._hproc)
        self._hproc = None
        self._threads.clear()
        self._bps.clear()
        self._hw_bps.clear()
        self._rearm.clear()
        self._pending = None
        self._user_step = None
        self._peb = None
        self._peb_walk_count = -1

    def _wait_event(self, ms):
        ev = DEBUG_EVENT()
        if WaitForDebugEvent(ctypes.byref(ev), ms):
            return ev
        err = ctypes.get_last_error()
        if err == ERROR_SEM_TIMEOUT:
            return None
        _fail("WaitForDebugEvent", err)

    def _continue_pending(self):
        """``ContinueDebugEvent`` the one outstanding event (exactly once)."""
        ev = self._pending
        if ev is None:
            return
        self._pending = None
        status = self._pending_status
        self._pending_status = DBG_CONTINUE
        if not ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status):
            _fail("ContinueDebugEvent")

    def _prepare_resume(self, want_step_tid=None):
        """Set/clear the trap flag on the thread we are about to resume.

        Normally there is a pending debug event and the thread is frozen by the
        debug subsystem.  When the debuggee is running free (a previous
        ``cont()`` timed out) the thread has to be suspended around the context
        update instead.
        """
        free_running = self._pending is None
        if not free_running:
            tid = self._pending.dwThreadId
        elif want_step_tid is not None:
            tid = want_step_tid
        else:
            return
        if tid not in self._threads:
            return
        need_trap = (tid in self._rearm) or (
            want_step_tid is not None and want_step_tid == tid
        )
        if not need_trap and not self._set_rf:
            return
        h = self._thread_handle(tid)
        if free_running and SuspendThread(h) == 0xFFFFFFFF:
            return
        try:
            try:
                ctx = self._get_ctx(tid, CONTEXT_ALL)
            except DebugError:
                return
            if need_trap:
                ctx.EFlags |= EFLAGS_TF
            else:
                ctx.EFlags &= ~EFLAGS_TF
            if self._set_rf:
                ctx.EFlags |= EFLAGS_RF
                self._set_rf = False
            ctx.Dr6 = 0
            try:
                self._set_ctx(tid, ctx)
            except DebugError:
                pass
        finally:
            if free_running:
                ResumeThread(h)

    # -- individual event handlers; each returns 'stop' or 'go' --------

    def _on_create_process(self, ev):
        info = ev.u.CreateProcessInfo
        self._pid = ev.dwProcessId
        if self._hproc is None:
            self._hproc = info.hProcess
        elif info.hProcess and info.hProcess != self._hproc:
            CloseHandle(info.hProcess)
        path = self._path_from_handle(info.hFile)
        if info.hFile:
            CloseHandle(info.hFile)
        self._image_base = info.lpBaseOfImage
        mod = self._add_module(info.lpBaseOfImage, path=path)
        self._threads[ev.dwThreadId] = {
            "handle": info.hThread,
            "teb": info.lpThreadLocalBase or 0,
            "entry": info.lpStartAddress or 0,
        }
        is32 = wt.BOOL(0)
        if IsWow64Process(self._hproc, ctypes.byref(is32)):
            self._wow64 = bool(is32.value)
        self._log(
            "create_process",
            pid=ev.dwProcessId,
            tid=ev.dwThreadId,
            base=info.lpBaseOfImage,
            path=path,
            entry=mod["entry"] if mod else 0,
            wow64=self._wow64,
        )
        return "go"

    def _on_create_thread(self, ev):
        info = ev.u.CreateThread
        self._threads[ev.dwThreadId] = {
            "handle": info.hThread,
            "teb": info.lpThreadLocalBase or 0,
            "entry": info.lpStartAddress or 0,
        }
        if self._hw_bps:
            self._apply_hw_to_thread(ev.dwThreadId)
        self._log(
            "create_thread",
            tid=ev.dwThreadId,
            teb=info.lpThreadLocalBase or 0,
            entry=info.lpStartAddress or 0,
        )
        return "go"

    def _on_exit_thread(self, ev):
        self._log(
            "exit_thread", tid=ev.dwThreadId, exit_code=ev.u.ExitThread.dwExitCode
        )
        self._close_thread(ev.dwThreadId)
        return "go"

    def _on_exit_process(self, ev):
        self._exit_code = ev.u.ExitProcess.dwExitCode
        self._log("exit_process", pid=ev.dwProcessId, exit_code=self._exit_code)
        return "exited"

    def _on_load_dll(self, ev):
        info = ev.u.LoadDll
        path = self._path_from_handle(info.hFile)
        if path is None and info.lpImageName:
            try:
                ptr = struct.unpack("<Q", self._read_raw(info.lpImageName, 8))[0]
                if ptr:
                    raw = self._read_raw(ptr, 520)
                    if info.fUnicode:
                        s = raw.decode("utf-16-le", "replace")
                    else:
                        s = raw.decode("mbcs", "replace")
                    path = s.split("\x00", 1)[0] or None
            except DebugError:
                path = None
        if info.hFile:
            CloseHandle(info.hFile)
        mod = self._add_module(info.lpBaseOfDll, path=path)
        self._log(
            "load_dll",
            base=info.lpBaseOfDll,
            path=path,
            size=mod["size"] if mod else 0,
            tid=ev.dwThreadId,
        )
        # Re-arm any breakpoint that lives inside a freshly (re)mapped image.
        for bp in self._bps.values():
            if bp["armed"] and mod and mod["base"] <= bp["addr"] < mod["end"]:
                try:
                    if self._read_raw(bp["addr"], 1) != b"\xcc":
                        bp["armed"] = False
                        self._arm_bp(bp)
                except DebugError:
                    pass
        return "go"

    def _on_unload_dll(self, ev):
        base = ev.u.UnloadDll.lpBaseOfDll
        mod = self._modules.pop(base, None)
        self._log(
            "unload_dll", base=base, path=mod["path"] if mod else None, tid=ev.dwThreadId
        )
        return "go"

    def _on_output_debug_string(self, ev):
        info = ev.u.DebugString
        text = None
        try:
            n = info.nDebugStringLength
            raw = self._read_raw(info.lpDebugStringData, max(0, n))
            if info.fUnicode:
                text = raw.decode("utf-16-le", "replace")
            else:
                text = raw.decode("mbcs", "replace")
            text = text.split("\x00", 1)[0]
        except DebugError:
            text = None
        self._log("output_debug_string", tid=ev.dwThreadId, text=text)
        return "go"

    def _on_rip(self, ev):
        info = ev.u.RipInfo
        self._log(
            "rip",
            tid=ev.dwThreadId,
            error=info.dwError,
            error_text=_win_error_text(info.dwError),
            type=info.dwType,
        )
        self._reason = "rip"
        self._stop_info = {
            "rip_event_error": info.dwError,
            "rip_event_type": info.dwType,
        }
        return "stop"

    def _policy_action(self, code, first_chance):
        act = self._exc_policy.get(code)
        if act is None:
            act = self._exc_policy.get("all")
        if act is not None:
            return act
        if code in (EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP):
            return "stop"
        return "ignore" if first_chance else "stop"

    def _on_exception(self, ev, want_step_tid):
        rec = ev.u.Exception.ExceptionRecord
        code = rec.ExceptionCode & 0xFFFFFFFF
        addr = rec.ExceptionAddress or 0
        first = bool(ev.u.Exception.dwFirstChance)
        tid = ev.dwThreadId
        nparams = min(rec.NumberParameters, 15)
        params = [rec.ExceptionInformation[i] for i in range(nparams)]
        self._log(
            "exception",
            tid=tid,
            code=code,
            code_hex=f"0x{code:08x}",
            name=EXCEPTION_NAMES.get(code, "UNKNOWN"),
            address=addr,
            address_hex=f"0x{addr:016x}",
            sym=self._sym(addr),
            first_chance=first,
            parameters=params,
        )
        base_info = {
            "exception_code": code,
            "exception_code_hex": f"0x{code:08x}",
            "exception_name": EXCEPTION_NAMES.get(code, "UNKNOWN"),
            "exception_address": addr,
            "exception_address_sym": self._sym(addr),
            "first_chance": first,
            "exception_parameters": params,
        }

        # --- single step: ours (re-arm / user step / hw bp) or foreign ---
        if code in (EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
            self._pending_status = DBG_CONTINUE
            hw_hit = None
            try:
                ctx = self._get_ctx(tid, CONTEXT_ALL)
                if ctx.Dr6 & 0xF:
                    for slot in range(4):
                        if ctx.Dr6 & (1 << slot) and slot in self._hw_bps:
                            hw_hit = (slot, dict(self._hw_bps[slot]))
                            break
                ctx.Dr6 = 0
                self._set_ctx(tid, ctx)
            except DebugError:
                pass

            rearm_addr = self._rearm.pop(tid, None)
            if rearm_addr is not None:
                bp = self._bps.get(rearm_addr)
                if bp is not None and not bp["armed"]:
                    try:
                        self._arm_bp(bp)
                    except DebugError:
                        pass

            if hw_hit is not None:
                slot, hb = hw_hit
                if hb["kind"] == "x":
                    self._set_rf = True
                self._reason = "hw_breakpoint"
                self._stop_info = dict(base_info)
                self._stop_info.update(
                    {
                        "hw_bp_slot": slot,
                        "hw_bp_addr": hb["addr"],
                        "hw_bp_kind": hb["kind"],
                        "hw_bp_size": hb["size"],
                    }
                )
                return "stop"

            if want_step_tid is not None and want_step_tid == tid:
                self._reason = "step"
                self._stop_info = dict(base_info)
                return "stop"

            if rearm_addr is not None:
                return "go"  # internal step used only to get past a 0xCC

            act = self._policy_action(code, first)
            if act == "stop":
                self._reason = "single_step"
                self._stop_info = dict(base_info)
                return "stop"
            self._pending_status = (
                DBG_CONTINUE if act == "swallow" else DBG_EXCEPTION_NOT_HANDLED
            )
            return "go"

        # --- breakpoint ---
        if code in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
            self._pending_status = DBG_CONTINUE
            bp = self._bps.get(addr)
            if bp is not None and bp["armed"]:
                bp["hits"] += 1
                try:
                    ctx = self._get_ctx(tid, CONTEXT_ALL)
                    if ctx.Rip == addr + 1:
                        ctx.Rip = addr
                        self._set_ctx(tid, ctx)
                    rsp = ctx.Rsp
                except DebugError:
                    rsp = 0
                try:
                    self._disarm_bp(bp)
                except DebugError:
                    pass
                deep = (
                    bp["min_rsp"] is not None and rsp and rsp < bp["min_rsp"]
                )
                if bp["temp"] and not deep:
                    self._bps.pop(addr, None)
                else:
                    self._rearm[tid] = addr
                if deep:
                    return "go"  # recursive hit of a step-over bp: keep going
                self._reason = bp["reason"] or "breakpoint"
                self._stop_info = dict(base_info)
                self._stop_info.update(
                    {
                        "bp_addr": addr,
                        "bp_sym": self._sym(addr),
                        "bp_temp": bp["temp"],
                        "bp_hits": bp["hits"],
                    }
                )
                return "stop"

            if not self._initial_bp_seen:
                self._initial_bp_seen = True
                self._log("initial_breakpoint", tid=tid, address=addr)
                self._reason = "initial_breakpoint"
                self._stop_info = dict(base_info)
                self._stop_info["initial"] = True
                return "stop"

            if self._break_in_pending:
                self._break_in_pending = False
                self._reason = "interrupt"
                self._stop_info = dict(base_info)
                return "stop"

            act = self._policy_action(code, first)
            if act == "stop":
                self._reason = "breakpoint_unknown"
                self._stop_info = dict(base_info)
                return "stop"
            self._pending_status = (
                DBG_CONTINUE if act == "swallow" else DBG_EXCEPTION_NOT_HANDLED
            )
            return "go"

        # --- everything else ---
        act = self._policy_action(code, first)
        if act == "stop":
            self._pending_status = DBG_EXCEPTION_NOT_HANDLED
            self._reason = "exception"
            self._stop_info = dict(base_info)
            return "stop"
        self._pending_status = (
            DBG_CONTINUE if act == "swallow" else DBG_EXCEPTION_NOT_HANDLED
        )
        return "go"

    def _dispatch(self, ev, want_step_tid):
        code = ev.dwDebugEventCode
        self._cur_tid = ev.dwThreadId
        if code == EXCEPTION_DEBUG_EVENT:
            return self._on_exception(ev, want_step_tid)
        if code == CREATE_PROCESS_DEBUG_EVENT:
            return self._on_create_process(ev)
        if code == CREATE_THREAD_DEBUG_EVENT:
            return self._on_create_thread(ev)
        if code == EXIT_THREAD_DEBUG_EVENT:
            return self._on_exit_thread(ev)
        if code == EXIT_PROCESS_DEBUG_EVENT:
            return self._on_exit_process(ev)
        if code == LOAD_DLL_DEBUG_EVENT:
            return self._on_load_dll(ev)
        if code == UNLOAD_DLL_DEBUG_EVENT:
            return self._on_unload_dll(ev)
        if code == OUTPUT_DEBUG_STRING_EVENT:
            return self._on_output_debug_string(ev)
        if code == RIP_EVENT:
            return self._on_rip(ev)
        self._log("unknown_event", code=code, tid=ev.dwThreadId)
        return "go"

    def _pump(self, timeout, want_step_tid=None, stop_on_initial=True):
        """Resume the debuggee and run the event loop until something stops it.

        Returns the state dict.  ``ContinueDebugEvent`` is issued exactly once
        for each event received.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        self._status = "running"
        self._reason = None
        self._stop_info = {}
        while True:
            self._prepare_resume(want_step_tid)
            self._continue_pending()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._status = "running"
                self._reason = "timeout"
                return self._state_dict()
            ev = self._wait_event(min(250, int(remaining * 1000) + 1))
            if ev is None:
                continue
            self._pending = ev
            self._pending_status = DBG_CONTINUE
            try:
                what = self._dispatch(ev, want_step_tid)
            except BaseException:
                # never leave an event un-continued because a handler blew up
                self._pending_status = DBG_EXCEPTION_NOT_HANDLED
                try:
                    self._continue_pending()
                except DebugError:
                    pass
                raise
            if what == "stop":
                if (
                    not stop_on_initial
                    and self._reason == "initial_breakpoint"
                ):
                    continue
                self._status = "stopped"
                if want_step_tid is not None:
                    self._user_step = None
                return self._state_dict()
            if what == "exited":
                self._continue_pending()
                self._status = "exited"
                self._reason = "exit_process"
                st = self._state_dict()
                self._teardown()
                return st

    # ---- worker command implementations -------------------------------

    def _w_launch(self, path, args, cwd, suspended_at_entry):
        if self._hproc is not None:
            raise DebugError("already debugging a process; detach() first")
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise DebugError(f"no such executable: {path}")
        cmdline = f'"{path}"' + ((" " + args) if args else "")
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        buf = ctypes.create_unicode_buffer(cmdline, max(len(cmdline) + 1, 260))
        ok = CreateProcessW(
            path,
            buf,
            None,
            None,
            False,
            DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT,
            None,
            cwd,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            _fail(f"CreateProcessW({path!r})")
        # The handles from PROCESS_INFORMATION are duplicates of the ones the
        # CREATE_PROCESS debug event will hand us; close them right away.
        if pi.hThread:
            CloseHandle(pi.hThread)
        if pi.hProcess:
            CloseHandle(pi.hProcess)
        self._pid = pi.dwProcessId
        self._attached = False
        self._initial_bp_seen = False
        self._status = "running"
        self._log("launch", pid=self._pid, path=path, cmdline=cmdline, cwd=cwd)
        st = self._pump(self.timeout, stop_on_initial=True)
        if self._status == "stopped":
            try:
                self._walk_peb_modules()
            except DebugError:
                pass
            st = self._state_dict()
        if not suspended_at_entry and self._status == "stopped":
            st = self._pump(1.0)
        return st

    def _w_attach(self, pid):
        if self._hproc is not None:
            raise DebugError("already debugging a process; detach() first")
        if not DebugActiveProcess(pid):
            _fail(f"DebugActiveProcess({pid})")
        self._pid = pid
        self._attached = True
        self._initial_bp_seen = False
        self._status = "running"
        self._log("attach", pid=pid)
        st = self._pump(self.timeout, stop_on_initial=True)
        if self._status == "stopped":
            try:
                self._walk_peb_modules()
            except DebugError:
                pass
            st = self._state_dict()
        return st

    def _w_detach(self, terminate):
        if self._hproc is None:
            return {"status": "no_target", "detached": False}
        pid = self._pid
        out = {"pid": pid, "terminated": bool(terminate)}
        if terminate:
            try:
                self._continue_pending()
            except DebugError:
                pass
            TerminateProcess(self._hproc, 0)
            # drain so the kernel can finish the kill while we are the debugger
            end = time.monotonic() + 3.0
            while time.monotonic() < end:
                ev = self._wait_event(100)
                if ev is None:
                    continue
                self._pending = ev
                self._pending_status = DBG_CONTINUE
                done = ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
                if done:
                    self._exit_code = ev.u.ExitProcess.dwExitCode
                try:
                    self._continue_pending()
                except DebugError:
                    pass
                if done:
                    break
            out["status"] = "exited"
            self._log("terminated", pid=pid)
        else:
            try:
                self._remove_all_bps()
            except DebugError:
                pass
            self._hw_bps.clear()
            try:
                self._apply_hw_all()
            except DebugError:
                pass
            try:
                self._continue_pending()
            except DebugError:
                pass
            DebugSetProcessKillOnExit(False)
            if not DebugActiveProcessStop(pid):
                _fail(f"DebugActiveProcessStop({pid})")
            out["status"] = "detached"
            self._log("detach", pid=pid)
        self._teardown()
        self._status = "no_target"
        self._reason = None
        self._stop_info = {}
        self._pid = None
        self._cur_tid = None
        self._modules.clear()
        self._initial_bp_seen = False
        self._attached = False
        self._break_in_pending = False
        out["detached"] = True
        return out

    def _w_state(self):
        return self._state_dict()

    # breakpoints -------------------------------------------------------

    def _w_set_bp(self, addr):
        self._require_target()
        bp = self._bps.get(addr)
        if bp is not None and not bp["temp"]:
            return {"addr": addr, "already": True, **self._bp_dict(bp)}
        bp = {
            "addr": addr,
            "orig": b"\x90",
            "armed": False,
            "temp": False,
            "min_rsp": None,
            "reason": "breakpoint",
            "hits": bp["hits"] if bp else 0,
        }
        self._bps[addr] = bp
        try:
            self._arm_bp(bp)
        except DebugError:
            self._bps.pop(addr, None)
            raise
        self._log("set_bp", addr=addr, sym=self._sym(addr))
        return {"addr": addr, "already": False, **self._bp_dict(bp)}

    def _bp_dict(self, bp):
        return {
            "addr": bp["addr"],
            "addr_hex": f"0x{bp['addr']:016x}",
            "sym": self._sym(bp["addr"]),
            "orig_byte": bp["orig"].hex(),
            "armed": bp["armed"],
            # True while we are stopped *on* this breakpoint: the 0xCC has been
            # lifted and will be put back by the trap-flag step on resume.
            "pending_rearm": bp["addr"] in self._rearm.values(),
            "temporary": bp["temp"],
            "hits": bp["hits"],
        }

    def _w_del_bp(self, addr):
        self._require_target()
        bp = self._bps.pop(addr, None)
        if bp is None:
            return {"addr": addr, "removed": False}
        self._disarm_bp(bp)
        for tid, a in list(self._rearm.items()):
            if a == addr:
                self._rearm.pop(tid, None)
        self._log("del_bp", addr=addr)
        return {"addr": addr, "removed": True, "hits": bp["hits"]}

    def _w_list_bps(self):
        return [self._bp_dict(bp) for bp in sorted(
            self._bps.values(), key=lambda b: b["addr"])]

    def _w_set_hw_bp(self, addr, size, kind):
        self._require_target()
        kind = kind.lower()
        if kind not in _HW_RW:
            raise DebugError("kind must be one of 'x', 'w', 'rw'")
        if size not in _HW_LEN:
            raise DebugError("size must be one of 1, 2, 4, 8")
        if kind == "x":
            size = 1
        elif size > 1 and addr % size:
            raise DebugError(
                f"a {size}-byte hardware breakpoint must be {size}-byte aligned"
            )
        for slot, hb in self._hw_bps.items():
            if hb["addr"] == addr:
                hb.update(size=size, kind=kind)
                self._apply_hw_all()
                return {"slot": slot, "addr": addr, "size": size, "kind": kind,
                        "replaced": True, **self._hw_summary()}
        slot = next((s for s in range(4) if s not in self._hw_bps), None)
        if slot is None:
            raise DebugError("all four hardware debug registers are in use")
        self._hw_bps[slot] = {"addr": addr, "size": size, "kind": kind}
        n = self._apply_hw_all()
        self._log("set_hw_bp", slot=slot, addr=addr, size=size, kind=kind, threads=n)
        return {
            "slot": slot,
            "addr": addr,
            "addr_hex": f"0x{addr:016x}",
            "size": size,
            "kind": kind,
            "replaced": False,
            "threads_programmed": n,
            **self._hw_summary(),
        }

    def _hw_summary(self):
        ctx = _new_context()
        dr7 = self._compose_dr(ctx)
        return {"dr7": dr7, "dr7_hex": f"0x{dr7:016x}"}

    def _w_del_hw_bp(self, addr):
        self._require_target()
        slot = next((s for s, h in self._hw_bps.items() if h["addr"] == addr), None)
        if slot is None:
            return {"addr": addr, "removed": False}
        self._hw_bps.pop(slot)
        n = self._apply_hw_all()
        self._log("del_hw_bp", slot=slot, addr=addr, threads=n)
        return {"addr": addr, "removed": True, "slot": slot,
                "threads_programmed": n, **self._hw_summary()}

    def _w_list_hw_bps(self):
        out = []
        for slot, hb in sorted(self._hw_bps.items()):
            out.append(
                {
                    "slot": slot,
                    "addr": hb["addr"],
                    "addr_hex": f"0x{hb['addr']:016x}",
                    "size": hb["size"],
                    "kind": hb["kind"],
                    "sym": self._sym(hb["addr"]),
                }
            )
        return out

    # execution ---------------------------------------------------------

    def _w_cont(self, timeout):
        self._require_target()
        return self._pump(timeout)

    def _w_step(self, timeout):
        self._require_target()
        tid = self._cur_tid
        if tid not in self._threads:
            raise DebugError("no current thread to step")
        self._user_step = tid
        try:
            return self._pump(timeout, want_step_tid=tid)
        finally:
            self._user_step = None

    def _w_run_to(self, addr, timeout, reason="run_to", min_rsp=None):
        self._require_target()
        existing = self._bps.get(addr)
        created = False
        if existing is None:
            bp = {
                "addr": addr,
                "orig": b"\x90",
                "armed": False,
                "temp": True,
                "min_rsp": min_rsp,
                "reason": reason,
                "hits": 0,
            }
            self._bps[addr] = bp
            try:
                self._arm_bp(bp)
            except DebugError:
                self._bps.pop(addr, None)
                raise
            created = True
        self._log("run_to", addr=addr, sym=self._sym(addr), temp=created)
        try:
            return self._pump(timeout)
        finally:
            if created:
                bp = self._bps.get(addr)
                if bp is not None and bp.get("temp"):
                    try:
                        self._disarm_bp(bp)
                    except DebugError:
                        pass
                    self._bps.pop(addr, None)
                    for t, a in list(self._rearm.items()):
                        if a == addr:
                            self._rearm.pop(t, None)

    def _w_step_over(self, timeout):
        self._require_target()
        tid = self._cur_tid
        if tid not in self._threads:
            raise DebugError("no current thread to step")
        ctx = self._get_ctx(tid, CONTEXT_ALL)
        code = self._read_clean(ctx.Rip, 16)
        n = _call_length(code)
        if n is None:
            st = self._w_step(timeout)
            st["step_over"] = "stepped"
            return st
        ret_addr = ctx.Rip + n
        st = self._w_run_to(
            ret_addr, timeout, reason="step_over", min_rsp=ctx.Rsp
        )
        st["step_over"] = "called"
        st["call_length"] = n
        st["call_return_addr"] = ret_addr
        return st

    def _w_interrupt(self, timeout):
        self._require_target()
        if self._status == "stopped":
            return self._state_dict()
        self._break_in_pending = True
        if not DebugBreakProcess(self._hproc):
            self._break_in_pending = False
            _fail("DebugBreakProcess")
        return self._pump(timeout)

    # inspection --------------------------------------------------------

    def _pick_tid(self, tid):
        if tid is None:
            tid = self._cur_tid
        if tid not in self._threads:
            raise DebugError(f"no such thread: {tid}")
        return tid

    def _w_regs(self, tid):
        self._require_target()
        tid = self._pick_tid(tid)
        ctx = self._ctx_any(tid, CONTEXT_ALL)
        names = (
            "Rax Rbx Rcx Rdx Rsi Rdi Rbp Rsp R8 R9 R10 R11 R12 R13 R14 R15 Rip"
        ).split()
        out = {
            "tid": tid,
            "context_size": CONTEXT_SIZE,
            "context_address": ctypes.addressof(ctx),
            "context_aligned_16": ctypes.addressof(ctx) % 16 == 0,
            "context_flags": f"0x{ctx.ContextFlags:08x}",
        }
        for n in names:
            out[n.lower()] = getattr(ctx, n)
        out["eflags"] = ctx.EFlags
        out["eflags_hex"] = f"0x{ctx.EFlags:08x}"
        out["flags"] = _decode_eflags(ctx.EFlags)
        out["mxcsr"] = ctx.MxCsr
        out["segments"] = {
            "cs": ctx.SegCs,
            "ds": ctx.SegDs,
            "es": ctx.SegEs,
            "fs": ctx.SegFs,
            "gs": ctx.SegGs,
            "ss": ctx.SegSs,
        }
        out["dr"] = {
            "dr0": ctx.Dr0,
            "dr1": ctx.Dr1,
            "dr2": ctx.Dr2,
            "dr3": ctx.Dr3,
            "dr6": ctx.Dr6,
            "dr7": ctx.Dr7,
        }
        out["dr_hex"] = {k: f"0x{v:016x}" for k, v in out["dr"].items()}
        xmm = {}
        for i in range(16):
            m = ctx.FltSave.XmmRegisters[i]
            xmm[f"xmm{i}"] = f"{m.High & 0xFFFFFFFFFFFFFFFF:016x}{m.Low:016x}"
        out["xmm"] = xmm
        mod = self._module_of(ctx.Rip)
        out["rip_module"] = mod["name"] if mod else None
        out["rip_sym"] = self._sym(ctx.Rip)
        out["rip_hex"] = f"0x{ctx.Rip:016x}"
        return out

    _REG_ALIASES = {
        "pc": "Rip",
        "sp": "Rsp",
        "fp": "Rbp",
        "flags": "EFlags",
        "eflags": "EFlags",
    }

    def _w_set_reg(self, name, value, tid):
        self._require_target()
        tid = self._pick_tid(tid)
        key = self._REG_ALIASES.get(name.lower(), name.capitalize())
        canon = {f.lower(): f for f, _ in CONTEXT._fields_}
        field = canon.get(key.lower())
        if field is None or field in ("FltSave", "VectorRegister", "ContextFlags"):
            raise DebugError(f"unknown or unwritable register {name!r}")
        ctx = self._ctx_any(tid, CONTEXT_ALL)
        old = getattr(ctx, field)
        setattr(ctx, field, value)
        self._set_ctx(tid, ctx)
        self._log("set_reg", tid=tid, reg=field, old=old, new=value)
        return {"tid": tid, "register": field, "old": old, "new": value}

    def _w_read(self, addr, size):
        self._require_target()
        return self._read_clean(addr, size)

    def _w_write(self, addr, data):
        self._require_target()
        n = self._write_raw(addr, data)
        # keep breakpoint shadows coherent with what the caller just wrote
        for a, bp in self._bps.items():
            if bp["armed"] and addr <= a < addr + len(data):
                bp["orig"] = data[a - addr : a - addr + 1]
                bp["armed"] = False
                self._arm_bp(bp)
        self._log("write", addr=addr, size=n)
        return {"addr": addr, "written": n}

    def _w_memmap(self):
        self._require_target()
        out = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        limit = 0x7FFFFFFF0000
        while addr < limit and len(out) < 200000:
            if not VirtualQueryEx(
                self._hproc, LPVOID(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            ):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0x1000
            alloc = mbi.AllocationBase or 0
            mod = self._modules.get(alloc)
            if mod is None and mbi.Type == MEM_IMAGE:
                mod = self._module_of(base)
            out.append(
                {
                    "base": base,
                    "base_hex": f"0x{base:016x}",
                    "size": size,
                    "end": base + size,
                    "allocation_base": alloc,
                    "state": _STATE_NAMES.get(mbi.State, hex(mbi.State)),
                    "protect": _protect_name(mbi.Protect) if mbi.Protect else "---",
                    "protect_raw": mbi.Protect,
                    "allocation_protect": _protect_name(mbi.AllocationProtect)
                    if mbi.AllocationProtect
                    else "---",
                    "type": _TYPE_NAMES.get(mbi.Type, hex(mbi.Type) if mbi.Type else "-"),
                    "executable": (mbi.Protect & 0xFF) in _EXEC_PROTECTS,
                    "module": mod["name"] if mod else None,
                    "module_path": mod["path"] if mod else None,
                }
            )
            addr = base + size
        return out

    def _w_modules(self):
        self._require_target()
        try:
            self._walk_peb_modules()
        except DebugError:
            pass
        out = []
        for mod in sorted(self._modules.values(), key=lambda m: m["base"]):
            out.append(
                {
                    "base": mod["base"],
                    "base_hex": f"0x{mod['base']:016x}",
                    "size": mod["size"],
                    "end": mod["base"] + mod["size"],
                    "entry": mod["entry"],
                    "path": mod["path"],
                    "name": mod["name"],
                    "is_main": mod["base"] == self._image_base,
                }
            )
        return out

    def _w_threads(self):
        self._require_target()
        out = []
        for tid in sorted(self._threads):
            t = self._threads[tid]
            h = t["handle"]
            prev = SuspendThread(h)
            if prev == 0xFFFFFFFF:
                susp_count = None
            else:
                susp_count = prev
                ResumeThread(h)
            rip = None
            try:
                ctx = self._get_ctx(tid, CONTEXT_ALL)
                rip = ctx.Rip
            except DebugError:
                pass
            out.append(
                {
                    "tid": tid,
                    "suspended": bool(susp_count) if susp_count is not None else None,
                    "suspend_count": susp_count,
                    "teb": t["teb"],
                    "teb_hex": f"0x{t['teb']:016x}",
                    "entry": t["entry"],
                    "entry_sym": self._sym(t["entry"]) if t["entry"] else None,
                    "rip": rip,
                    "rip_hex": f"0x{rip:016x}" if rip is not None else None,
                    "rip_sym": self._sym(rip) if rip is not None else None,
                    "is_current": tid == self._cur_tid,
                }
            )
        return out

    def _w_backtrace(self, max_frames):
        """Walk the saved-RBP chain.

        NOTE: RBP-chain walking is *unreliable* on x64.  The Microsoft x64 ABI
        does not require a frame pointer; most optimised code omits it (FPO),
        so RBP frequently holds an ordinary value and the chain is bogus or
        truncates after one frame.  A correct unwinder would parse
        ``.pdata``/``RUNTIME_FUNCTION`` + ``UNWIND_INFO``.  That is out of
        scope here and this inaccuracy is accepted.
        """
        self._require_target()
        tid = self._pick_tid(None)
        ctx = self._ctx_any(tid, CONTEXT_ALL)
        frames = []

        def frame(idx, rip, rbp, extra=None):
            mod = self._module_of(rip)
            d = {
                "index": idx,
                "rip": rip,
                "rip_hex": f"0x{rip:016x}",
                "rbp": rbp,
                "rbp_hex": f"0x{rbp:016x}",
                "module": mod["name"] if mod else None,
                "module_path": mod["path"] if mod else None,
                "offset": (rip - mod["base"]) if mod else None,
                "sym": self._sym(rip),
            }
            if extra:
                d.update(extra)
            return d

        frames.append(frame(0, ctx.Rip, ctx.Rbp, {"rsp": ctx.Rsp}))
        rbp = ctx.Rbp
        seen = set()
        while len(frames) < max_frames and rbp and rbp not in seen:
            seen.add(rbp)
            try:
                raw = self._read_raw(rbp, 16)
            except DebugError:
                break
            if len(raw) < 16:
                break
            next_rbp, ret = struct.unpack("<QQ", raw)
            if not ret or ret < 0x10000:
                break
            frames.append(frame(len(frames), ret, next_rbp))
            if next_rbp <= rbp:
                break
            rbp = next_rbp
        return frames

    def _classify_ptr(self, value, stack_lo, stack_hi):
        if not value:
            return "null", None
        mod = self._module_of(value)
        if mod is not None:
            mbi = MEMORY_BASIC_INFORMATION()
            exec_ = False
            if VirtualQueryEx(
                self._hproc, LPVOID(value), ctypes.byref(mbi), ctypes.sizeof(mbi)
            ):
                exec_ = (mbi.Protect & 0xFF) in _EXEC_PROTECTS
            return ("code" if exec_ else "module_data"), self._sym(value)
        if stack_lo and stack_lo <= value < stack_hi:
            return "stack", None
        mbi = MEMORY_BASIC_INFORMATION()
        if not VirtualQueryEx(
            self._hproc, LPVOID(value), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ):
            return "invalid", None
        if mbi.State == MEM_FREE:
            return "invalid", None
        if (mbi.Protect & 0xFF) in _EXEC_PROTECTS:
            return "code_unknown", None
        if mbi.Type == MEM_PRIVATE:
            return "heap_or_private", None
        if mbi.Type == MEM_IMAGE:
            return "module_data", self._sym(value)
        return "mapped", None

    def _w_stack(self, count):
        self._require_target()
        tid = self._pick_tid(None)
        ctx = self._ctx_any(tid, CONTEXT_ALL)
        teb = self._threads[tid]["teb"]
        stack_lo = stack_hi = 0
        if teb:
            try:
                raw = self._read_raw(teb + 0x08, 16)
                stack_hi, stack_lo = struct.unpack("<QQ", raw)
            except DebugError:
                pass
        data = self._read_clean(ctx.Rsp, count * 8)
        out = []
        for i in range(len(data) // 8):
            addr = ctx.Rsp + i * 8
            val = struct.unpack_from("<Q", data, i * 8)[0]
            kind, sym = self._classify_ptr(val, stack_lo, stack_hi)
            out.append(
                {
                    "index": i,
                    "addr": addr,
                    "addr_hex": f"0x{addr:016x}",
                    "value": val,
                    "value_hex": f"0x{val:016x}",
                    "kind": kind,
                    "sym": sym,
                    "offset_from_rsp": i * 8,
                }
            )
        return out

    def _w_set_exception_policy(self, code_or_all, action):
        action = action.lower()
        if action not in ("ignore", "stop", "swallow"):
            raise DebugError("action must be 'ignore', 'stop' or 'swallow'")
        if isinstance(code_or_all, str) and code_or_all.lower() == "all":
            key = "all"
        else:
            key = int(code_or_all) & 0xFFFFFFFF
        self._exc_policy[key] = action
        self._log("set_exception_policy", code=key, action=action)
        return self._w_get_exception_policy()

    def _w_get_exception_policy(self):
        out = {}
        for k, v in self._exc_policy.items():
            if k == "all":
                out["all"] = v
            else:
                out[f"0x{k:08x}"] = {
                    "action": v,
                    "name": EXCEPTION_NAMES.get(k, "UNKNOWN"),
                }
        out["_default"] = (
            "stop on BREAKPOINT/SINGLE_STEP; first chance -> ignore "
            "(DBG_EXCEPTION_NOT_HANDLED), second chance -> stop"
        )
        return out
