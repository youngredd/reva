<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7A3BFF,100:1F8EFA&height=180&section=header&text=REVA&fontSize=78&fontColor=ffffff&fontAlignY=38&desc=reverse-engineering%20workbench%20for%20an%20LLM%20agent&descAlignY=62&descSize=16&animation=fadeIn" />

<p>
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="windows" src="https://img.shields.io/badge/platform-windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img alt="mcp" src="https://img.shields.io/badge/MCP-stdio-7A3BFF?style=for-the-badge" />
  <img alt="license" src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" />
  <img alt="status" src="https://img.shields.io/badge/status-alpha-f59e0b?style=for-the-badge" />
</p>

<p><em>31 tools · PE/COFF/UEFI · Unicorn emulation · live Win32 debugger · pseudo-C lifter</em></p>

</div>

<img src="assets/waifu.png" align="right" width="280" alt="" />

A reverse-engineering workbench for PE/COFF binaries — `.exe`, `.dll`, `.sys`,
`.efi` — built to be driven by an LLM agent over [MCP](https://modelcontextprotocol.io),
with a live Windows debugger attached.

It is not a clone of IDA. It is the set of tools an agent actually needs, which
turns out to be a different set: a persistent analysis database, output shaped
for a limited context window, search that answers behavioural questions, and an
emulator for the things static reading cannot settle.

<br clear="right" />

```
┌──────────────────────────────────────────────────────────────┐
│ MCP server (31 tools, stdio)                                 │
├──────────────────────────────────────────────────────────────┤
│ project database (SQLite)  — names, comments, types, notes    │
│                              persists across sessions         │
├───────────────────────────┬──────────────────────────────────┤
│ static                    │ dynamic                           │
│  PE/COFF/UEFI loader      │  Unicorn emulation                │
│  recursive-descent disasm │   · api calls intercepted + logged │
│  CFG, xrefs, jump tables  │   · run a decoder, read the answer │
│  strings, RTTI, vtables   │                                   │
│  UEFI protocol GUIDs      │  live Win32 debugger              │
│  crypto constants/tables  │   · software + hardware bps        │
│  behavioural fingerprints │   · step / step-over / run-to      │
│  pseudo-C lifter          │   · memory, threads, modules       │
│  assembler + patcher      │   · exception policy               │
└───────────────────────────┴──────────────────────────────────┘
```

---

## ✦ Why not just wrap IDA or Ghidra

Because the hard part for an agent is not disassembly, it is *attention*. A
45 KB function dumped as text is 11,000 instructions of mostly-useless
addresses. REVA is built around that constraint:

- **Every function carries a one-line behavioural profile.** You can triage
  5,000 functions without reading any of them:
  `530i/59bb 1args 4loop gui+keylog+network 59indirect calls:GetWindowTextW,...`
- **Disassembly is annotated, not raw.** Call targets resolve to API names,
  rip-relative loads resolve to symbols, referenced strings are inlined as
  comments, stack slots get stable names.
- **Search answers the question you have.** Not "where is byte 0x48" but
  "which function calls `CreateFileW` and then `WriteFile`, in that order".
- **Conclusions are durable.** Names and comments go into a project database
  and survive re-analysis and restarts, so a second pass starts where the
  first ended.

---

## ✦ Install

Requires Python 3.10+ and Windows for the debugger (static analysis and
emulation work anywhere).

```bash
git clone https://github.com/theodorlucaci/reva
cd reva
pip install -e .
```

Register it with Claude Code:

```bash
claude mcp add reva --scope user -- python -m reva.server
```

Or add it to any MCP client's config:

```json
{
  "mcpServers": {
    "reva": { "command": "python", "args": ["-m", "reva.server"] }
  }
}
```

Project databases are kept in `~/.local/reva/projects/`, keyed by the
binary's name and content hash, so re-opening a binary restores your work and
two builds of the same program never collide.

---

## ✦ A session, end to end

```python
open_binary("C:/samples/thing.exe")
triage()                                   # what is it, where to start
search(kind="behavior", calls=["virtualalloc", "writeprocessmemory"],
       ordered=True)                       # find the injector
decompile("0x140004a20")                   # read it as C
annotate("0x140004a20", name="InjectPayload",
         pre_comment="allocs RWX in the target, copies the stage, CreateRemoteThread")
emulate("0x140002100", args=[b"\x1f\x3e...", 32, {"alloc": 64}])
                                           # run the string decoder, read the plaintext
dbg_start(path="C:/samples/thing.exe")     # go live
dbg_bp("set", at="InjectPayload")
dbg_control("cont")
dbg_inspect("regs")
```

---

## ✦ Tools

| group | tools |
|---|---|
| **Project** | `open_binary` · `project_info` · `analyze` · `triage` · `close_binary` |
| **Listing** | `list_functions` · `list_strings` · `list_symbols` *(imports, exports, names, vtables, jump tables, patches, bookmarks, notes)* |
| **Reading** | `disasm` · `decompile` · `function_info` · `read_data` · `cfg` |
| **Navigation** | `xrefs` · `search` *(bytes · text · immediate · behavior · similar · constants)* |
| **Annotation** | `annotate` · `note` · `make_function` |
| **Emulation** | `emulate` · `emulate_batch` |
| **Patching** | `assemble` · `patch` · `patch_control` |
| **Debugging** | `dbg_start` · `dbg_control` · `dbg_bp` · `dbg_inspect` · `dbg_mem` · `dbg_disasm` · `dbg_exception_policy` · `dbg_stop` |

Any tool taking an address accepts a number, a hex string, a symbol name, an
imported API name, a section name, or any of those plus an offset:
`0x140001000`, `"MessageBoxW"`, `"sub_140001234"`, `".text+0x200"`.

---

## ✦ How function recovery works

On x64 PE, guessing is mostly unnecessary — the binary says where its functions
are. Seeds come from, in order of authority: the entry point, exports, the
`.pdata` unwind table, TLS callbacks, the Control Flow Guard address-taken
table, SEH handler tables. Recursive descent then follows calls and branches,
resolving switch jump tables, and a prologue scan sweeps whatever is left in
executable gaps.

Two things that are easy to get wrong and are handled explicitly:

- **A `.pdata` record's `end` is not a function boundary.** One record can span
  many functions, because separated and cold code share an unwind record. In
  `notepad.exe` a single record covers 45 KB. Function bodies are therefore
  capped at the next *authoritative* start, and a branch to any known function
  start is treated as a tail call however the record reads.
- **MSVC puts switch tables inside `.text`.** The table base typically arrives
  as `lea rdx, [rip - X]` resolving to `__ImageBase`, with the table holding
  int32 deltas from it. Rejecting executable table addresses — the intuitive
  check — silently loses every switch in the binary.

Measured on stock Windows 11 system binaries:

| binary | functions | instructions | time | `.text` coverage |
|---|---|---|---|---|
| `notepad.exe` | 525 | 37,742 | 2.4 s | 94.3 % |
| `kernel32.dll` | 2,742 | 126,368 | 9.1 s | 92 % |

---

## ✦ The pseudo-C lifter

Expression propagation with light control-flow structuring. Across all 3,267
functions in those two binaries it produces output for every one, with 0.1–0.3 %
of lines falling back to verbatim `__asm` — and those are `lock`, `rep`,
`cpuid`, `rdtsc` and `lfence`, which you want to see verbatim anyway.

It is honest about what it is not. From the module's own header:

- A write to a sub-register (`al`, `ax`, `eax`) is modelled as writing the whole
  register. For compiler output that is what the source meant; it is formally
  wrong for 8/16-bit writes intended to preserve the upper bits.
- Each basic block starts from a clean store, so values propagate only within a
  block. Cross-block values appear as plain register names.
- Flags are modelled as "the last comparison", which covers compiler output but
  not hand-written arithmetic-flag tricks.
- There is no type inference. Loads are shown with their access width.
- Anything unmodelled is emitted as `__asm("...")` and its destination
  registers are invalidated, so nothing is ever silently wrong.

Expressions carry a cost budget; past it, a value is materialised into a named
variable. Without that, a shared subtree such as `x = x + x` doubles the tree
each iteration and rendering never terminates.

---

## ✦ Emulation

Imported functions are not executed. Every IAT slot is redirected to a unique
address in a synthetic page of `ret` instructions, so each API call is logged
with its arguments and returns 0, or whatever you set:

```python
emulate("decode_string",
        args=[b"\x08\x3f\x2c...", 19, {"alloc": 64}],
        api_returns={"GetLastError": 5})
# → { "return_value": "0x13",
#     "buffers": [{"ascii": "ReverseEngineering!", ...}],
#     "api_calls": [...], "memory_writes": [...] }
```

Unmapped accesses are backed by zero pages on demand and reported, so one bad
pointer does not abort the run — but a null dereference still faults, and
faults are reported rather than swallowed.

For raw blobs the calling convention cannot be inferred from the file, so pass
`cc="ms64"` or `cc="sysv64"` explicitly.

---

## ✦ Patching

Patches are staged in the project database, never written to the input file.
`patch(at, asm=...)` assembles at the real address so relative branches are
correct, pads with NOPs to the length of the instructions it replaces, and
**refuses** to overrun them rather than corrupting the next instruction.
`patch_control("list")` shows every staged patch with its decode preview;
`patch_control("write", path=...)` produces a new file and verifies the
original bytes still match what was recorded.

PE checksums are not recalculated and signatures become invalid — relevant for
signed binaries.

---

## ✦ UEFI

`.efi` images are PE, but they have no import table: services are reached
through `EFI_SYSTEM_TABLE` and protocols are located by GUID. REVA ships a
table of common protocol GUIDs and labels them where they appear in the image,
along with boot-services and runtime-services table offsets, and `triage()`
reports the entry signature and what to look for.

---

## ✦ Debugging

A live Win32 user-mode debugger in pure `ctypes`. The Win32 debug API is
thread-affine, so the whole session runs on one dedicated worker thread with a
command queue; public methods block on a reply. Software breakpoints rewind
RIP, restore the original byte, step over with the trap flag and re-arm.
Hardware breakpoints use `Dr0`–`Dr3` and are applied to threads created later.
Writes to read-only pages change protection and restore it.

Known limits, by design:

- **x64 only.** WOW64 and 32-bit debuggees are unsupported; `state()` reports
  `wow64` so you can refuse the target.
- **`backtrace()` walks the RBP chain**, which x64 frame-pointer omission
  defeats. Correct unwinding needs `.pdata`/`UNWIND_INFO` and is not
  implemented.
- **`step_over` recognises only real call opcodes** (`E8`, `FF /2`, `FF /3`,
  `9A`). On anything else — including `rep movsb` — it behaves like `step`.
- A single `0xCC` per breakpoint means another thread can slip past the address
  during the trap-flag step-over. `list_bps()[i]["pending_rearm"]` tells you
  when you are in that window.
- `C:\Windows\System32\notepad.exe` on Windows 11 is a launcher stub that
  re-launches the Store app as a separate process outside the debug session.
  Poor attach target; not a defect.

---

## ✦ Project layout

```
src/reva/
  image.py      flat virtual address space over the loaded image
  loader.py     PE/COFF/UEFI parsing; raw blobs
  db.py         SQLite project database
  disasm.py     Capstone wrapper, normalised instruction model
  analysis.py   function recovery, CFG, xrefs, jump tables, fingerprints
  scan.py       strings, MSVC RTTI, vtables, UEFI GUIDs, algorithm tables
  apiinfo.py    API categories, crypto constants, protocol GUIDs
  render.py     annotated output tuned for a limited context window
  lifter.py     pseudo-C
  emu.py        Unicorn emulation with API interception
  patcher.py    Keystone assembler, staged patches
  search.py     byte/text/immediate/behaviour/similarity search
  triage.py     first-look report
  session.py    ties a binary to its project database
  server.py     MCP server
  debug/        live Win32 debugger
```

---

## ✦ Running the tests

```bash
pip install -e ".[dev]"
pytest
```

Tests that need Windows system binaries or the debugger skip themselves
elsewhere.

---

## ✦ Status and license

Alpha, and honest about it: the lifter is not a decompiler, there is no type
system yet, and ARM support is loader-and-disassembler only. ELF and Mach-O are
detected but load as raw.

MIT. See [LICENSE](LICENSE).

---

<div align="center">

### ★ If REVA saved you an afternoon, drop a star — it costs you nothing and makes the next person find it ★

<a href="https://github.com/theodorlucaci/reva/stargazers">
  <img src="https://img.shields.io/github/stars/theodorlucaci/reva?style=for-the-badge&logo=github&color=f5a623&logoColor=white&labelColor=1a1a1a" alt="stars" />
</a>
<a href="https://github.com/theodorlucaci/reva/network/members">
  <img src="https://img.shields.io/github/forks/theodorlucaci/reva?style=for-the-badge&logo=github&color=7A3BFF&logoColor=white&labelColor=1a1a1a" alt="forks" />
</a>
<a href="https://github.com/theodorlucaci/reva/issues">
  <img src="https://img.shields.io/github/issues/theodorlucaci/reva?style=for-the-badge&logo=github&color=22c55e&logoColor=white&labelColor=1a1a1a" alt="issues" />
</a>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1F8EFA,100:7A3BFF&height=100&section=footer" />

</div>
