"""Binary loaders. PE/COFF (incl. UEFI images) is first class; raw blobs supported."""
from __future__ import annotations

import hashlib
import math
import os
import struct
from collections import Counter

import pefile

from .image import Image, Section

MACHINE_ARCH = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "arm64",
    0x01C0: "arm",
    0x01C4: "thumb",
    0x01C2: "thumb",
    0x0200: "ia64",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

SUBSYSTEM = {
    0: "unknown", 1: "native", 2: "windows_gui", 3: "windows_cui",
    5: "os2_cui", 7: "posix_cui", 8: "native_windows", 9: "wince_gui",
    10: "efi_application", 11: "efi_boot_service_driver",
    12: "efi_runtime_driver", 13: "efi_rom", 14: "xbox",
    16: "windows_boot_application",
}

DLL_CHARACTERISTICS = {
    0x0020: "high_entropy_va", 0x0040: "dynamic_base", 0x0080: "force_integrity",
    0x0100: "nx_compat", 0x0200: "no_isolation", 0x0400: "no_seh",
    0x0800: "no_bind", 0x1000: "appcontainer", 0x2000: "wdm_driver",
    0x4000: "guard_cf", 0x8000: "terminal_server_aware",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


class LoadResult:
    def __init__(self, image: Image):
        self.image = image
        self.imports: list[dict] = []       # {va, dll, name, ordinal, kind}
        self.exports: list[dict] = []       # {va, name, ordinal, forwarder}
        self.func_hints: list[dict] = []    # {va, source, end?}
        self.relocs: list[int] = []         # VAs holding a relocated pointer
        self.notes: list[str] = []


def detect_format(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(0x1000)
    if head[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0] if len(head) > 0x40 else 0
        if 0 < e_lfanew < len(head) - 4 and head[e_lfanew:e_lfanew + 4] == b"PE\0\0":
            return "pe"
        return "mz"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if len(head) >= 2 and struct.unpack_from("<H", head, 0)[0] in MACHINE_ARCH:
        return "coff"
    return "raw"


# ---------------------------------------------------------------- PE ----
def load_pe(path: str) -> LoadResult:
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
    ])

    machine = pe.FILE_HEADER.Machine
    arch = MACHINE_ARCH.get(machine, "x86_64")
    base = pe.OPTIONAL_HEADER.ImageBase
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    img = Image(path, arch, base, base + entry_rva if entry_rva else 0, fmt="pe")

    raw = pe.__data__
    raw = bytes(raw) if not isinstance(raw, bytes) else raw

    # headers are mapped at the image base
    hdr_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    img.add_section(Section("HEADER", base, hdr_size, 0, min(hdr_size, len(raw)),
                            "r", raw[:hdr_size]))

    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", "replace") or ".unnamed"
        ch = s.Characteristics
        perms = ""
        if ch & 0x40000000:
            perms += "r"
        if ch & 0x80000000:
            perms += "w"
        if ch & 0x20000000:
            perms += "x"
        if not perms:
            perms = "r"
        vsize = s.Misc_VirtualSize or s.SizeOfRawData
        foff, fsize = s.PointerToRawData, s.SizeOfRawData
        data = raw[foff: foff + fsize] if fsize else b""
        img.add_section(Section(name, base + s.VirtualAddress, vsize, foff, len(data),
                                perms, data))
    img.finalize()

    res = LoadResult(img)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    is_dll = bool(fh.Characteristics & 0x2000)
    subsystem = SUBSYSTEM.get(oh.Subsystem, str(oh.Subsystem))

    with open(path, "rb") as f:
        filedata = f.read()

    img.meta.update({
        "format": "pe",
        "pe_plus": oh.Magic == 0x20B,
        "machine": hex(machine),
        "arch": arch,
        "bits": img.bits,
        "image_base": base,
        "entry": img.entry,
        "entry_rva": entry_rva,
        "size_of_image": oh.SizeOfImage,
        "subsystem": subsystem,
        "is_dll": is_dll,
        "is_driver": subsystem in ("native", "native_windows"),
        "is_efi": subsystem.startswith("efi"),
        "timestamp": fh.TimeDateStamp,
        "checksum": oh.CheckSum,
        "dll_characteristics": [v for k, v in DLL_CHARACTERISTICS.items()
                                if oh.DllCharacteristics & k],
        "file_size": len(filedata),
        "md5": hashlib.md5(filedata).hexdigest(),
        "sha256": hashlib.sha256(filedata).hexdigest(),
        "imphash": _safe(lambda: pe.get_imphash()),
        "entropy": round(entropy(filedata), 3),
        "sections": [
            {"name": s.name, "va": s.va, "vsize": s.vsize, "fsize": s.fsize,
             "perms": s.perms, "entropy": round(entropy(s.data[:s.fsize] if s.fsize else b""), 3)}
            for s in img.sections
        ],
    })

    # ---- entry / exports -------------------------------------------
    if img.entry:
        res.func_hints.append({"va": img.entry, "source": "entry"})

    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp:
        img.meta["export_dll_name"] = _bs(getattr(exp.struct, "Name", None) and
                                          pe.get_string_at_rva(exp.struct.Name))
        for e in exp.symbols:
            if e.address is None:
                continue
            va = base + e.address
            name = _bs(e.name) or f"ord_{e.ordinal}"
            fwd = _bs(e.forwarder)
            res.exports.append({"va": va, "name": name, "ordinal": e.ordinal,
                                "forwarder": fwd})
            if not fwd and img.is_exec(va):
                res.func_hints.append({"va": va, "source": "export"})

    # ---- imports ----------------------------------------------------
    for attr, kind in (("DIRECTORY_ENTRY_IMPORT", "import"),
                       ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay_import")):
        for mod in getattr(pe, attr, []) or []:
            dll = (_bs(mod.dll) or "?").lower()
            for imp in mod.imports or []:
                if imp.address is None:
                    continue
                res.imports.append({
                    "va": imp.address,            # VA of the IAT slot
                    "dll": dll,
                    "name": _bs(imp.name) or f"ord_{imp.ordinal}",
                    "ordinal": imp.ordinal,
                    "kind": kind,
                })

    # ---- TLS callbacks ---------------------------------------------
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls and getattr(tls.struct, "AddressOfCallBacks", 0):
        cb = tls.struct.AddressOfCallBacks
        for i in range(64):
            p = img.ptr(cb + i * img.ptr_size)
            if not p:
                break
            if img.is_exec(p):
                res.func_hints.append({"va": p, "source": "tls_callback"})
    # ---- .pdata: the big one on x64 --------------------------------
    res.func_hints += _parse_pdata(pe, img, res)

    # ---- load config: SEH handler table / CFG guard functions ------
    _parse_load_config(pe, img, res)

    # ---- relocations -----------------------------------------------
    for b in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        for r in b.entries:
            if r.type in (3, 10) and r.rva:   # HIGHLOW / DIR64
                res.relocs.append(base + r.rva)

    # ---- debug info (PDB path is gold) -----------------------------
    pdbs = []
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        ent = getattr(d, "entry", None)
        p = _bs(getattr(ent, "PdbFileName", None)) if ent else None
        if p:
            pdbs.append(p.rstrip("\x00"))
    if pdbs:
        img.meta["pdb"] = pdbs

    rich = _safe(lambda: pe.parse_rich_header())
    if rich:
        img.meta["rich_header_xor_key"] = rich.get("checksum")

    # ---- overlay ----------------------------------------------------
    ov = _safe(lambda: pe.get_overlay_data_start_offset())
    if ov:
        img.meta["overlay"] = {"offset": ov, "size": len(filedata) - ov,
                               "entropy": round(entropy(filedata[ov:]), 3)}

    if img.meta["is_efi"]:
        res.notes.append("UEFI image: no classic imports, services reached via "
                         "EFI_SYSTEM_TABLE and protocol GUIDs")
    pe.close()
    return res


def _parse_pdata(pe, img: Image, res: LoadResult) -> list[dict]:
    """RUNTIME_FUNCTION table -> precise function bounds on x64/ARM64."""
    out: list[dict] = []
    sec = img.section_by_name(".pdata")
    if sec is None:
        try:
            d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]      # EXCEPTION
            if d.VirtualAddress and d.Size:
                va, size = img.base + d.VirtualAddress, d.Size
            else:
                return out
        except Exception:
            return out
    else:
        va, size = sec.va, sec.fsize or sec.vsize

    if img.arch == "x86_64":
        n = size // 12
        for i in range(n):
            p = va + i * 12
            beg, end, unw = img.u32(p), img.u32(p + 4), img.u32(p + 8)
            if not beg or beg == 0xFFFFFFFF:
                continue
            fva = img.base + beg
            if not img.is_exec(fva):
                continue
            rec = {"va": fva, "source": "pdata"}
            if end and end > beg:
                rec["end"] = img.base + end
            out.append(rec)
            # chained unwind info points at the parent function
            if unw:
                uva = img.base + unw
                flags_ver = img.u8(uva)
                if flags_ver is not None and (flags_ver >> 3) & 0x4:   # CHAININFO
                    cnt = img.u8(uva + 2) or 0
                    cp = uva + 4 + ((cnt + 1) & ~1) * 2
                    pbeg = img.u32(cp)
                    if pbeg and img.is_exec(img.base + pbeg):
                        out.append({"va": img.base + pbeg, "source": "pdata_chain"})
    elif img.arch == "arm64":
        n = size // 8
        for i in range(n):
            p = va + i * 8
            beg = img.u32(p)
            if not beg:
                continue
            fva = img.base + beg
            if img.is_exec(fva):
                out.append({"va": fva, "source": "pdata"})
    res.notes.append(f".pdata: {len(out)} runtime-function records")
    return out


def _parse_load_config(pe, img: Image, res: LoadResult) -> None:
    lc = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if not lc:
        return
    st = lc.struct
    # x86 SEH handler table
    tbl = getattr(st, "SEHandlerTable", 0)
    cnt = getattr(st, "SEHandlerCount", 0)
    if tbl and cnt and cnt < 0x10000:
        for i in range(cnt):
            rva = img.u32(tbl + i * 4)
            if rva and img.is_exec(img.base + rva):
                res.func_hints.append({"va": img.base + rva, "source": "seh_handler"})
    # CFG guard address-taken IAT / function table
    gf = getattr(st, "GuardCFFunctionTable", 0)
    gn = getattr(st, "GuardCFFunctionCount", 0)
    gflags = getattr(st, "GuardFlags", 0)
    if gf and gn and gn < 0x100000:
        stride = 4 + ((gflags >> 28) & 0xF)
        for i in range(gn):
            rva = img.u32(gf + i * stride)
            if rva and img.is_exec(img.base + rva):
                res.func_hints.append({"va": img.base + rva, "source": "guard_cf"})
        res.notes.append(f"guard CF table: {gn} address-taken functions")


# --------------------------------------------------------------- raw ----
def load_raw(path: str, arch: str = "x86_64", base: int = 0) -> LoadResult:
    with open(path, "rb") as f:
        data = f.read()
    img = Image(path, arch, base, 0, fmt="raw")
    img.add_section(Section("raw", base, len(data), 0, len(data), "rwx", data))
    img.finalize()
    img.meta.update({
        "format": "raw", "arch": arch, "bits": img.bits, "image_base": base,
        "file_size": len(data), "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(entropy(data), 3),
        "sections": [{"name": "raw", "va": base, "vsize": len(data),
                      "fsize": len(data), "perms": "rwx",
                      "entropy": round(entropy(data), 3)}],
    })
    return LoadResult(img)


def load(path: str, arch: str | None = None, base: int | None = None) -> LoadResult:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    fmt = detect_format(path)
    if fmt in ("pe", "mz"):
        try:
            return load_pe(path)
        except Exception as e:
            r = load_raw(path, arch or "x86", base or 0)
            r.notes.append(f"PE parse failed ({e}); loaded as raw")
            return r
    return load_raw(path, arch or "x86_64", base or 0)


# ------------------------------------------------------------ helpers ---
def _bs(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None
