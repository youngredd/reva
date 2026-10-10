"""Flat virtual address space over a loaded binary image."""
from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    foff: int
    fsize: int
    perms: str          # subset of "rwx"
    data: bytes = b""   # exactly vsize bytes (zero padded)

    @property
    def end(self) -> int:
        return self.va + self.vsize

    def contains(self, va: int) -> bool:
        return self.va <= va < self.end

    @property
    def exec(self) -> bool:
        return "x" in self.perms

    @property
    def write(self) -> bool:
        return "w" in self.perms


ARCH_BITS = {"x86_64": 64, "x86": 32, "arm64": 64, "arm": 32, "thumb": 32}


class Image:
    """Read-only view of an image mapped at its preferred base."""

    def __init__(self, path: str, arch: str, base: int, entry: int = 0,
                 fmt: str = "raw", endian: str = "little"):
        self.path = path
        self.arch = arch
        self.bits = ARCH_BITS.get(arch, 64)
        self.base = base
        self.entry = entry
        self.fmt = fmt
        self.endian = endian
        self.sections: list[Section] = []
        self.meta: dict = {}
        self._starts: list[int] = []
        self._ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if self.bits == 64 else "I")

    # ---- construction -------------------------------------------------
    def add_section(self, s: Section) -> None:
        if len(s.data) < s.vsize:
            s.data = s.data + b"\x00" * (s.vsize - len(s.data))
        elif len(s.data) > s.vsize:
            s.data = s.data[: s.vsize]
        self.sections.append(s)

    def finalize(self) -> None:
        self.sections.sort(key=lambda s: s.va)
        self._starts = [s.va for s in self.sections]

    # ---- lookup -------------------------------------------------------
    def section_at(self, va: int) -> Section | None:
        if not self._starts:
            return None
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        s = self.sections[i]
        return s if s.contains(va) else None

    def section_by_name(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def is_valid(self, va: int) -> bool:
        return self.section_at(va) is not None

    def is_exec(self, va: int) -> bool:
        s = self.section_at(va)
        return bool(s and s.exec)

    def perms_at(self, va: int) -> str:
        s = self.section_at(va)
        return s.perms if s else ""

    @property
    def min_va(self) -> int:
        return self.sections[0].va if self.sections else self.base

    @property
    def max_va(self) -> int:
        return self.sections[-1].end if self.sections else self.base

    # ---- addr conversion ----------------------------------------------
    def va_to_off(self, va: int) -> int | None:
        s = self.section_at(va)
        if s is None or s.fsize == 0:
            return None
        d = va - s.va
        return s.foff + d if d < s.fsize else None

    def off_to_va(self, off: int) -> int | None:
        for s in self.sections:
            if s.fsize and s.foff <= off < s.foff + s.fsize:
                return s.va + (off - s.foff)
        return None

    # ---- reads --------------------------------------------------------
    def read(self, va: int, size: int) -> bytes:
        """Read across section boundaries; gaps read as zero, OOB truncates."""
        out = bytearray()
        want = size
        cur = va
        while want > 0:
            s = self.section_at(cur)
            if s is None:
                break
            off = cur - s.va
            n = min(want, s.vsize - off)
            out += s.data[off: off + n]
            cur += n
            want -= n
        return bytes(out)

    def read_exact(self, va: int, size: int) -> bytes | None:
        b = self.read(va, size)
        return b if len(b) == size else None

    def u8(self, va: int) -> int | None:
        b = self.read_exact(va, 1)
        return b[0] if b else None

    def _unpack(self, va: int, fmt: str, size: int):
        b = self.read_exact(va, size)
        if b is None:
            return None
        return struct.unpack(fmt, b)[0]

    def u16(self, va: int):
        return self._unpack(va, "<H" if self.endian == "little" else ">H", 2)

    def u32(self, va: int):
        return self._unpack(va, "<I" if self.endian == "little" else ">I", 4)

    def u64(self, va: int):
        return self._unpack(va, "<Q" if self.endian == "little" else ">Q", 8)

    def i32(self, va: int):
        return self._unpack(va, "<i" if self.endian == "little" else ">i", 4)

    def ptr(self, va: int):
        return self._unpack(va, self._ptr_fmt, self.bits // 8)

    @property
    def ptr_size(self) -> int:
        return self.bits // 8

    def cstr(self, va: int, limit: int = 1024) -> str:
        b = self.read(va, limit)
        i = b.find(b"\x00")
        if i >= 0:
            b = b[:i]
        return b.decode("utf-8", "replace")

    def wstr(self, va: int, limit: int = 2048) -> str:
        b = self.read(va, limit)
        i = 0
        while i + 1 < len(b):
            if b[i] == 0 and b[i + 1] == 0:
                break
            i += 2
        return b[:i].decode("utf-16-le", "replace")

    # ---- scanning -----------------------------------------------------
    def iter_exec_sections(self):
        return (s for s in self.sections if s.exec)

    def find_all(self, needle: bytes, exec_only: bool = False):
        """Yield every VA where `needle` occurs."""
        for s in self.sections:
            if exec_only and not s.exec:
                continue
            start = 0
            while True:
                i = s.data.find(needle, start)
                if i < 0:
                    break
                yield s.va + i
                start = i + 1

    def __repr__(self) -> str:
        return (f"<Image {self.fmt} {self.arch} base=0x{self.base:x} "
                f"entry=0x{self.entry:x} sections={len(self.sections)}>")
