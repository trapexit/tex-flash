# Copyright 2026 Mauro DiBenedetto (updater slot codec)
# SPDX-License-Identifier: GPL-2.0-or-later
"""Offline admission of Shura V1.00.18 stock or a matching QMK ELF/flat pair."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct


UPDATER_SIZE = 3011348
UPDATER_SHA256 = "1b9678d235cecaa7affea40ff8858a2f5993795b24dd7b7d2a34aa7b193c0f99"
SLOT_OFFSET = 0x2D7A00  # Application A of descriptor 0, in this exact updater only.
SLOT_SIZE = 27964
SLOT_SHA256 = "ea3e6dd68ea6ff98c7689473c05e25df36b9d011207c8d89869396a047c088f9"
KEY_SHA256 = "f16ee8f89ba10701814564614693a13be0a69cd27531de6e88cf380f10922a51"
PLAIN_SHA256 = "b8360aeed3536eeab1469a5890b5ecf948f4b68df24631473ebf149045fbefb9"
BLOCK_SIZE = 52
BASE, APP_END = 0x3200, 0x1FC00
MAX_TRANSFER = APP_END - BASE
RAM_BASE, RAM_END = 0x20000000, 0x20003FE0  # Exclude loader handoff bytes.
_RECORD = slice(0x3BF8 - BASE, 0x3C04 - BASE)

# Offsets (relative to slot A) and lengths of known 0xff bytes in the pinned
# plaintext. There is no full erased block at its end. Together these spans
# cover each phase of the repeating transform, without storing the key.
_FF_SPANS = (
    (0x10, 28), (0x30, 8), (0x6C48, 3), (0xEE1, 2), (0x43AC, 2),
    (0x668E, 2), (0x1CC, 1), (0xA63, 1), (0xA9C, 1), (0xF17, 1),
    (0x1016, 1), (0x1241, 1), (0x524F, 1),
)


def _snapshot(path: Path, limit: int) -> bytes:
    # O_PATH allows checking the inode without opening a device or blocking
    # on a FIFO. Reopen that inode, not the replaceable pathname.
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError(f"{path}: supply a regular file, not a symlink or device")
        if meta.st_size > limit:
            raise ValueError(f"{path}: exceeds the {limit}-byte input limit")
        with open(f"/proc/self/fd/{fd}", "rb") as stream:
            data = stream.read(meta.st_size + 1)
        if len(data) != meta.st_size:
            raise ValueError(f"{path}: file size changed during read; supply a stable file")
        return data
    finally:
        os.close(fd)


def _stock_slot(updater: bytes) -> bytes:
    if len(updater) != UPDATER_SIZE or hashlib.sha256(updater).hexdigest() != UPDATER_SHA256:
        raise ValueError("Supply the original, unmodified Shura V1.00.18 updater executable "
                         f"({UPDATER_SIZE} bytes, SHA-256 {UPDATER_SHA256})")
    # Slot decoder adapted from cyclistmass/tex-qmk, shinobi/tools/build_updater.py,
    # revision bf4a40841d3b3ecd226fc2e0ebb09cdc67b1c7da. The final five-byte
    # group is not swapped when it ends exactly at the end of the slot.
    buf = bytearray(updater[SLOT_OFFSET:SLOT_OFFSET + SLOT_SIZE])
    for i in range(0, len(buf) - 5, 5):
        buf[i], buf[i + 4] = buf[i + 4], buf[i]
    for i in range(0, len(buf) - 1, 2):
        buf[i], buf[i + 1] = buf[i + 1], buf[i]
    slot = bytes((((v - 7) << 4) & 0xF0) | (v >> 4) for v in buf)
    if len(slot) != SLOT_SIZE or hashlib.sha256(slot).hexdigest() != SLOT_SHA256:
        raise ValueError("Decoded Shura application slot has unexpected size or SHA-256")
    return slot


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[i % BLOCK_SIZE] for i, value in enumerate(data))


def _stock_plain(slot: bytes) -> tuple[bytes, bytes]:
    key = bytearray(BLOCK_SIZE)
    for offset, size in _FF_SPANS:
        for i in range(offset, offset + size):
            key[i % BLOCK_SIZE] = slot[i] ^ 0xFF
    if hashlib.sha256(key).hexdigest() != KEY_SHA256:
        raise ValueError("Derived Shura transfer key failed SHA-256 validation")
    key_bytes = bytes(key)
    plain = _xor(slot, key_bytes)
    if hashlib.sha256(plain).hexdigest() != PLAIN_SHA256:
        raise ValueError("Decoded stock Shura application failed SHA-256 validation")
    return plain, key_bytes


_EHDR = struct.Struct("<16sHHIIIIIHHHHHH")
_PHDR = struct.Struct("<8I")
_SHDR = struct.Struct("<10I")
_SYM = struct.Struct("<IIIBBH")
_REQUIRED = {b"keymaps", b"DeviceDescriptor", b"__main_stack_end__", b"__process_stack_end__"}


def _span(data: bytes, off: int, size: int, label: str) -> bytes:
    if not 0 <= off <= off + size <= len(data):
        raise ValueError(f"{label} outside file; supply matching, complete ELF and BIN files")
    return data[off:off + size]


def _name(table: bytes, index: int) -> bytes:
    end = table.find(b"\0", index)
    if end < 0:
        raise ValueError("Invalid ELF string-table offset or unterminated name")
    return table[index:end]


@dataclass(frozen=True)
class _Section:
    name: bytes
    kind: int
    flags: int
    addr: int
    off: int
    size: int


def _elf_inventory(data: bytes):
    h = _EHDR.unpack(_span(data, 0, _EHDR.size, "ELF header"))
    if h[0][:7] != b"\x7fELF\x01\x01\x01" or h[1:4] != (2, 40, 1):
        raise ValueError("Supply the ELF32 little-endian ARM executable from the same QMK build")
    entry, phoff, shoff = h[4:7]
    ehsize, phsize, phnum, shsize, shnum, shnames = h[8:]
    if (ehsize, phsize, shsize) != (_EHDR.size, _PHDR.size, _SHDR.size) or not phnum or shnames >= shnum:
        raise ValueError("Malformed or missing ELF program/section headers")
    programs = _PHDR.iter_unpack(_span(data, phoff, phnum * phsize, "ELF program headers"))
    raw_sections = list(_SHDR.iter_unpack(_span(data, shoff, shnum * shsize, "ELF section headers")))

    def strtab(index: int) -> bytes:
        if index >= shnum or raw_sections[index][1] != 3:
            raise ValueError("Invalid ELF string-table section reference")
        return _span(data, *raw_sections[index][4:6], "ELF string table")

    names = strtab(shnames)
    sections = [_Section(_name(names, s[0]), *s[1:6]) for s in raw_sections]
    symbols = {}
    for s in raw_sections:
        if s[1] != 2:  # SHT_SYMTAB
            continue
        if s[9] != _SYM.size or s[5] % _SYM.size:
            raise ValueError("Invalid ELF symbol-table entry size")
        strings = strtab(s[6])
        for index, value, size, _, _, section in _SYM.iter_unpack(_span(data, s[4], s[5], "ELF symbols")):
            name = _name(strings, index)
            if name not in _REQUIRED or section == 0:
                continue
            if name in symbols:
                raise ValueError(f"Ambiguous ELF symbol {name.decode()}")
            symbols[name] = (value, size, section)
    missing = _REQUIRED - symbols.keys()
    if missing:
        raise ValueError("Supply the unstripped Shura QMK ELF; missing " +
                         ", ".join(sorted(name.decode() for name in missing)))
    return entry, programs, sections, symbols


def _in_memory(start: int, size: int) -> bool:
    return (BASE <= start < start + size <= APP_END or
            RAM_BASE <= start < start + size <= RAM_END)


def _admit_qmk(image: bytes, elf: bytes, stock: bytes) -> None:
    if not _RECORD.stop <= len(image) <= MAX_TRANSFER:
        raise ValueError("Shura QMK BIN does not fit the application region or is truncated")
    if image[_RECORD] != stock[_RECORD]:
        raise ValueError("Shura application record at 0x3bf8 does not match stock")
    entry, programs, sections, symbols = _elf_inventory(elf)
    # Reconstruct the whole flat file. PT_LOAD.p_paddr is the flash address,
    # even when p_vaddr maps initialized data to SRAM. objcopy fills gaps with zero.
    flat = bytearray(len(image))
    loads = []
    for kind, off, vaddr, paddr, filesz, memsz, flags, _ in programs:
        if kind != 1:
            continue
        if filesz > memsz or (memsz and not _in_memory(vaddr, memsz)):
            raise ValueError("ELF load segment exceeds application or handoff-safe SRAM bounds")
        if filesz:
            if not BASE <= paddr < paddr + filesz <= BASE + len(image):
                raise ValueError("ELF flash load segment outside the supplied Shura BIN")
            flat[paddr - BASE:paddr - BASE + filesz] = _span(elf, off, filesz, "ELF load segment")
            loads.append((paddr, paddr + filesz, off, vaddr, flags))
    loads.sort()
    if (not loads or loads[0][0] != BASE or loads[-1][1] != BASE + len(image) or
            any(a[1] > b[0] for a, b in zip(loads, loads[1:])) or flat != image):
        raise ValueError("ELF flash load segments do not reproduce the complete flat BIN; use a matching pair")

    executable = []
    vectors = []
    for s in sections:
        if not s.flags & 2 or not s.size:  # SHF_ALLOC
            continue
        if not _in_memory(s.addr, s.size):
            raise ValueError(f"Allocated ELF section {s.name!r} exceeds flash or handoff-safe SRAM bounds")
        if s.kind == 8:  # SHT_NOBITS: no bytes are loaded from the ELF file.
            if s.flags & 4 or s.name == b".vectors":
                raise ValueError(f"ELF section {s.name!r} requires file-backed flash content")
            continue
        segments = [(start, vaddr, flags) for start, end, off, vaddr, flags in loads
                    if off <= s.off and s.off + s.size <= off + end - start
                    and s.addr == vaddr + s.off - off]
        if len(segments) != 1:
            raise ValueError(f"Allocated ELF section {s.name!r} is not backed by one load segment")
        start, vaddr, flags = segments[0]
        if s.addr < APP_END and start != vaddr:
            raise ValueError(f"Flash section {s.name!r} disagrees with its physical load address")
        if s.flags & 4:
            if s.addr >= APP_END or not flags & 1:
                raise ValueError(f"Executable section {s.name!r} is not executable flash content")
            executable.append((s.addr, s.addr + s.size))
        if s.name == b".vectors":
            vectors.append(s)
    if (len(vectors) != 1 or vectors[0].addr != BASE or vectors[0].kind == 8 or
            not 8 <= vectors[0].size <= len(image) or vectors[0].size % 4):
        raise ValueError("Expected one complete, word-aligned .vectors section at 0x3200")
    stack, reset = struct.unpack_from("<II", image)
    for label, value in (("initial stack", stack), ("ELF main stack", symbols[b"__main_stack_end__"][0]),
                         ("ELF process stack", symbols[b"__process_stack_end__"][0])):
        if value % 8 or not RAM_BASE < value <= RAM_END:
            raise ValueError(f"{label} is misaligned or outside handoff-safe SRAM")
    if not reset or reset != entry:
        raise ValueError("ELF entry must equal the nonzero Thumb reset vector")
    for i, (target,) in enumerate(struct.iter_unpack("<I", image[4:vectors[0].size]), 1):
        if target and (not target & 1 or not any(lo <= (target & ~1) < hi for lo, hi in executable)):
            raise ValueError(f"Vector {i} does not point to Thumb code in executable flash")

    def symbol_bytes(name: bytes, expected_size: int) -> bytes:
        value, size, index = symbols[name]
        if index >= len(sections) or size != expected_size:
            raise ValueError(f"Unexpected ELF section or size for {name.decode()} (expected {expected_size} bytes)")
        s = sections[index]
        if (not s.flags & 2 or s.kind == 8 or not s.addr <= value < value + size <= s.addr + s.size or
                not BASE <= value < value + size <= BASE + len(image)):
            raise ValueError(f"{name.decode()} must be stored in a flash-backed ELF section")
        raw = _span(image, value - BASE, size, name.decode())
        if raw != _span(elf, s.off + value - s.addr, size, name.decode()):
            raise ValueError(f"ELF and BIN disagree on {name.decode()}")
        return raw

    descriptor = symbol_bytes(b"DeviceDescriptor", 18)
    if descriptor[:2] != b"\x12\x01" or struct.unpack_from("<HH", descriptor, 8) != (0x04D9, 0x0532):
        raise ValueError("USB DeviceDescriptor must identify the Shura (04d9:0532)")
    # The builder reports stock-default mapping as informational, not a gate.
    # Custom mappings are valid, but all four 8x11 uint16 layers must exist.
    symbol_bytes(b"keymaps", 4 * 8 * 11 * 2)


def load_image(updater: Path, binary: Path | None = None, elf: Path | None = None) -> bytes:
    """Return device-encoded bytes, without executing the updater or opening USB."""
    if (binary is None) != (elf is None):
        raise ValueError("For QMK supply both the .bin and matching unstripped .elf; for stock supply neither")
    slot = _stock_slot(_snapshot(updater, UPDATER_SIZE))
    if binary is None or elf is None:
        return slot
    stock, key = _stock_plain(slot)
    image = _snapshot(binary, MAX_TRANSFER)
    # Permit debug information, but do not read unbounded files into memory.
    _admit_qmk(image, _snapshot(elf, 64 * 1024 * 1024), stock)
    size = SLOT_SIZE if len(image) <= SLOT_SIZE else (len(image) + BLOCK_SIZE - 1) // BLOCK_SIZE * BLOCK_SIZE
    if size > MAX_TRANSFER:
        raise ValueError("Shura QMK BIN would overlap reserved flash after transfer-block padding")
    return _xor(image.ljust(size, b"\xff"), key)
