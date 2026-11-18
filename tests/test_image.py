# SPDX-License-Identifier: GPL-2.0-or-later
"""Entirely synthetic fixtures. No vendor firmware, transfer key or keyboard needed."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tex_flash import image


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode_slot(slot):
    # Invert the container transform independently: rotate nibbles, add 7
    # modulo 16 to the low nibble, then undo the two group permutations.
    data = bytearray(((v & 15) << 4) | (((v >> 4) + 7) & 15) for v in slot)
    for i in range(0, len(data) - 1, 2):
        data[i], data[i + 1] = data[i + 1], data[i]
    for i in range(0, len(data) - 5, 5):
        data[i], data[i + 4] = data[i + 4], data[i]
    return data


BASE = 0x3200
RAM = 0x20000000
# Not the stock record. The positive fixture takes the record from its own
# hash-pinned simulated slot, rather than shipping any stock firmware bytes.
RECORD = bytes(range(12))


def pair(length=0xA40, *, stack=RAM + 256, pstack=RAM + 512, reset=BASE + 17,
         entry=None, vector=0, record=RECORD, pid=0x0532, keymap_size=704,
         ram_size=512, text_flags=6, data_at=BASE, keymap_name=b"keymaps"):
    """Build a real ELF32 with two load segments, symbols, strings and SRAM NOBITS."""
    flat = bytearray(length)
    struct.pack_into("<III", flat, 0, stack, reset, vector)
    struct.pack_into("<HH", flat, 40, 0x04D9, pid)
    flat[32:34] = b"\x12\x01"
    flat[0x9F8:0xA04] = record
    flat[64] = 0xA5  # custom mapping is allowed

    dataoff = 0x100
    data = bytearray(dataoff) + flat
    names = b"\0.vectors\0.text\0.rodata\0.bss\0.symtab\0.strtab\0.shstrtab\0"
    strings = b"\0__main_stack_end__\0__process_stack_end__\0DeviceDescriptor\0" + keymap_name + b"\0"
    symoff = len(data)
    data.extend(bytes(16))  # ELF null symbol
    for name, address, size, section in [
        (b"__main_stack_end__", RAM + 256, 0, 4), (b"__process_stack_end__", pstack, 0, 4),
        (b"DeviceDescriptor", BASE + 32, 18, 3), (keymap_name, BASE + 64, keymap_size, 3),
    ]:
        data.extend(struct.pack("<IIIBBH", strings.index(name), address, size, 0x11, 0, section))
    stroff = len(data)
    data.extend(strings)
    nameoff = len(data)
    data.extend(names)
    shoff = len(data)
    data.extend(bytes(40))
    for name, kind, flags, addr, off, size, link, entsize in [
        (b".vectors", 1, 2, BASE, dataoff, 12, 0, 0),
        (b".text", 1, text_flags, BASE + 16, dataoff + 16, 16, 0, 0),
        (b".rodata", 1, 2, BASE + 32, dataoff + 32, length - 32, 0, 0),
        (b".bss", 8, 3, RAM, 0, ram_size, 0, 0),
        (b".symtab", 2, 0, 0, symoff, 80, 6, 16),
        (b".strtab", 3, 0, 0, stroff, len(strings), 0, 0),
        (b".shstrtab", 3, 0, 0, nameoff, len(names), 0, 0),
    ]:
        data.extend(struct.pack("<10I", names.index(name), kind, flags, addr, off, size, link, 0, 1, entsize))
    ident = b"\x7fELF\x01\x01\x01".ljust(16, b"\0")
    struct.pack_into("<16sHHIIIIIHHHHHH", data, 0, ident, 2, 40, 1, reset if entry is None else entry,
                     52, shoff, 0, 52, 32, 2, 40, 8, 7)
    struct.pack_into("<8I", data, 52, 1, dataoff, BASE, data_at, length, length, 5, 4)
    struct.pack_into("<8I", data, 84, 1, 0, RAM, RAM, 0, ram_size, 6, 4)
    return bytes(flat), bytes(data)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        root = Path(root.name)
        self.updater, self.binary, self.elf = (root / name for name in ("updater", "image.bin", "image.elf"))
        self.plain = bytearray([255]) * image.SLOT_SIZE
        self.plain[0x9F8:0xA04] = RECORD
        self.key = bytes(range(image.BLOCK_SIZE))
        self.slot = self.xor(self.plain)
        exe = b"synthetic" + encode_slot(self.slot) + b"end"
        self.updater.write_bytes(exe)
        pins = patch.multiple(image, UPDATER_SIZE=len(exe), SLOT_OFFSET=len(b"synthetic"),
                              UPDATER_SHA256=digest(exe), SLOT_SHA256=digest(self.slot),
                              KEY_SHA256=digest(self.key), PLAIN_SHA256=digest(self.plain))
        pins.start()
        self.addCleanup(pins.stop)

    def xor(self, data):
        return bytes(v ^ self.key[i % len(self.key)] for i, v in enumerate(data))

    def inputs(self, *args, **kwargs):
        flat, elf = pair(*args, **kwargs)
        self.binary.write_bytes(flat)
        self.elf.write_bytes(elf)
        return flat

    def qmk(self):
        return image.load_image(self.updater, self.binary, self.elf)

    def test_stock_returns_only_device_encoded_slot(self):
        self.assertEqual(image.load_image(self.updater), self.slot)

    def test_qmk_small_exact_large_and_aligned(self):
        for length, padded in [(0xA40, 27964), (27964, 27964), (27965, 27976), (27976, 27976)]:
            with self.subTest(length=length):
                flat = self.inputs(length)
                self.assertEqual(self.xor(self.qmk()), flat + b"\xff" * (padded - length))

    def test_rounding_must_not_cross_application_end(self):
        self.inputs(image.MAX_TRANSFER)
        with self.assertRaisesRegex(ValueError, "padding"):
            self.qmk()

    def test_one_qmk_file_is_not_a_stock_request(self):
        for binary, elf in [(self.binary, None), (None, self.elf)]:
            with self.assertRaisesRegex(ValueError, "both"):
                image.load_image(self.updater, binary, elf)

    def test_wrong_updater_size_or_hash(self):
        original = self.updater.read_bytes()
        for bad in [original[:-1], b"?" + original[1:]]:
            self.updater.write_bytes(bad)
            with self.assertRaisesRegex(ValueError, "original, unmodified"):
                image.load_image(self.updater)

    def test_slot_key_and_plaintext_independently_pinned(self):
        self.inputs()
        for field in ("SLOT_SHA256", "KEY_SHA256", "PLAIN_SHA256"):
            with self.subTest(field=field), patch.object(image, field, "0" * 64), self.assertRaises(ValueError):
                self.qmk()

    def test_reject_symlink_without_opening_target(self):
        self.binary.symlink_to(self.updater)
        with self.assertRaisesRegex(ValueError, "regular file"):
            image.load_image(self.binary)

    def test_qmk_admission_failures(self):
        for kwargs, expected in [
            ({"record": bytes(12)}, "record"), ({"pstack": RAM + 0x3FE8}, "process stack"),
            ({"stack": RAM + 252}, "initial stack"), ({"pid": 0x1532}, "04d9:0532"),
            ({"keymap_size": 702}, "keymaps"), ({"keymap_name": b"layers"}, "unstripped"),
            ({"reset": 0}, "reset vector"), ({"entry": BASE + 19}, "reset vector"),
            ({"vector": BASE + 16}, "Vector 2"), ({"vector": BASE + 33}, "Vector 2"),
            ({"text_flags": 2}, "Vector 1"), ({"data_at": BASE - 4}, "load segment"),
            ({"ram_size": 0x4000}, "SRAM bounds"),
        ]:
            with self.subTest(kwargs=kwargs):
                self.inputs(**kwargs)
                with self.assertRaisesRegex(ValueError, expected):
                    self.qmk()

    def test_flat_must_match_file_backed_elf_including_extent(self):
        flat = self.inputs()
        for bad in [flat + bytes(4), flat[:-1], flat[:-1] + b"\x01"]:
            with self.subTest(length=len(bad)):
                self.binary.write_bytes(bad)
                with self.assertRaisesRegex(ValueError, "(load segment|complete flat BIN)"):
                    self.qmk()

    def test_malformed_elf_rejected_as_value_error(self):
        self.inputs()
        original = self.elf.read_bytes()
        for bad in [b"", original[:-1], original[:32], original[:50] + b"\xff\xff" + original[52:]]:
            self.elf.write_bytes(bad)
            with self.assertRaises(ValueError):
                self.qmk()
