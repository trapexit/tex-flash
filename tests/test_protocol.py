# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the entire 64-byte IAP exchange; all device data is synthetic."""

import hashlib
import struct
import unittest
from dataclasses import dataclass, replace

from tex_flash.models import Model
from tex_flash.protocol import inspect, program


def report(op, sub, body=b""):
    if len(body) > 60:
        raise AssertionError("Fixture would truncate")
    return struct.pack("<BB2x60s", op, sub, body)


def fake_info(model=Model.SHURA):
    data = bytearray(report(0x12, 0, bytes(range(60))))
    if model is Model.SHINOBI:
        data[8:24] = bytes.fromhex("00000000 d9040714 00510404 ffffffff")
    else:
        data[8:24] = bytes.fromhex("00000000 d9043215 c0510404 ffffffff")
    struct.pack_into("<H", data, 24, 1)
    struct.pack_into("<HHH", data, 36, 512, 231, 512)
    return bytes(data)


INFO = fake_info()
METADATA = bytes(range(180))
SHINOBI_INFO = fake_info(Model.SHINOBI)


def shinobi_metadata(version="V1.04.04"):
    data = bytearray(METADATA)
    data[:2] = b"\x1a\x00"
    data[4:22] = (version + "\0").encode("utf-16le")
    data[144:148] = bytes.fromhex("d9040704")
    data[176:178] = b"\xa5\x5a"
    return bytes(data)


def descending_words(size):
    # Distinct full words, with a sum large enough to require a 32-bit reduction.
    return b"".join(struct.pack("<I", 0xFFFFFFFF - i) for i in range(size // 4))


TRANSFER = descending_words(27964)
SHINOBI_TRANSFER = descending_words(28076)
SHINOBI_METADATA = shinobi_metadata()


@dataclass(frozen=True)
class Exchange:
    name: str
    request: bytes
    reply: bytes
    timeout: float = 0.5


def metadata_reads(metadata, stage):
    return [Exchange(f"{stage}-{i}", report(0x12, 32 + i),
                     report(0x12, 32 + i, metadata[60 * i:60 * (i + 1)])) for i in range(3)]


def reads(info=INFO, metadata=METADATA):
    return [Exchange("info", report(0x12, 0), info)] + metadata_reads(metadata, "pre")


def writes(data, start, stage):
    result = []
    for pos in range(0, len(data), 52):
        chunk = data[pos:pos + 52]
        result.append(Exchange(f"{stage}-{pos // 52}", report(0x1F, len(chunk), chunk),
                               report(0x1E, 2, struct.pack("<I", start + pos + len(chunk)))))
    return result


def transaction(transfer=TRANSFER, live=METADATA, saved=METADATA, *, model=Model.SHURA):
    n = len(transfer) // 4
    # Both supported fixtures are the descending sequence UINT32_MAX, MAX-1, ...
    checksum = (-(n * (n + 1) // 2)) % (2**32)
    info = SHINOBI_INFO if model is Model.SHINOBI else INFO
    get_zero = ([Exchange("get-meta", report(0x1E, 0, b"\xff" * 4), report(0x1E, 0))]
                if model is Model.SHINOBI else [])
    return (reads(info, live) + [
        Exchange("erase", report(0x1D, 0, bytes.fromhex("00000000 00ce0100")), report(0x1D, 0), 11),
        Exchange("set-app", report(0x1E, 1, b"\x00\x02\x00\x00"), report(0x1E, 1), 1),
        Exchange("get-app", report(0x1E, 0, b"\xff" * 4), report(0x1E, 0, b"\x00\x02\x00\x00")),
    ] + writes(transfer, 512, "app") + [
        Exchange("checksum", report(0x1D, 1, struct.pack("<II", 512, len(transfer))),
                 report(0x1D, 1, struct.pack("<I", checksum))),
        Exchange("set-meta", report(0x1E, 1), report(0x1E, 1), 1),
    ] + get_zero + writes(saved, 0, "meta") + metadata_reads(saved, "post"))


class Responder:
    def __init__(self, case, script):
        self.case = case
        self.script = script
        self.sent = 0
        self.events = []
        self.requests = []

    def exchange(self, payload, *, timeout):
        step = self.script[self.sent]
        self.sent += 1
        self.case.assertEqual(payload, step.request, step.name)
        self.case.assertEqual(timeout, step.timeout, step.name)
        self.events.append(step.name)
        self.requests.append(payload)
        return step.reply

    def on_erase(self):
        self.events.append("on_erase")

    def return_application(self):
        self.case.assertEqual(self.sent, len(self.script))
        self.events.append("return")


class ProtocolTests(unittest.TestCase):
    def test_inspection_returns_wire_and_exactly_three_pages(self):
        for metadata in (METADATA, b"\xff" * 180):
            s = Responder(self, reads(metadata=metadata))
            self.assertEqual(inspect(s, TRANSFER), (INFO, metadata))
            self.assertEqual(s.events, ["info", "pre-0", "pre-1", "pre-2"])

    def test_stock_length_and_full_block_length(self):
        n = len(TRANSFER) // 4
        extended = TRANSFER + b"".join(struct.pack("<I", 0xFFFFFFFF - i) for i in range(n, n + 3))
        for transfer in (TRANSFER, extended):
            with self.subTest(length=len(transfer)):
                script = transaction(transfer)
                s = Responder(self, script)
                program(s, transfer, INFO, METADATA, s.on_erase)
                events = [e.name for e in script]
                events.insert(4, "on_erase")
                self.assertEqual(s.events, events + ["return"])
                self.assertEqual(s.sent, 554)

    def test_recovery_rechecks_live_but_restores_saved_bytes(self):
        damaged = b"\xff" * 180
        s = Responder(self, transaction(live=damaged, saved=METADATA))
        program(s, TRANSFER, INFO, damaged, s.on_erase, restore_metadata=METADATA)
        self.assertEqual(s.events[-1], "return")

    def test_live_metadata_is_not_skipped_in_recovery(self):
        s = Responder(self, reads())
        with self.assertRaisesRegex(ValueError, "Metadata"):
            program(s, TRANSFER, INFO, b"\xff" * 180, s.on_erase, restore_metadata=METADATA)
        self.assertEqual(s.events, ["info", "pre-0"])

    def test_rejects_malformed_inputs_without_io(self):
        for transfer in (b"", bytes(52), bytes(27960), bytes(27968), bytes(0x1FC00 - 0x3200 + 4),
                         bytearray(TRANSFER)):
            s = Responder(self, [])
            with self.subTest(size=len(transfer)), self.assertRaises(ValueError):
                inspect(s, transfer)
            self.assertEqual(s.events, [])
        for info, meta, saved in ((INFO[:-1], METADATA, None), (INFO, METADATA[:-1], None),
                                  (INFO, METADATA, b"\xff" * 181)):
            s = Responder(self, [])
            with self.assertRaises(ValueError):
                program(s, TRANSFER, info, meta, s.on_erase, restore_metadata=saved)
            self.assertEqual(s.events, [])

    def test_pins_compatibility_layout_and_each_geometry_word(self):
        for offset in (*range(8, 26), *range(36, 42)):
            bad = bytearray(INFO)
            bad[offset] ^= 1
            s = Responder(self, reads(info=bytes(bad)))
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                inspect(s, TRANSFER)
            self.assertEqual(s.events, ["info"])
        # Even an identical erase product isn't the supported device profile.
        bad = bytearray(INFO)
        struct.pack_into("<HHH", bad, 36, 256, 462, 512)
        s = Responder(self, reads(info=bytes(bad)))
        with self.assertRaises(ValueError):
            inspect(s, TRANSFER)
        self.assertEqual(s.events, ["info"])

    def test_info_and_metadata_mismatch_stop_before_erase(self):
        for stage, offset in (("info", 55), ("pre-0", 4), ("pre-2", 63)):
            with self.subTest(stage=stage):
                self.assert_stops_at(stage, lambda r: flip(r, offset))

    def test_unspecified_info_padding_is_not_compared(self):
        script = transaction()
        script[0] = replace(script[0], reply=flip(INFO, 56))
        s = Responder(self, script)
        program(s, TRANSFER, INFO, METADATA, s.on_erase)
        self.assertEqual(s.events[-1], "return")

    def test_erase_callback_failure_sends_no_erase(self):
        s = Responder(self, reads())

        def fail():
            raise OSError("cannot save recovery state")

        with self.assertRaises(OSError):
            program(s, TRANSFER, INFO, METADATA, fail)
        self.assertEqual(s.events, ["info", "pre-0", "pre-1", "pre-2"])

    def assert_stops_at(self, stage, corrupt):
        script = transaction()
        index = next(i for i, step in enumerate(script) if step.name == stage)
        script[index] = replace(script[index], reply=corrupt(script[index].reply))
        s = Responder(self, script)
        with self.assertRaises(ValueError):
            program(s, TRANSFER, INFO, METADATA, s.on_erase)
        events = [step.name for step in script[:index + 1]]
        if "erase" in events:
            events.insert(4, "on_erase")
        self.assertEqual(s.events, events)

    def test_short_wrong_header_nak_or_extra_byte_never_continue(self):
        for stage in ("info", "pre-1", "erase", "set-app", "get-app", "app-0", "checksum",
                      "set-meta", "meta-3", "post-2"):
            for name, corrupt in (("short", lambda r: r[:4]), ("NAK", lambda r: b"\xff\xaa" + r[2:]),
                                  ("header", lambda r: flip(r, 3)), ("long", lambda r: r + b"\x00")):
                with self.subTest(stage=stage, fault=name):
                    self.assert_stops_at(stage, corrupt)

    def test_position_checksum_and_readback_predicates(self):
        for stage in ("get-app", "app-0", "app-537", "checksum", "meta-0", "meta-3", "post-0", "post-2"):
            with self.subTest(stage=stage):
                self.assert_stops_at(stage, lambda r: flip(r, 4))


class ShinobiProtocolTests(unittest.TestCase):
    model = Model.SHINOBI

    def test_reference_write_plan_digest_and_readbacks(self):
        s = Responder(self, reads(SHINOBI_INFO, SHINOBI_METADATA))
        self.assertEqual(inspect(s, SHINOBI_TRANSFER, model=self.model), (SHINOBI_INFO, SHINOBI_METADATA))
        script = transaction(SHINOBI_TRANSFER, SHINOBI_METADATA, SHINOBI_METADATA, model=self.model)
        s = Responder(self, script)
        program(s, SHINOBI_TRANSFER, SHINOBI_INFO, SHINOBI_METADATA, s.on_erase, model=self.model)
        self.assertEqual(s.events[:5], ["info", "pre-0", "pre-1", "pre-2", "on_erase"])
        self.assertEqual(s.events[-4:], ["post-0", "post-1", "post-2", "return"])
        # Independent oracle: upstream shinobi/tools/tex_flash.py at bf4a4084,
        # sha256(concat(padded(p) for _, p, _ in plan(transfer, metadata))).
        # plan() excludes metadata reads and includes the final 11 01 restart.
        frames = [p for p in s.requests if p[0] != 0x12] + [report(0x11, 1)]
        self.assertEqual(len(frames), 551)
        self.assertEqual(hashlib.sha256(b"".join(frames)).hexdigest(),
                         "30c37d7fa11e10b248c174a602eba65db25095943e141e11d7d78673c1695a40")

    def test_only_exact_stock_length(self):
        for bad in (TRANSFER, SHINOBI_TRANSFER[:-4], SHINOBI_TRANSFER + bytes(4), bytearray(SHINOBI_TRANSFER)):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                inspect(Responder(self, []), bad, model=self.model)

    def test_geometry_and_compatibility_guard(self):
        for offset in (*range(8, 26), *range(36, 42)):
            bad = flip(SHINOBI_INFO, offset)
            s = Responder(self, reads(bad, SHINOBI_METADATA))
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                inspect(s, SHINOBI_TRANSFER, model=self.model)
            self.assertEqual(s.events, ["info"])
        for info, transfer, model in ((INFO, SHINOBI_TRANSFER, self.model), (SHINOBI_INFO, TRANSFER, Model.SHURA)):
            s = Responder(self, reads(info, SHINOBI_METADATA))
            with self.subTest(model=model), self.assertRaises(ValueError):
                inspect(s, transfer, model=model)
            self.assertEqual(s.events, ["info"])

    def test_invalid_markers_version_or_id_never_admitted_for_restoration(self):
        for bad in [flip(SHINOBI_METADATA, off) for off in (0, 1, 20, 21, 144, 147, 176, 177)] + [
                bytes(180), b"\xff" * 180, shinobi_metadata("V1.03.01")]:
            with self.subTest(bad=bad):
                s = Responder(self, reads(SHINOBI_INFO, bad))
                with self.assertRaises(ValueError):
                    inspect(s, SHINOBI_TRANSFER, model=self.model)
                self.assertEqual(s.events, ["info", "pre-0", "pre-1", "pre-2"])
                for live, restore in ((bad, None), (b"\xff" * 180, bad)):
                    s = Responder(self, [])
                    with self.assertRaises(ValueError):
                        program(s, SHINOBI_TRANSFER, SHINOBI_INFO, live, s.on_erase,
                                restore_metadata=restore, model=self.model)
                    self.assertEqual(s.events, [])

    def test_recovery_admits_partial_live_bytes_only_against_valid_saved_bytes(self):
        partial = SHINOBI_METADATA[:60] + b"\xff" * 120
        for damaged in (partial, b"\xff" * 180):
            s = Responder(self, reads(SHINOBI_INFO, damaged))
            self.assertEqual(inspect(s, SHINOBI_TRANSFER, model=self.model, recovery=True)[1], damaged)
            s = Responder(self, transaction(SHINOBI_TRANSFER, damaged, SHINOBI_METADATA, model=self.model))
            program(s, SHINOBI_TRANSFER, SHINOBI_INFO, damaged, s.on_erase,
                    restore_metadata=SHINOBI_METADATA, model=self.model)
            self.assertEqual(s.events[-1], "return")
        for conflict in (flip(partial, 25), shinobi_metadata("V1.03.01")):
            s = Responder(self, [])
            with self.assertRaisesRegex(ValueError, "conflicts"):
                program(s, SHINOBI_TRANSFER, SHINOBI_INFO, conflict, s.on_erase,
                        restore_metadata=SHINOBI_METADATA, model=self.model)
            self.assertEqual(s.events, [])

    def test_recovery_snapshot_and_zero_pointer_are_checked(self):
        live = b"\xff" * 180
        for stage, off in (("info", 55), ("pre-1", 40), ("get-meta", 4), ("post-2", 63)):
            script = transaction(SHINOBI_TRANSFER, live, SHINOBI_METADATA, model=self.model)
            i = next(i for i, step in enumerate(script) if step.name == stage)
            script[i] = replace(script[i], reply=flip(script[i].reply, off))
            s = Responder(self, script)
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                program(s, SHINOBI_TRANSFER, SHINOBI_INFO, live, s.on_erase,
                        restore_metadata=SHINOBI_METADATA, model=self.model)
            self.assertEqual(s.sent, i + 1)
            self.assertNotIn("return", s.events)
            if stage in ("info", "pre-1"):
                self.assertNotIn("on_erase", s.events)


def flip(data, offset):
    return data[:offset] + bytes([data[offset] ^ 1]) + data[offset + 1:]
