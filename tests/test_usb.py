# SPDX-License-Identifier: GPL-2.0-or-later
"""All USB topology, reports, node opens and readiness events below are synthetic."""

import hashlib
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tex_flash import usb
from tex_flash.models import Model


def write_fields(path, **fields):
    path.mkdir(parents=True, exist_ok=True)
    for key, value in fields.items():
        (path / key).write_text(value + "\n", encoding="utf-8")


def raw_descriptor(*, qmk=False, via=False):
    """Build unnumbered vendor Input and Output reports using HID short items."""
    usage = b"\x06\x60\xff\x09\x61" if via else b"\x06\x00\xff\x09\x01"
    count = 32 if via else 64
    fields = bytes((0x95, count, 0x75, 8)) if qmk else bytes((0x75, 8, 0x95, count))

    def report(usage_id, main_item):
        return bytes((9, usage_id, 0x15, 0, 0x26, 255, 0)) + fields + bytes((main_item, 2))

    base = 0x62 if qmk else 2
    return usage + bytes((0xa1, 1)) + report(base, 0x81) + report(base + 1, 0x91) + b"\xc0"


class TopologyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bus = self.root / "usb-devices"
        self.hidraw = self.root / "hidraw"
        self.bus.mkdir()
        self.hidraw.mkdir()
        for attr, value in (("_USB_BUS", self.bus), ("_HIDRAW", self.hidraw)):
            p = patch.object(usb, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def device(self, port, pid, name, serial="serial-for-test", *, model=Model.SHURA, revision="0000"):
        path = self.root / "controller" / "usb2" / port
        write_fields(path, idVendor="04d9", idProduct=pid, product=name, serial=serial,
                     manufacturer="TEX", busnum="2", devnum="13", bcdDevice=revision)
        (self.bus / port).symlink_to(path)
        return usb._device(path, model=model)

    def endpoint(self, dev, iface, index, descriptor):
        interface = dev.path / f"{dev.path.name}:1.{iface}"
        write_fields(interface, bInterfaceNumber=f"{iface:02x}", bInterfaceClass="03")
        hid = interface / f"testing-hid-{index}"
        write_fields(hid, uevent=f"HID_ID=0003:000004D9:0000{dev.pid}")
        (hid / "report_descriptor").write_bytes(descriptor)
        node = hid / "hidraw" / f"hidraw{index}"
        write_fields(node, dev=f"243:{index}")
        (node / "device").symlink_to(hid)
        (self.hidraw / node.name).symlink_to(node)
        return hid

    def test_selection_does_not_guess_a_stock_device_or_cross_modes(self):
        stock = self.device("2-1", "0532", "USB-HID Keyboard", "test-007")
        with self.assertRaises(ValueError):
            usb._select(None)
        for serial in ("TEST-007", "test-7", " test-007", ""):
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                usb._select(serial)
        self.assertEqual(usb._select("test-007"), stock)
        qmk = self.device("2-2.1", "0532", "Shura experimental", "qmk-test")
        self.assertEqual(usb._select(None), qmk)
        with self.assertRaises(ValueError):
            usb._select("qmk-test")
        self.device("2-3", "1532", "loader")
        with self.assertRaisesRegex(ValueError, "found 2"):
            usb._select(None)
        self.device("2-4", "0532", "USB-HID Keyboard", "test-007")
        with self.assertRaisesRegex(ValueError, "found 2"):
            usb._select("test-007")

    def test_exact_stock_serial_cannot_select_other_model(self):
        shura = self.device("2-1", "0532", "USB-HID Keyboard", "one")
        shinobi = self.device("2-2", "0407", "USB-HID Keyboard", "two", model=Model.SHINOBI, revision="0410")
        for wanted, other in ((shura, shinobi), (shinobi, shura)):
            with self.subTest(model=wanted.model), patch.object(usb, "_Channel") as channel:
                self.assertEqual(usb._select(wanted.serial, model=wanted.model), wanted)
                with self.assertRaisesRegex(ValueError, "found 0"), usb.open_bootloader(other.serial, model=wanted.model):
                    self.fail("selected the other keyboard")
                channel.assert_not_called()
        write_fields(shinobi.path, bcdDevice="0310")
        with self.assertRaisesRegex(ValueError, "found 0"):
            usb._select(shinobi.serial, model=Model.SHINOBI)

    def test_each_model_recovers_only_its_iap_even_with_both_connected(self):
        shura = self.device("2-1", "1532", "loader")
        shinobi = self.device("2-2", "1407", "loader", model=Model.SHINOBI)
        for index, dev in enumerate((shura, shinobi), 1):
            self.endpoint(dev, 1, index, raw_descriptor())
        for dev in (shura, shinobi):
            with self.subTest(model=dev.model), patch.object(usb, "_Channel") as channel:
                entered = channel.return_value.__enter__.return_value
                entered.endpoint = usb._endpoint(dev)
                with usb.open_bootloader(model=dev.model, iap_only=True):
                    ep = channel.call_args.args[0]
                    self.assertEqual((ep.device, ep.size, ep.restart), (dev, 64, b"\x11\x01"))
                entered.change_mode.assert_not_called()

    def test_shinobi_loader_rejects_unknown_sole_interface(self):
        dev = self.device("2-1", "1407", "loader", model=Model.SHINOBI)
        self.endpoint(dev, 0, 1, raw_descriptor()[:-1])
        with self.assertRaisesRegex(ValueError, "descriptor"):
            usb._endpoint(dev)

    def test_shinobi_app_selection_excludes_bluetooth_and_unknown_names(self):
        self.device("2-1", "2521", "Shinobi", revision="0900")
        self.device("2-2", "0407", "Shura", revision="0900")
        with self.assertRaisesRegex(ValueError, "found 0"):
            usb._select(None, model=Model.SHINOBI)

    def test_shinobi_app_checks_info_version_and_readable_tail_before_reset(self):
        # The two Shinobi package generations share compatibility fields.
        # Even a matching USB revision and selector cannot replace the version check.
        shinobi_info = bytes.fromhex("00000000 d9040714 00510404 ffffffff 0100")
        shura_info = bytes.fromhex("00000000 d9043215 c0510404 ffffffff 0100")
        for index, qmk in enumerate((True, False), 1):
            name, revision = ("Shinobi", "0900") if qmk else ("USB-HID Keyboard", "0410")
            app = self.device(f"2-{index}", "0407", name, model=Model.SHINOBI, revision=revision)
            hid = self.endpoint(app, 1, index, raw_descriptor(qmk=qmk))
            for info, version, tail, error in (
                (shura_info, "V1.04.04", 255, "Incompatible"),
                (shinobi_info, "V1.03.01", 255, "4.04"),
                (shinobi_info, "V1.04.04", 0, "tail"),
                (shinobi_info, "V1.04.04", 255, None),
            ):
                data = bytearray(180) + bytearray([255]) * 300
                data[:2] = b"\x1a\x00"
                data[4:22] = (version + "\0").encode("utf-16le")
                data[0x90:0x94] = b"\xd9\x04\x07\x04"
                data[176:178] = b"\xa5\x5a"
                data[-1] = tail

                def reply(payload):
                    sub = payload[1]
                    if sub == 0:
                        return (payload[:8] + info).ljust(64, b"\x00")
                    if sub == 1:
                        return payload[:4] + bytes.fromhex("04 00 02 00") + bytes(56)
                    self.assertIn(sub, range(0x20, 0x28))
                    start = (sub - 0x20) * 60
                    return payload[:4] + bytes(data[start:start + 60])

                def enter_iap():
                    write_fields(app.path, idProduct="1407", devnum="14")
                    write_fields(hid, uevent="HID_ID=0003:000004D9:00001407")
                    (hid / "report_descriptor").write_bytes(raw_descriptor())

                reset = Mock(side_effect=enter_iap)

                @contextmanager
                def channel(ep):
                    yield Mock(endpoint=ep, exchange=reply, change_mode=reset)

                with self.subTest(qmk=qmk, error=error), patch.object(usb, "_Channel", channel):
                    session = usb.open_bootloader(None if qmk else app.serial, model=Model.SHINOBI)
                    if error:
                        with self.assertRaisesRegex(ValueError, error), session:
                            self.fail("unsafe mode switch")
                        reset.assert_not_called()
                    else:
                        with session as loader:
                            self.assertEqual(loader.app_metadata, bytes(data[:180]))
                            self.assertEqual(loader.anchor, usb._anchor(app.path))
                        reset.assert_called_once_with()

    def test_iap_only_never_opens_or_restarts_an_application(self):
        self.device("2-1", "0532", "USB-HID Keyboard", "test-007")
        self.device("2-2", "0532", "Shura")
        for serial in ("test-007", None):
            with self.subTest(serial=serial), patch.object(usb, "_endpoint") as endpoint:
                with self.assertRaisesRegex(ValueError, "already"), usb.open_bootloader(serial, iap_only=True):
                    self.fail("recovery admitted an application")
                endpoint.assert_not_called()

    def test_mounted_configuration_partition_prevents_reset(self):
        dev = self.device("2-1", "0532", "USB-HID Keyboard")
        blocks = self.root / "block"
        blocks.mkdir()
        partition = dev.path / "block" / "testdisk" / "testdisk1"
        partition.mkdir(parents=True)
        (blocks / "8:17").symlink_to(partition)
        mounts = self.root / "mountinfo"
        with patch.object(usb, "_BLOCK_DEVICES", blocks), patch.object(usb, "_MOUNTINFO", mounts):
            mounts.write_bytes(b"18 5 8:17 / /fake rw - vfat /dev/testdisk1 rw\n")
            ch = usb._Channel(Mock(device=dev))
            with patch.object(ch, "_send") as send, self.assertRaisesRegex(ValueError, "Unmount"):
                try:
                    ch.change_mode()
                finally:
                    send.assert_not_called()
            mounts.write_bytes(b"malformed\n")
            with self.assertRaisesRegex(ValueError, "mount state"):
                usb._require_unmounted(dev)

    def test_iap_recognizes_only_vendor_channel_and_fails_on_ambiguity_or_damage(self):
        dev = self.device("2-1", "1532", "loader")
        test_vendor, test_keyboard = b"test-vendor-interface", b"test-keyboard-interface"
        self.endpoint(dev, 0, 1, test_keyboard)
        hid = self.endpoint(dev, 1, 2, test_vendor)
        with (patch.object(usb, "_STOCK_RAW", hashlib.sha256(test_vendor).hexdigest()),
              patch.object(usb, "_IAP_KEYBOARD", hashlib.sha256(test_keyboard).hexdigest())):
            ep = usb._endpoint(dev)
            self.assertEqual((ep.node.name, ep.size, ep.restart), ("hidraw2", 64, b"\x11\x01"))
            (hid / "report_descriptor").write_bytes(test_vendor + b"!")
            with self.assertRaisesRegex(ValueError, "descriptor"):
                usb._endpoint(dev)
            (hid / "report_descriptor").write_bytes(test_vendor)
            self.endpoint(dev, 1, 3, test_vendor)
            with self.assertRaisesRegex(ValueError, "Ambiguous"):
                usb._endpoint(dev)

    def test_qmk_restart_reports_have_complete_descriptor_guards(self):
        dev = self.device("2-2", "0532", "Shura")
        hid = self.endpoint(dev, 1, 4, b"initial")
        for via, count, opcode in ((False, 64, 0x11), (True, 32, 0xf1)):
            descriptor = raw_descriptor(qmk=True, via=via)
            (hid / "report_descriptor").write_bytes(descriptor)
            ep = usb._endpoint(dev)
            self.assertEqual((ep.size, ep.restart), (count, bytes((opcode, 0))))
            (hid / "report_descriptor").write_bytes(descriptor[:-1])
            with self.assertRaisesRegex(ValueError, "descriptor"):
                usb._endpoint(dev)

    def test_shinobi_qmk_rejects_shura_via_descriptor(self):
        dev = self.device("2-1", "0407", "Shinobi", model=Model.SHINOBI, revision="0900")
        hid = self.endpoint(dev, 1, 1, raw_descriptor(qmk=True))
        ep = usb._endpoint(dev)
        self.assertEqual((ep.size, ep.restart), (64, b"\x11\x00"))
        (hid / "report_descriptor").write_bytes(raw_descriptor(qmk=True, via=True))
        with self.assertRaisesRegex(ValueError, "descriptor"):
            usb._endpoint(dev)

    def test_successor_rejects_other_model_on_selected_port_both_directions(self):
        for port, model, other in (("2-1", Model.SHURA, Model.SHINOBI), ("2-2", Model.SHINOBI, Model.SHURA)):
            with self.subTest(model=model):
                before = self.device(port, model.app_pid, model.title, model=model, revision="0900")
                write_fields(before.path, idProduct=other.iap_pid, devnum="14")
                with self.assertRaisesRegex(ValueError, "Unexpected"):
                    usb._successor(before, {"iap"})
                write_fields(before.path, idProduct=model.iap_pid)
                iap = usb._successor(before, {"iap"})
                write_fields(before.path, idProduct=other.app_pid, product=other.title, devnum="15")
                with self.assertRaisesRegex(ValueError, "Unexpected"):
                    usb._successor(iap, {"stock", "qmk"})

    def test_returned_shinobi_requires_model_and_raw_endpoint(self):
        iap = self.device("2-1.3", "1407", "loader", model=Model.SHINOBI)
        session = usb.BootloaderSession(Mock(endpoint=Mock(device=iap)), None, None)
        session.return_application()
        write_fields(iap.path, idProduct="0407", product="Shinobi", devnum="19", bcdDevice="0900")
        app = usb._device(iap.path, model=Model.SHINOBI)
        hid = self.endpoint(app, 1, 3, raw_descriptor(qmk=True, via=True))
        with self.assertRaisesRegex(ValueError, "descriptor"):
            session.wait_application()
        (hid / "report_descriptor").write_bytes(raw_descriptor(qmk=True))
        self.assertEqual(session.wait_application(), "qmk 04d9:0407")

    def test_wait_requires_new_mode_on_same_controller_port(self):
        iap = self.device("2-1.3", "1532", "loader")
        self.device("2-3", "0532", "Shura")
        self.assertTrue(usb._anchor(iap.path).endswith("controller:1.3"))
        session = usb.BootloaderSession(Mock(endpoint=Mock(device=iap)), None, None)
        with self.assertRaisesRegex(ValueError, "not sent"):
            session.wait_application()
        with self.assertRaises(usb._Pending):
            usb._successor(iap, {"qmk"})
        write_fields(iap.path, idProduct="9999", devnum="14")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            usb._successor(iap, {"qmk"})
        write_fields(iap.path, idProduct="0532", product="Shura", devnum="15")
        session.return_application()
        self.assertEqual(session.wait_application(), "qmk 04d9:0532")
        write_fields(iap.path, product="USB-HID Keyboard")
        session = usb.BootloaderSession(Mock(endpoint=Mock(device=iap)), None, "different-test-serial")
        session.return_application()
        with self.assertRaisesRegex(ValueError, "serial"):
            session.wait_application()

    def test_pinned_fd_verified_locked_and_rechecked_at_udev_open(self):
        dev = self.device("2-1", "1532", "loader")
        descriptor = b"synthetic"
        self.endpoint(dev, 1, 2, descriptor)
        with patch.object(usb, "_STOCK_RAW", hashlib.sha256(descriptor).hexdigest()):
            ep = usb._endpoint(dev)
            for wrong_stat, locked in ((False, False), (True, False), (False, True)):
                info = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=ep.rdev + int(wrong_stat))
                with (self.subTest(wrong_stat=wrong_stat, locked=locked),
                      patch.object(usb.os, "open", side_effect=[PermissionError(), 9]) as opened,
                      patch.object(usb.os, "fstat", return_value=info),
                      patch.object(usb.os, "close") as close,
                      patch.object(usb.time, "sleep"),
                      patch.object(usb.fcntl, "flock", side_effect=BlockingIOError if locked else None) as lock):
                    if wrong_stat or locked:
                        with self.assertRaises(ValueError), usb._Channel(ep):
                            self.fail("opened an unverified or busy endpoint")
                    else:
                        with usb._Channel(ep):
                            lock.assert_called_once_with(9, usb.fcntl.LOCK_EX | usb.fcntl.LOCK_NB)
                    self.assertEqual(opened.call_count, 2)
                    self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
                    close.assert_called_once_with(9)


class EnumerationTests(unittest.TestCase):
    def test_late_strings_are_polled_but_wrong_values_fail_immediately(self):
        iap = usb._Device(Path("/sys/devices/test/usb1/1-2"), "04d9", "1532", None, None, None, 1, 1)
        qmk = replace(iap, pid="0532", number=2, name="Shura", manufacturer="TEX")
        stock = replace(qmk, name="USB-HID Keyboard", serial="test-stock")
        for partial, final in ((replace(qmk, name=None), qmk), (replace(qmk, manufacturer=None), qmk),
                               (replace(stock, serial=None), stock)):
            with (self.subTest(mode=final.mode), patch.object(usb, "_devices", side_effect=[[partial], [final]]),
                  patch.object(usb.time, "sleep") as sleep):
                self.assertEqual(usb._wait(lambda: usb._successor(iap, {"stock", "qmk"}), 1), final)
                sleep.assert_called_once()
        with patch.object(usb, "_devices", return_value=[replace(qmk, manufacturer="other")]):
            with self.assertRaisesRegex(ValueError, "Unexpected"):
                usb._successor(iap, {"qmk"})


class ReportTests(unittest.TestCase):
    def channel(self):
        self.ch = usb._Channel(Mock(size=64, restart=b"\x11\x01"))
        self.ch.fd = 8
        real_check = self.ch._check
        self.check = self.patch(self.ch, "_check", side_effect=lambda: 8 if self.ch.fd == 8 else real_check())
        self.write = self.patch(usb.os, "write", return_value=65)
        self.read = self.patch(usb.os, "read")
        self.close = self.patch(usb.os, "close")
        self.patch(usb.select, "select", side_effect=lambda r, w, e, t: (r, w, e))
        self.patch(usb, "_require_unmounted")
        return self.ch

    def patch(self, obj, name, **kwargs):
        p = patch.object(obj, name, **kwargs)
        result = p.start()
        self.addCleanup(p.stop)
        return result

    def test_chunk_ack_uses_pointer_header_and_mode_change_never_reads(self):
        ch = self.channel()
        payload = b"\x1f\x34" + bytes(62)
        self.read.return_value = b"\x1e\x02" + bytes(62)
        self.assertEqual(ch.exchange(payload), self.read.return_value)
        self.write.assert_called_once_with(8, b"\0" + payload)
        ch.change_mode()
        self.assertEqual(self.write.call_args.args, (8, b"\0\x11\x01" + bytes(62)))
        self.assertEqual(self.read.call_count, 1)
        self.close.assert_called_once_with(8)

    def test_bad_reply_poisons_session_and_short_write_is_never_retried(self):
        for response in (b"\xff\xaa" + bytes(62), bytes(64), b"\x12\0\0\0", None):
            with self.subTest(response=response):
                ch = self.channel()
                self.read.return_value = response
                if response is None:
                    self.write.return_value = 64
                with self.assertRaises((ValueError, OSError)):
                    ch.exchange(b"\x12" + bytes(63))
                self.assertIsNone(ch.fd)
                with self.assertRaisesRegex(ValueError, "closed"):
                    ch.change_mode()
                self.assertEqual(self.write.call_count, 1)
                self.assertEqual(self.read.call_count, int(response is not None))
                self.close.assert_called_once_with(8)
                self.doCleanups()

    def test_endpoint_change_after_write_readiness_sends_nothing(self):
        ch = self.channel()
        self.check.side_effect = [8, ValueError("endpoint changed")]
        with self.assertRaisesRegex(ValueError, "changed"):
            ch.exchange(b"\x12" + bytes(63))
        self.write.assert_not_called()
        self.read.assert_not_called()
        self.close.assert_called_once_with(8)

    def test_invalid_input_is_not_written(self):
        for payload, timeout in ((bytes(63), 1), (bytes(65), 1), (bytes(64), float("nan")),
                                 (bytes(64), 0), (b"\x11\x01" + bytes(62), 1)):
            with self.subTest(size=len(payload), timeout=timeout):
                ch = self.channel()
                with self.assertRaises(ValueError):
                    ch.exchange(payload, timeout)
                self.write.assert_not_called()
                self.doCleanups()

    def test_stock_tail_is_checked_before_mode_change(self):
        stock = usb._Device(Path("/sys/devices/test/usb1/1-2"), "04d9", "0532", "USB-HID Keyboard",
                            "test", "test-serial", 1, 5)
        iap = replace(stock, pid="1532", number=6)
        ep = Mock(device=iap)
        good = bytes(range(180)) + b"\xff" * 300
        for metadata in (good, good[:-1] + b"\xfe"):
            channel = Mock(endpoint=ep)
            def reply(payload):
                sub = payload[1]
                data = (bytes((4,)) + bytes(59) if sub == 1 else bytes(60))
                if sub >= 0x20:
                    start = (sub - 0x20) * 60
                    data = metadata[start:start + 60]
                return payload[:4] + data
            channel.exchange.side_effect = reply
            context = Mock(__enter__=Mock(return_value=channel), __exit__=Mock(return_value=False))
            with (patch.object(usb, "_select", return_value=stock), patch.object(usb, "_endpoint", return_value=ep),
                  patch.object(usb, "_Channel", return_value=context), patch.object(usb, "validate_model"),
                  patch.object(usb, "_successor", return_value=iap) as successor):
                if metadata == good:
                    with usb.open_bootloader(stock.serial) as session:
                        self.assertEqual(session.app_metadata, good[:180])
                    channel.change_mode.assert_called_once_with()
                else:
                    with self.assertRaisesRegex(ValueError, "tail"), usb.open_bootloader(stock.serial):
                        self.fail("non-erased tail was admitted")
                    channel.change_mode.assert_not_called()
                    successor.assert_not_called()
