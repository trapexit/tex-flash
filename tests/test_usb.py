# SPDX-License-Identifier: GPL-2.0-or-later
"""All USB topology, reports, node opens and readiness events below are synthetic."""

import hashlib
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tex_flash import usb


def write_fields(path, **fields):
    path.mkdir(parents=True, exist_ok=True)
    for key, value in fields.items():
        (path / key).write_text(value + "\n", encoding="utf-8")


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

    def device(self, port, pid, name, serial="serial-for-test"):
        path = self.root / "controller" / "usb2" / port
        write_fields(path, idVendor="04d9", idProduct=pid, product=name, serial=serial,
                     manufacturer="TEX", busnum="2", devnum="13")
        (self.bus / port).symlink_to(path)
        return usb._device(path)

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
        for usage, count, opcode in ((b"\x06\x00\xff\x09\x01", 64, 0x11),
                                     (b"\x06\x60\xff\x09\x61", 32, 0xf1)):
            # Construct the public QMK RawReport shape, independently of the digest table.
            def report(usage_id, main_item):
                return bytes((9, usage_id, 0x15, 0, 0x26, 255, 0, 0x95, count,
                              0x75, 8, main_item, 2))
            descriptor = usage + bytes((0xa1, 1)) + report(0x62, 0x81) + report(0x63, 0x91) + b"\xc0"
            (hid / "report_descriptor").write_bytes(descriptor)
            ep = usb._endpoint(dev)
            self.assertEqual((ep.size, ep.restart), (count, bytes((opcode, 0))))
            (hid / "report_descriptor").write_bytes(descriptor[:-1])
            with self.assertRaisesRegex(ValueError, "descriptor"):
                usb._endpoint(dev)

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
