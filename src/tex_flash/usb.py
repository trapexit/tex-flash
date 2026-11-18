# SPDX-License-Identifier: GPL-2.0-or-later
"""Linux hidraw transport for supported TEX keyboards. No report capture or replay."""

import fcntl
import hashlib
import os
import re
import select
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

from .models import Model
from .protocol import validate_metadata, validate_model

_USB_BUS = Path("/sys/bus/usb/devices")
_HIDRAW = Path("/sys/class/hidraw")
_MOUNTINFO = Path("/proc/self/mountinfo")
_BLOCK_DEVICES = Path("/sys/dev/block")
_USB_PORT = re.compile(r"([0-9]+)-([1-9][0-9]*(?:\.[1-9][0-9]*)*)")
_QMK_NAMES = {Model.SHURA: {"Shura", "Shura experimental"}, Model.SHINOBI: {"Shinobi"}}
# Exact fingerprints of the unnumbered reports, not just their usage prefix.
_STOCK_RAW = "23e33901919ad6b26a0321a9637b177734d7d7a40d6167fb37811fa2c7a017e7"
_IAP_KEYBOARD = "816047140f3c21b699dbf4c15ebe253abc5c1e2a72bbf53ff7397d796ca76a8e"
# Stock 4.04 (flash 0x9b94) and released Shinobi QMK v1.2 (0x9cb2)
# both have raw interface 1, but distinct complete report descriptors.
_QMK_TEX_RAW = "7fe330b991174d7584ea423fcbbd4b58479de2f3dc0827305244aafc057c2945"
_QMK_RAW = {
    # FF00/01, 64-byte TEX raw HID; FF60/61, 32-byte Shura VIA raw HID.
    _QMK_TEX_RAW: (64, b"\x11\x00"),
    "b464b2658e8e41b89af847112efa3c3059c330864e10094425c0b92d55e24d89": (32, b"\xf1\x00"),
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").removesuffix("\n")


def _optional(path: Path) -> str | None:
    try:
        return _text(path)
    except FileNotFoundError:
        return None


def _anchor(path: Path) -> str:
    port = _USB_PORT.fullmatch(path.name)
    root = next((p for p in path.parents if re.fullmatch(r"usb[0-9]+", p.name)), None)
    if not port or root is None or root.name != "usb" + port[1]:
        raise ValueError("Unknown USB controller/port ancestry")
    return f"{root.parent}:{port[2]}"


@dataclass(frozen=True)
class _Device:
    path: Path
    vid: str
    pid: str
    name: str | None
    manufacturer: str | None
    serial: str | None = field(repr=False)
    bus: int
    number: int
    model: Model = Model.SHURA
    revision: str | None = None

    @property
    def mode(self) -> str | None:
        if self.vid == "04d9":
            if self.pid == self.model.iap_pid:
                return "iap"
            if self.pid == self.model.app_pid:
                if (self.name in _QMK_NAMES[self.model] and self.manufacturer == "TEX"
                        and (self.model is Model.SHURA or self.revision == "0900")):
                    return "qmk"
                if (self.name == "USB-HID Keyboard" and self.serial
                        and (self.model is Model.SHURA or self.revision == "0410")):
                    return "stock"
        return None


def _device(path: Path, *, model: Model = Model.SHURA) -> _Device:
    bus, number = (int(_text(path / key)) for key in ("busnum", "devnum"))
    if not path.name.startswith(f"{bus}-") or number <= 0:
        raise ValueError("Inconsistent USB enumeration identity")
    return _Device(path, _text(path / "idVendor"), _text(path / "idProduct"),
                   _optional(path / "product"), _optional(path / "manufacturer"),
                   _optional(path / "serial"), bus, number, model, _optional(path / "bcdDevice"))


def _devices(anchor: str | None = None, *, model: Model = Model.SHURA) -> Iterator[_Device]:
    for entry in _USB_BUS.iterdir():
        if not _USB_PORT.fullmatch(entry.name):  # exclude interfaces and root hubs
            continue
        path = entry.resolve(strict=True)
        if anchor is not None:
            if _anchor(path) != anchor:
                continue
        elif (_text(path / "idVendor"), _text(path / "idProduct")) not in {
                ("04d9", model.app_pid), ("04d9", model.iap_pid)}:
            continue
        yield _device(path, model=model)


def _select(serial: str | None, *, model: Model = Model.SHURA) -> _Device:
    if serial is not None and (not isinstance(serial, str) or not serial or serial != serial.strip()):
        raise ValueError("Specify the exact nonempty stock USB serial, including leading zeroes")
    if serial is None:
        matches = [d for d in _devices(model=model) if d.mode in {"qmk", "iap"}]
    else:
        matches = [d for d in _devices(model=model) if d.mode == "stock" and d.serial == serial]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one matching {model.title}, found {len(matches)}; "
                         "stock firmware requires its exact --serial")
    return matches[0]


@dataclass(frozen=True)
class _Endpoint:
    device: _Device
    hid: Path
    interface: int
    node: Path
    rdev: int
    digest: str
    size: int
    restart: bytes


class _Pending(FileNotFoundError):
    """Expected enumeration state not yet visible; no request has been sent."""


def _endpoint(device: _Device) -> _Endpoint:
    mode, model = device.mode, device.model
    if mode is None or _device(device.path, model=model) != device:
        raise ValueError("Selected USB identity changed")
    found = []
    for entry in _HIDRAW.iterdir():
        hid = (entry / "device").resolve(strict=True)
        if not hid.is_relative_to(device.path):
            continue
        # A child behind a USB hub is a separate USB device, not this endpoint.
        owner = next((p for p in hid.parents if (p / "idVendor").is_file()), None)
        if owner != device.path:
            continue
        interface = hid.parent
        if (interface.parent != device.path or entry.resolve(strict=True) != hid / "hidraw" / entry.name
                or not re.fullmatch(r"hidraw[0-9]+", entry.name)):
            raise ValueError("Unexpected USB/hidraw interface ancestry")
        number = int(_text(interface / "bInterfaceNumber"), 16)
        if mode == "stock" and number != 1:
            continue
        fields = dict(line.split("=", 1) for line in _text(hid / "uevent").splitlines() if "=" in line)
        if (_text(interface / "bInterfaceClass").lower() != "03"
                or fields.get("HID_ID", "").upper() != f"0003:000004D9:0000{device.pid.upper()}"):
            raise ValueError("USB and HID interface identities disagree")
        descriptor = (hid / "report_descriptor").read_bytes()
        digest = hashlib.sha256(descriptor).hexdigest()
        if mode == "iap" and digest == _IAP_KEYBOARD and (model is Model.SHINOBI or number == 0):
            continue  # never open keyboard input
        if mode == "qmk":
            profile = _QMK_RAW.get(digest)
            if profile is None or (model is Model.SHINOBI and (digest != _QMK_TEX_RAW or number != 1)):
                if descriptor.startswith((b"\x06\x00\xff\x09\x01", b"\x06\x60\xff\x09\x61")):
                    raise ValueError(f"Unrecognized {model.title} QMK raw descriptor or interface")
                continue
            size, restart = profile
        else:
            # The Shinobi reference selects its IAP vendor page, not an
            # interface number. Require the full stock 64-byte report shape;
            # never fall back to a keyboard or an unknown sole interface.
            if digest != _STOCK_RAW or (model is Model.SHURA and number != 1):
                raise ValueError(f"Unrecognized {model.title} vendor interface or descriptor")
            size, restart = 64, b"\x11\x01" if mode == "iap" else b"\x11\x00"
        dev = _text(entry / "dev")
        if not re.fullmatch(r"[0-9]+:[0-9]+", dev):
            raise ValueError("Invalid hidraw device number")
        major, minor = map(int, dev.split(":"))
        found.append(_Endpoint(device, hid, number, Path("/dev") / entry.name, os.makedev(major, minor),
                               digest, size, restart))
    if not found:
        if mode == "qmk":
            raise _Pending(f"No supported QMK raw endpoint; hold Escape while connecting the {model.title}")
        raise _Pending(f"The {model.title} vendor hidraw endpoint is not present")
    if len(found) != 1:
        raise ValueError(f"Ambiguous {model.title} vendor interfaces")
    return found[0]


_T = TypeVar("_T")


def _wait(probe: Callable[[], _T], seconds: float) -> _T:
    deadline = time.monotonic() + seconds
    while True:
        try:
            return probe()
        except FileNotFoundError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for USB enumeration: {exc}") from exc
            time.sleep(min(0.1, remaining))


def _successor(before: _Device, modes: set[str]) -> _Device:
    model = before.model
    matches = list(_devices(_anchor(before.path), model=model))
    if not matches or matches == [before]:
        raise _Pending("The original port has not re-enumerated")
    if len(matches) != 1:
        raise ValueError("Ambiguous USB identity on the original port")
    device = matches[0]
    if ((device.vid, device.pid) == ("04d9", model.app_pid)
            and (not device.name or (device.name in _QMK_NAMES[model] and not device.manufacturer)
                 or (device.name == "USB-HID Keyboard" and not device.serial)
                 or (model is Model.SHINOBI and not device.revision))):
        raise _Pending("Application USB identity attributes have not appeared")
    if (device.mode not in modes or device.model is not model
            or (device.bus, device.number) == (before.bus, before.number)):
        raise ValueError("Unexpected USB identity on the original port")
    return device


def _require_unmounted(device: _Device) -> None:
    # Check mounted disks and individual partitions. Do not unmount anything.
    for line in _MOUNTINFO.read_bytes().splitlines():
        fields = line.split()
        if len(fields) < 7 or b"-" not in fields or not re.fullmatch(rb"[0-9]+:[0-9]+", fields[2]):
            raise ValueError("Cannot establish mount state; refusing mode change")
        block = _BLOCK_DEVICES / fields[2].decode("ascii")
        try:
            child = block.resolve(strict=True)
        except FileNotFoundError:  # pseudo-filesystem, not a Linux block device
            continue
        if child.is_relative_to(device.path):
            raise ValueError(f"Unmount the {device.model.title} configuration disk before changing mode")


class _Channel:
    def __init__(self, endpoint: _Endpoint):
        self.endpoint = endpoint
        self.fd: int | None = None

    def _check(self) -> int:
        if self.fd is None:
            raise ValueError("HID session is closed")
        info = os.fstat(self.fd)
        if (not stat.S_ISCHR(info.st_mode) or info.st_rdev != self.endpoint.rdev
                or _endpoint(self.endpoint.device) != self.endpoint):
            raise ValueError("Opened hidraw node no longer matches the selected endpoint")
        return self.fd

    def __enter__(self) -> "_Channel":
        # udev often creates the node before logind grants the active user access.
        deadline = time.monotonic() + 5.0
        while True:
            if _endpoint(self.endpoint.device) != self.endpoint:
                raise ValueError("Selected HID endpoint changed before open")
            try:
                self.fd = os.open(self.endpoint.node, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
                break
            except (FileNotFoundError, PermissionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        try:
            fd = self._check()
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("Another process owns this keyboard's hidraw session") from exc
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _send(self, payload: bytes, timeout: float) -> float:
        if type(payload) is not bytes or len(payload) != self.endpoint.size:
            raise ValueError("Invalid HID report length or type")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ValueError("HID timeout must be in (0, 30] seconds")
        deadline = time.monotonic() + timeout
        fd = self._check()
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([], [fd], [], left)[1]:
            raise TimeoutError("Timed out before writing HID report")
        self._check()
        if time.monotonic() >= deadline:
            raise TimeoutError("HID write deadline elapsed; nothing sent")
        if os.write(fd, b"\x00" + payload) != len(payload) + 1:
            raise OSError("Short hidraw write; not retrying")
        if time.monotonic() > deadline:
            raise TimeoutError("HID write exceeded its deadline; not retrying")
        return deadline

    def exchange(self, payload64: bytes, timeout: float = 1.0) -> bytes:
        try:
            if self.endpoint.size != 64 or not isinstance(payload64, bytes) or payload64[:1] == b"\x11":
                raise ValueError("Expected a 64-byte command with a reply")
            deadline = self._send(payload64, timeout)
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.fd], [], [], left)[0]:
                raise TimeoutError("Timed out waiting for HID reply; not retrying")
            reply = os.read(self.fd, 65)
            if time.monotonic() > deadline:
                raise TimeoutError("HID reply exceeded its deadline")
            header = b"\x1e\x02\x00\x00" if payload64[0] == 0x1f else payload64[:4]
            if len(reply) != 64 or reply[:2] == b"\xff\xaa" or reply[:4] != header:
                raise ValueError("Bootloader refused the command or returned an unexpected HID reply")
            self._check()
            return reply
        except BaseException:
            self.close()  # poisoned session: no recovery write or continuation
            raise

    def change_mode(self) -> None:
        try:
            _require_unmounted(self.endpoint.device)
            self._send(self.endpoint.restart.ljust(self.endpoint.size, b"\x00"), 1.0)
        finally:
            self.close()  # disconnect is expected; never read or retry this report


def _stock_metadata(channel: _Channel, *, model: Model) -> bytes:
    def query(subcommand: int) -> bytes:
        return channel.exchange(bytes((0x12, subcommand)) + bytes(62))

    validate_model(query(0), model=model)
    selector = query(1)
    if (selector[4] != 4 or int.from_bytes(selector[6:8], "little") > 7
            or (model is Model.SHINOBI and selector[4:8] != b"\x04\x00\x02\x00")):
        raise ValueError("Unexpected stock record selector")
    data = b"".join(query(subcommand)[4:] for subcommand in range(0x20, 0x28))
    if data[180:] != b"\xff" * 300:
        raise ValueError("The stock metadata has a non-erased tail that cannot be restored")
    metadata = data[:180]
    validate_metadata(metadata, model=model)
    return metadata


class BootloaderSession:
    """One pinned IAP endpoint. Context exit only closes; it never resets the device."""

    def __init__(self, channel: _Channel, app_metadata: bytes | None, stock_serial: str | None):
        self._channel = channel
        self._stock_serial = stock_serial
        self._returned = False
        self.anchor = _anchor(channel.endpoint.device.path)
        self.app_metadata = app_metadata

    def exchange(self, payload64: bytes, timeout: float = 1.0) -> bytes:
        return self._channel.exchange(payload64, timeout)

    def return_application(self) -> None:
        self._channel.change_mode()
        self._returned = True

    def wait_application(self) -> str:
        if not self._returned:
            self._channel.close()
            raise ValueError("Application return was not sent")
        device = _wait(lambda: _successor(self._channel.endpoint.device, {"stock", "qmk"}), 15.0)
        if device.mode == "stock" and self._stock_serial is not None and device.serial != self._stock_serial:
            raise ValueError("Returned stock serial differs from the selected device")
        if device.mode == "stock" or device.model is Model.SHINOBI:
            _wait(lambda: _endpoint(device), 5.0)
        return f"{device.mode} {device.vid}:{device.pid}"


@contextmanager
def open_bootloader(serial: str | None = None, *, iap_only: bool = False,
                    model: Model = Model.SHURA) -> Iterator[BootloaderSession]:
    """Select only the requested model. Recovery never restarts an application."""
    original = _select(serial, model=model)
    if iap_only and original.mode != "iap":
        raise ValueError(f"Recovery requires a {model.title} already in its bootloader")
    _anchor(original.path)  # require a usable anchor before issuing any request
    endpoint = _wait(lambda: _endpoint(original), 5.0)
    metadata = None
    if original.mode != "iap":
        with _Channel(endpoint) as app:
            # Released Shinobi QMK implements the same read-only queries as
            # stock. Check its version block too, before requesting any reset.
            if original.mode == "stock" or model is Model.SHINOBI:
                metadata = _stock_metadata(app, model=model)
            app.change_mode()
        iap = _wait(lambda: _successor(original, {"iap"}), 15.0)
        endpoint = _wait(lambda: _endpoint(iap), 5.0)
    with _Channel(endpoint) as channel:
        yield BootloaderSession(channel, metadata, serial)
