# SPDX-License-Identifier: GPL-2.0-or-later
"""TEX IAP protocol on an already identified and anchored session."""

import struct
from collections.abc import Callable, Iterator

from .image import BLOCK_SIZE, MAX_TRANSFER
from .models import Model


# Decoded stock updater trailer[0:16], compared with info[8:24] by
# AP_0532_0.18 and AP_0407_4.04 at 0x404e80. Both select layout 1.
_COMPATIBILITY = {
    Model.SHURA: struct.pack("<IHHII", 0, 0x04D9, 0x1532, 0x040451C0, 0xFFFFFFFF),
    Model.SHINOBI: struct.pack("<IHHII", 0, 0x04D9, 0x1407, 0x04045100, 0xFFFFFFFF),
}
_SHINOBI_VERSION = "V1.04.04\0".encode("utf-16le")
_SHINOBI_APP_ID = struct.pack("<HH", 0x04D9, 0x0407)
_PAGE_DATA = 60
_METADATA_SIZE = 3 * _PAGE_DATA
_WORD = struct.Struct("<I")
_INFO_HEADER = b"\x12\x00\x00\x00"
_WRITE_ACK = b"\x1e\x02\x00\x00"


class ApplicationReturnError(OSError):
    """Flash contents are verified, but the final restart did not complete."""


def _frame(command: int, selector: int, data: bytes = b"") -> bytes:
    # Internal constructors only: two reserved header bytes, no HID report ID.
    return (bytes((command, selector, 0, 0)) + data).ljust(64, b"\x00")


def _check_reply(reply: bytes, header: bytes) -> None:
    if not isinstance(reply, bytes) or len(reply) != 64:
        raise ValueError(f"Expected exactly 64 reply bytes for {header.hex(' ')}")
    if reply[:2] == b"\xff\xaa":
        raise ValueError(f"IAP refused command (expected {header.hex(' ')})")
    if reply[:4] != header:
        raise ValueError(f"Unexpected reply header {reply[:4].hex(' ')}; expected {header.hex(' ')}")


def _exchange(session, request: bytes, *, timeout: float = 0.5, header: bytes | None = None) -> bytes:
    reply = session.exchange(request, timeout=timeout)
    _check_reply(reply, request[:4] if header is None else header)
    return reply


def _check_transfer(transfer: bytes, model: Model) -> None:
    if not isinstance(transfer, bytes):
        raise ValueError("Transfer must be immutable bytes")
    length = len(transfer)
    if model is Model.SHINOBI:
        if length != model.slot_size:
            raise ValueError("Shinobi requires exactly 28,076 transfer bytes")
    elif not (model.slot_size <= length <= MAX_TRANSFER and length % 4 == 0
              and (length == model.slot_size or length % BLOCK_SIZE == 0)):
        raise ValueError("Unexpected Shura transfer length or block alignment")


def validate_model(info: bytes, *, model: Model = Model.SHURA) -> None:
    """Check the selected updater's model and layout fields in app or IAP info."""
    _check_reply(info, _INFO_HEADER)
    if info[8:24] != _COMPATIBILITY[model] or struct.unpack_from("<H", info, 24)[0] != 1:
        raise ValueError(f"Incompatible {model.title} model or layout")


def _geometry(info: bytes, length: int, model: Model) -> tuple[int, int]:
    validate_model(info, model=model)
    unit, count, pointer = struct.unpack_from("<HHH", info, 0x24)
    extent = unit * count
    # Only Shura has a local capture of the individual factors. The Shinobi
    # reference plan pins their product (erase bytes 8..11) and app pointer.
    # These are wire arguments, not evidence of physical flash bounds.
    if model is Model.SHURA and (unit, count) != (512, 231):
        raise ValueError("Unsupported Shura erase factors")
    if extent != 0x1CE00 or pointer != 0x200:
        raise ValueError(f"Unsupported {model.title} erase extent or application pointer")
    if pointer < _METADATA_SIZE or pointer + length > extent:
        raise ValueError("Application transfer overlaps metadata or exceeds erase extent")
    return pointer, extent


def _metadata_pages(session) -> Iterator[bytes]:
    for index in range(3):
        yield _exchange(session, _frame(0x12, 0x20 + index))[4:]


def _check_metadata(data: bytes) -> None:
    if not isinstance(data, bytes) or len(data) != _METADATA_SIZE:
        raise ValueError("Expected exactly 180 saved metadata bytes")


def validate_metadata(data: bytes, *, model: Model = Model.SHURA) -> None:
    """Admit metadata for restoration, not a damaged page read during recovery."""
    _check_metadata(data)
    if model is Model.SHINOBI:
        # Upstream valid_version_block() checks the two markers. Both 3.01 and
        # 4.04 have those and the same compatibility info; admit only the 4.04
        # version and app identifier found in its decoded 180-byte B slot.
        if data[:2] != b"\x1a\x00" or data[-4:-2] != b"\xa5\x5a":
            raise ValueError("Invalid Shinobi metadata markers; cannot restore these bytes")
        if data[4:22] != _SHINOBI_VERSION or data[0x90:0x94] != _SHINOBI_APP_ID:
            raise ValueError("Expected Shinobi 4.04 metadata version and application ID")


def _verify_metadata(session, expected: bytes) -> None:
    for index, page in enumerate(_metadata_pages(session)):
        if page != expected[index * _PAGE_DATA:(index + 1) * _PAGE_DATA]:
            raise ValueError(f"Metadata mismatch in page {index}")


def inspect(session, transfer: bytes, *, model: Model = Model.SHURA, recovery: bool = False) -> tuple[bytes, bytes]:
    """Read info and metadata; only explicit recovery may inspect damaged Shinobi metadata."""
    _check_transfer(transfer, model)
    info = _exchange(session, _frame(0x12, 0))
    _geometry(info, len(transfer), model)
    metadata = b"".join(_metadata_pages(session))
    if not recovery:
        validate_metadata(metadata, model=model)
    return info, metadata


def _write_blocks(session, start: int, data: bytes) -> None:
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        reply = _exchange(session, _frame(0x1F, len(block), block), header=_WRITE_ACK)
        if _WORD.unpack_from(reply, 4)[0] != start + offset + len(block):
            raise ValueError(f"Wrong write completion pointer at offset {start + offset:#x}")


def program(session, transfer: bytes, info: bytes, metadata: bytes, on_erase: Callable[[], None],
            *, restore_metadata: bytes | None = None, model: Model = Model.SHURA) -> None:
    """Recheck live state, erase once, program and verify, then return to application.

    ``metadata`` always denotes the just-inspected state. For explicit recovery the
    caller may separately supply the previously saved bytes to restore. No failure
    path retries, erases again or requests a mode change.
    """
    _check_transfer(transfer, model)
    pointer, extent = _geometry(info, len(transfer), model)
    _check_metadata(metadata)
    saved = metadata if restore_metadata is None else restore_metadata
    validate_metadata(saved, model=model)
    if model is Model.SHINOBI and restore_metadata is not None and any(
            now != old and now != 0xFF for now, old in zip(metadata, saved)):
        raise ValueError("Device metadata conflicts with the Shinobi recovery file")
    checksum = sum(word for (word,) in _WORD.iter_unpack(transfer)) & 0xFFFFFFFF

    live_info = _exchange(session, _frame(0x12, 0))
    # The device defines 52 data bytes at offsets 4..55; the rest is HID padding.
    if live_info[4:56] != info[4:56]:
        raise ValueError(f"{model.title} information changed since inspection; not erasing")
    _verify_metadata(session, metadata)

    erase = _frame(0x1D, 0, struct.pack("<II", 0, extent))
    timeout = max(0.5, extent // 0x2800)
    on_erase()
    _exchange(session, erase, timeout=timeout)
    _exchange(session, _frame(0x1E, 1, _WORD.pack(pointer)), timeout=1.0)
    reply = _exchange(session, _frame(0x1E, 0, b"\xff" * 4))
    if _WORD.unpack_from(reply, 4)[0] != pointer:
        raise ValueError("Wrong application pointer after positioning")
    _write_blocks(session, pointer, transfer)
    reply = _exchange(session, _frame(0x1D, 1, struct.pack("<II", pointer, len(transfer))))
    if _WORD.unpack_from(reply, 4)[0] != checksum:
        raise ValueError(f"{model.title} application checksum mismatch")
    _exchange(session, _frame(0x1E, 1, _WORD.pack(0)), timeout=1.0)
    # Shinobi's recorded sequence (upstream write_steps) reads back both
    # positions. Keep the already qualified Shura sequence unchanged.
    if model is Model.SHINOBI:
        reply = _exchange(session, _frame(0x1E, 0, b"\xff" * 4))
        if _WORD.unpack_from(reply, 4)[0] != 0:
            raise ValueError("Wrong metadata pointer after positioning")
    _write_blocks(session, 0, saved)
    _verify_metadata(session, saved)
    try:
        session.return_application()
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        raise ApplicationReturnError("Could not restart the verified application") from exc
