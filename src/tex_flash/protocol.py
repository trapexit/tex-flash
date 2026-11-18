# SPDX-License-Identifier: GPL-2.0-or-later
"""Shura IAP protocol on an already identified and anchored session."""

import struct
from collections.abc import Callable, Iterator

from .image import BLOCK_SIZE, MAX_TRANSFER, SLOT_SIZE


# Model/compatibility fields compared by the Shura 0.18 updater (trailer[0:16]).
_COMPATIBILITY = struct.pack("<IHHII", 0, 0x04D9, 0x1532, 0x040451C0, 0xFFFFFFFF)
# The only observed loader geometry: erase factors and application pointer in
# protocol units. These do not establish physical flash bounds.
_SHURA_GEOMETRY = (512, 231, 512)
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
        raise ValueError(f"Shura refused command (expected {header.hex(' ')})")
    if reply[:4] != header:
        raise ValueError(f"Unexpected reply header {reply[:4].hex(' ')}; expected {header.hex(' ')}")


def _exchange(session, request: bytes, *, timeout: float = 0.5, header: bytes | None = None) -> bytes:
    reply = session.exchange(request, timeout=timeout)
    _check_reply(reply, request[:4] if header is None else header)
    return reply


def _check_transfer(transfer: bytes) -> None:
    if not isinstance(transfer, bytes):
        raise ValueError("Transfer must be immutable bytes")
    length = len(transfer)
    if not (SLOT_SIZE <= length <= MAX_TRANSFER and length % 4 == 0
            and (length == SLOT_SIZE or length % BLOCK_SIZE == 0)):
        raise ValueError("Unexpected Shura transfer length or block alignment")


def validate_model(info: bytes) -> None:
    """Check the Shura model and layout fields shared by stock and IAP info."""
    _check_reply(info, _INFO_HEADER)
    if info[8:24] != _COMPATIBILITY or struct.unpack_from("<H", info, 24)[0] != 1:
        raise ValueError("Incompatible Shura model or layout")


def _geometry(info: bytes, length: int) -> tuple[int, int]:
    validate_model(info)
    unit, count, pointer = struct.unpack_from("<HHH", info, 0x24)
    if (unit, count, pointer) != _SHURA_GEOMETRY:
        raise ValueError("Unsupported Shura erase factors or application pointer")
    extent = unit * count
    if pointer < _METADATA_SIZE or pointer + length > extent:
        raise ValueError("Application transfer overlaps metadata or exceeds erase extent")
    return pointer, extent


def _metadata_pages(session) -> Iterator[bytes]:
    for index in range(3):
        yield _exchange(session, _frame(0x12, 0x20 + index))[4:]


def _check_metadata(data: bytes) -> None:
    if not isinstance(data, bytes) or len(data) != _METADATA_SIZE:
        raise ValueError("Expected exactly 180 saved metadata bytes")


def _verify_metadata(session, expected: bytes) -> None:
    for index, page in enumerate(_metadata_pages(session)):
        if page != expected[index * _PAGE_DATA:(index + 1) * _PAGE_DATA]:
            raise ValueError(f"Metadata mismatch in page {index}")


def inspect(session, transfer: bytes) -> tuple[bytes, bytes]:
    """Read and validate info and the three readable IAP metadata pages; no writes."""
    _check_transfer(transfer)
    info = _exchange(session, _frame(0x12, 0))
    _geometry(info, len(transfer))
    return info, b"".join(_metadata_pages(session))


def _write_blocks(session, start: int, data: bytes) -> None:
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        reply = _exchange(session, _frame(0x1F, len(block), block), header=_WRITE_ACK)
        if _WORD.unpack_from(reply, 4)[0] != start + offset + len(block):
            raise ValueError(f"Wrong write completion pointer at offset {start + offset:#x}")


def program(session, transfer: bytes, info: bytes, metadata: bytes, on_erase: Callable[[], None],
            *, restore_metadata: bytes | None = None) -> None:
    """Recheck live state, erase once, program and verify, then return to application.

    ``metadata`` always denotes the just-inspected state. For explicit recovery the
    caller may separately supply the previously saved bytes to restore. No failure
    path retries, erases again or requests a mode change.
    """
    _check_transfer(transfer)
    pointer, extent = _geometry(info, len(transfer))
    _check_metadata(metadata)
    saved = metadata if restore_metadata is None else restore_metadata
    _check_metadata(saved)
    checksum = sum(word for (word,) in _WORD.iter_unpack(transfer)) & 0xFFFFFFFF

    live_info = _exchange(session, _frame(0x12, 0))
    # The device defines 52 data bytes at offsets 4..55; the rest is HID padding.
    if live_info[4:56] != info[4:56]:
        raise ValueError("Shura information changed since inspection; not erasing")
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
        raise ValueError("Shura application checksum mismatch")
    _exchange(session, _frame(0x1E, 1, _WORD.pack(0)), timeout=1.0)
    _write_blocks(session, 0, saved)
    _verify_metadata(session, saved)
    try:
        session.return_application()
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        raise ApplicationReturnError("Could not restart the verified application") from exc
