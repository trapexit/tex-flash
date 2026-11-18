# SPDX-License-Identifier: GPL-2.0-or-later
"""Save the bootloader's readable metadata before issuing an erase."""

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


def _encode(fields: dict) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")


@dataclass(frozen=True)
class Backup:
    anchor: str
    info: str
    metadata: str
    transfer_sha256: str

    def save(self, path: Path) -> None:
        fields = asdict(self)
        record = {"version": 1, "fields": fields, "sha256": hashlib.sha256(_encode(fields)).hexdigest()}
        # Both the contents and directory entry must survive a crash before erase.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(_encode(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @classmethod
    def load(cls, path: Path) -> "Backup":
        try:
            with path.open("rb") as stream:
                raw = stream.read(8193)
            if len(raw) > 8192:
                raise ValueError("file too large")
            record = json.loads(raw)
            fields = record["fields"]
            if record["version"] != 1 or hashlib.sha256(_encode(fields)).hexdigest() != record["sha256"]:
                raise ValueError("unrecognized format or incorrect digest")
            saved = cls(**fields)
            for value, size in ((saved.info, 64), (saved.metadata, 180), (saved.transfer_sha256, 32)):
                if len(value) != size * 2 or len(bytes.fromhex(value)) != size:
                    raise ValueError("invalid field size")
            if not isinstance(saved.anchor, str) or not saved.anchor:
                raise ValueError("missing USB port identity")
            if bytes.fromhex(saved.metadata) == b"\xff" * 180:
                raise ValueError("saved metadata is erased")
            return saved
        except (TypeError, KeyError, ValueError) as exc:
            raise ValueError(f"Invalid recovery file {path}: {exc}") from exc

    def restore(self, current: "Backup") -> bytes:
        # The final eight bytes in the 64-byte info report are HID padding.
        if (self.anchor != current.anchor or self.info[:112] != current.info[:112]
                or self.transfer_sha256 != current.transfer_sha256):
            raise ValueError("Recovery file does not match this USB port, bootloader info and image")
        saved = bytes.fromhex(self.metadata)
        # After an interrupted write, bytes may be unchanged or still erased. Anything
        # else could belong to another board: never replace it from this file.
        if any(now not in (old, 0xFF) for now, old in zip(bytes.fromhex(current.metadata), saved)):
            raise ValueError("Device metadata conflicts with the recovery file")
        return saved
