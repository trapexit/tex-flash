# SPDX-License-Identifier: GPL-2.0-or-later
"""Command-line interface for the Linux TEX Shura flasher."""

import argparse
import hashlib
import sys
from pathlib import Path

from . import protocol
from .backup import Backup
from .image import load_image
from .usb import open_bootloader


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tex-flash", description="Check or install firmware for a TEX Shura on Linux.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="validate the firmware files without accessing USB")
    flash = commands.add_parser("flash", help="erase and program the connected keyboard")
    for command in (check, flash):
        command.add_argument("--updater", type=Path, required=True, help="official AP_0532_0.18_20230914.exe")
        image = command.add_mutually_exclusive_group(required=True)
        image.add_argument("--stock", action="store_true", help="use the Shura 0.18 application from the updater")
        image.add_argument("--bin", type=Path, help="TEX Shura QMK .bin from your build (requires --elf)")
        command.add_argument("--elf", type=Path, help="unstripped .elf from the same QMK build")
    flash.add_argument("--serial", help="select a keyboard running stock firmware by its exact USB serial")
    backup = flash.add_mutually_exclusive_group(required=True)
    backup.add_argument("--backup", type=Path, help="save device metadata to a NEW file before erasing")
    backup.add_argument("--resume-from", type=Path, help="use this run’s saved metadata after an interrupted flash")
    return parser


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if (args.bin is None) != (args.elf is None):
        parser.error("supply both --bin and --elf for QMK, or only --stock for TEX firmware")
    if args.command == "flash" and args.resume_from and args.serial is not None:
        parser.error("recovery requires a keyboard already in the bootloader; omit --serial")
    erase_started = False
    transfer_verified = False

    def before_erase():
        nonlocal erase_started
        print("Erasing and programming the Shura. Keep USB connected.", file=sys.stderr, flush=True)
        erase_started = True

    try:
        transfer = load_image(args.updater, args.bin, args.elf)
        digest = hashlib.sha256(transfer).hexdigest()
        print(f"Validated {'TEX Shura 0.18' if args.stock else 'Shura QMK'}: "
              f"{len(transfer)} transfer bytes, SHA-256 {digest}", flush=True)
        if args.command == "check":
            return 0
        recovery = Backup.load(args.resume_from) if args.resume_from else None
        if recovery and recovery.transfer_sha256 != digest:
            raise ValueError("Recovery file is for a different image; no device accessed")
        if args.backup and args.backup.exists():
            raise ValueError(f"Backup file already exists: {args.backup}. Choose a new name for a new flash")
        with open_bootloader(args.serial, iap_only=recovery is not None) as session:
            info, metadata = protocol.inspect(session, transfer)
            current = Backup(session.anchor, info.hex(), metadata.hex(), digest)
            if session.app_metadata is not None and session.app_metadata != metadata:
                raise ValueError("Stock application and bootloader metadata disagree; nothing erased")
            if recovery:
                original = recovery.restore(current)
            else:
                if metadata == b"\xff" * 180:
                    raise ValueError("Device metadata is erased. Use the recovery file from the interrupted flash")
                current.save(args.backup)
                print(f"Saved device metadata: {args.backup}", file=sys.stderr, flush=True)
                original = metadata
            protocol.program(session, transfer, info, metadata, before_erase, restore_metadata=original)
            transfer_verified = True
            returned = session.wait_application()
            expected = "stock 04d9:0532" if args.stock else "qmk 04d9:0532"
            if returned != expected:
                raise ValueError(f"Expected {expected} to start, saw {returned}")
            print(f"Transfer and metadata verified. Application returned: {returned}")
        return 0
    except (ValueError, OSError, KeyboardInterrupt) as exc:
        print(f"tex-flash: {exc or 'interrupted'}", file=sys.stderr)
        if transfer_verified or isinstance(exc, protocol.ApplicationReturnError):
            print("The image and metadata were verified, but return to normal operation was not confirmed. "
                  "Check the USB connection before considering another flash.", file=sys.stderr)
        elif erase_started:
            print(f"Erase may have started. Keep the same keyboard connected to the same port. "
                  f"Keep {args.backup or args.resume_from} and see ‘Interrupted flash’ in the README.", file=sys.stderr)
        return 1
