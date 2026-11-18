# SPDX-License-Identifier: GPL-2.0-or-later
"""Command-line interface for the Linux TEX keyboard flasher."""

import argparse
import hashlib
import sys
from pathlib import Path

from . import protocol
from .backup import Backup
from .image import load_image
from .models import Model
from .usb import open_bootloader


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tex-flash", description="Check or install TEX keyboard firmware on Linux.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="validate the firmware files without accessing USB")
    flash = commands.add_parser("flash", help="erase and program the connected keyboard")
    for command in (check, flash):
        command.add_argument("--model", choices=[m.value for m in Model], default=Model.SHURA.value,
                             help="target keyboard (default: shura)")
        command.add_argument("--updater", type=Path, required=True, help="original TEX updater for the selected model")
        image = command.add_mutually_exclusive_group(required=True)
        image.add_argument("--stock", action="store_true", help="use the stock application from the updater")
        image.add_argument("--bin", type=Path, help="QMK .bin; custom builds also require --elf")
        command.add_argument("--elf", type=Path, help="unstripped .elf from the same QMK build")
    flash.add_argument("--serial", help="select a keyboard running stock firmware by its exact USB serial")
    backup = flash.add_mutually_exclusive_group(required=True)
    backup.add_argument("--backup", type=Path, help="save device metadata to a NEW file before erasing")
    backup.add_argument("--resume-from", type=Path, help="use this run’s saved metadata after an interrupted flash")
    return parser


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    model = Model(args.model)
    if args.elf is not None and args.bin is None:
        parser.error("--elf requires --bin")
    if args.bin is not None and args.elf is None and model is Model.SHURA:
        parser.error("Shura QMK builds require both --bin and --elf")
    if args.command == "flash" and args.resume_from and args.serial is not None:
        parser.error("recovery requires a keyboard already in the bootloader; omit --serial")
    erase_started = False
    transfer_verified = False

    def before_erase():
        nonlocal erase_started
        print(f"Erasing and programming the {model.title}. Keep USB connected.", file=sys.stderr, flush=True)
        erase_started = True

    try:
        transfer = load_image(args.updater, args.bin, args.elf, model=model)
        digest = hashlib.sha256(transfer).hexdigest()
        print(f"Validated TEX {model.title} {model.version if args.stock else 'QMK'}: "
              f"{len(transfer)} transfer bytes, SHA-256 {digest}", flush=True)
        if args.command == "check":
            return 0
        recovery = Backup.load(args.resume_from) if args.resume_from else None
        if recovery and recovery.transfer_sha256 != digest:
            raise ValueError("Recovery file is for a different image; no device accessed")
        if args.backup and args.backup.exists():
            raise ValueError(f"Backup file already exists: {args.backup}. Choose a new name for a new flash")
        with open_bootloader(args.serial, iap_only=recovery is not None, model=model) as session:
            info, metadata = protocol.inspect(session, transfer, model=model, recovery=recovery is not None)
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
            protocol.program(session, transfer, info, metadata, before_erase, restore_metadata=original, model=model)
            transfer_verified = True
            returned = session.wait_application()
            expected = f"{'stock' if args.stock else 'qmk'} 04d9:{model.app_pid}"
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
