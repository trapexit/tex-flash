# SPDX-License-Identifier: GPL-2.0-or-later
import json
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tex_flash.backup import Backup


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.saved = Backup("controller/port", "00" * 64, "01" * 180, "ab" * 32)

    def test_recover_partial_write_only_on_matching_board_and_image(self):
        partial = replace(self.saved, info="00" * 56 + "ff" * 8, metadata="01" * 52 + "ff" * 128)
        self.assertEqual(self.saved.restore(partial), b"\x01" * 180)
        for changed in (replace(partial, anchor="other port"), replace(partial, transfer_sha256="00" * 32),
                        replace(partial, metadata="02" * 180), replace(partial, info="01" * 64)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.saved.restore(changed)

    def test_backup_cannot_be_overwritten_and_detects_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "device.backup.json"
            self.saved.save(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                replace(self.saved, metadata="ff" * 180).save(path)
            self.assertEqual(Backup.load(path), self.saved)
            damaged = json.loads(path.read_bytes())
            damaged["fields"]["metadata"] = "00" * 180
            path.write_text(json.dumps(damaged))
            with self.assertRaisesRegex(ValueError, "digest"):
                Backup.load(path)
