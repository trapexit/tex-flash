# SPDX-License-Identifier: GPL-2.0-or-later
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tex_flash import cli


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli.main(args)

    def test_check_does_not_open_usb(self):
        with patch.object(cli, "load_image", return_value=b"payload"), patch.object(cli, "open_bootloader") as usb:
            self.assertEqual(0, self.run_cli("check", "--updater", "example", "--stock"))
            usb.assert_not_called()

    def test_erased_metadata_is_not_saved_as_a_new_backup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli, "load_image", return_value=b"payload"), \
                patch.object(cli, "open_bootloader") as usb, patch.object(cli.protocol, "program") as program, \
                patch.object(cli.protocol, "inspect", return_value=(bytes(64), b"\xff" * 180)):
            session = usb.return_value.__enter__.return_value
            session.app_metadata = None
            session.anchor = "test port"
            backup = Path(directory) / "saved.backup.json"
            self.assertEqual(1, self.run_cli("flash", "--updater", "example", "--stock", "--backup", str(backup)))
            program.assert_not_called()
            self.assertFalse(backup.exists())

    def test_wrong_application_after_verified_flash_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli, "load_image", return_value=b"payload"), \
                patch.object(cli, "open_bootloader") as usb, patch.object(cli.protocol, "program"), \
                patch.object(cli.protocol, "inspect", return_value=(bytes(64), bytes(range(180)))):
            session = usb.return_value.__enter__.return_value
            session.app_metadata = None
            session.anchor = "test port"
            session.wait_application.return_value = "qmk 04d9:0532"
            backup = Path(directory) / "saved.backup.json"
            with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
                result = cli.main(["flash", "--updater", "example", "--stock", "--backup", str(backup)])
            self.assertNotEqual(result, 0)
            self.assertNotIn("Application returned:", output.getvalue())
            self.assertIn("Expected stock", errors.getvalue())
            self.assertTrue(backup.is_file())
