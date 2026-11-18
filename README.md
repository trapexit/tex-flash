# tex-flash

Install QMK or the official stock application on a **TEX Shura** or **TEX Shinobi** over USB from Linux. `tex-flash` uses the keyboard's existing TEX bootloader. It does not run Windows executables, build QMK, or update a Bluetooth module.

**Experimental.** The standalone tool has not been tested end-to-end on hardware. An earlier implementation installed QMK on one Shura; an offline replay matched all 662 requests and accepted its replies. Shinobi support is based on [Mauro DiBenedetto's hardware-tested 4.04 port and flasher](https://github.com/cyclistmass/tex-qmk/blob/bf4a40841d3b3ecd226fc2e0ebb09cdc67b1c7da/shinobi/PORT_NOTES.md#flashing), not a live Linux Shinobi test.

An interrupted erase can leave the keyboard unable to type or enter the bootloader from its application. Have another input device available, use a stable USB connection, and back up settings you need. The metadata saved by this tool is **not** a full-device backup.

## Install

Requires Linux with `hidraw` and Python 3.10 or newer. From a checkout:

```sh
git clone https://github.com/trapexit/tex-flash.git
cd tex-flash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
tex-flash --help
```

For a local desktop login using systemd-logind, install the supplied udev rule, then **unplug and reconnect** the keyboard. The rule covers both models; reinstall it if you have the older Shura-only version. Run `tex-flash` as your normal user.

```sh
sudo install -m 644 udev/50-tex-shura.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

## Check your files (no keyboard required)

The updater must be an original executable extracted from [TEX Downloads](https://tex.com.tw/pages/download), even for a QMK install. No updater or firmware is bundled. Choose the keyboard model, not the Bluetooth module or keymap name: a **Shura with a Shinobi-style keymap is still a Shura**.

| Model option | Supported stock package | USB application → bootloader |
|---|---|---|
| `--model shura` (default) | `AP_0532_0.18_20230914.exe` | `04d9:0532` → `04d9:1532` |
| `--model shinobi` | `AP_0407_4.04.exe` | `04d9:0407` → `04d9:1407` |

**Shura:** the required updater SHA-256 is `1b9678d235cecaa7affea40ff8858a2f5993795b24dd7b7d2a34aa7b193c0f99`. For QMK, use the `.bin` and unstripped `.elf` from the **same build**. Supply regular files, not symlinks.

```sh
updater=./AP_0532_0.18_20230914.exe
tex-flash check --updater "$updater" --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf
# To check the official application instead:
tex-flash check --updater "$updater" --stock
```

**Shinobi:** extract `AP_0407_4.04.exe` from [TEX's 4.04 archive](https://cdn.shopify.com/s/files/1/0052/5814/9978/files/AP_0407_4.04.rar?v=1732595375). The executable SHA-256 is `f14658e73b1956641b72b80eca8f873bf95db21968baf1fb79ff7cc9e39621a7`. For the [published v1.2 QMK release](https://github.com/cyclistmass/tex-qmk/releases/tag/shinobi-v1.2), the exact `.bin` is sufficient; edited keymaps and other custom builds require their matching unstripped ELF. Only install firmware you trust.

```sh
updater=./AP_0407_4.04.exe
tex-flash check --model shinobi --updater "$updater" --stock
tex-flash check --model shinobi --updater "$updater" --bin ./tex_shinobi_v1.2.bin
# For a custom build, add --elf ./tex_shinobi_default.elf to its --bin command.
```

**Only Shinobi keyboard firmware 4.04 is supported; 3.01 is not.** The two versions use the same USB IDs but have different stock images and version metadata. The flasher checks the version, not whether a BLE4 or BLE5 module is attached. It does not upgrade a 3.01 installation to 4.04. A Shinobi QMK flash resets settings stored in the MCU's internal flash, including TrackPoint sensitivity and sleep time.

## Flash over USB

`flash` starts the update without an interactive prompt. Connect the intended keyboard by USB. Unmount its configuration disk if mounted and close VIA, any TEX updater, and other programs using raw HID. Pick a new backup filename in a writable directory; the tool will not overwrite it.

**From stock firmware:** find the keyboard's `iSerial` value (for example, `lsusb -v -d 04d9:0532` for Shura or `lsusb -v -d 04d9:0407` for Shinobi). Supply the exact USB serial, including leading zeroes. `--serial` selects the *running stock application*, not the image to install. Shura example:

```sh
tex-flash flash --serial 'YOUR_USB_SERIAL' --updater ./AP_0532_0.18_20230914.exe \
  --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf --backup ./first-flash.backup.json
```

**From supported QMK or the TEX bootloader:** omit `--serial`. The tool requires one matching device of the selected model and follows the same physical port across USB re-enumeration. If QMK has no supported raw HID endpoint, enter its bootloader first: hold Escape while plugging in the board (requires Bootmagic). That is not a stock-firmware shortcut.

```sh
tex-flash flash --updater ./AP_0532_0.18_20230914.exe --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf \
  --backup ./qmk-update.backup.json

# To install the official 0.18 application instead of QMK:
tex-flash flash --updater ./AP_0532_0.18_20230914.exe --stock --backup ./before-stock.backup.json
```

For example, to install QMK **from stock Shinobi 4.04**:

```sh
tex-flash flash --model shinobi --serial 'YOUR_USB_SERIAL' \
  --updater ./AP_0407_4.04.exe --bin ./tex_shinobi_v1.2.bin --backup ./shinobi.backup.json
```

To return to stock on that model, keep `--model shinobi --updater ./AP_0407_4.04.exe`, replace `--bin …` with `--stock`, omit `--serial` when starting from QMK, and choose a new backup path.

Before erasing, the tool checks the loader and its flash geometry, reads the 180 bytes of version metadata the loader exposes, and saves them to a private file. It rechecks the device, erases once, checks the write pointers and bootloader checksum, restores and reads back the metadata, then waits for the expected application on the same port. A zero exit status means these checks passed; test typing and your layout separately. There is no force flag or automatic retry.

## Interrupted flash

- **Error before erase:** nothing has been programmed. The keyboard may already be in its bootloader (see the USB IDs above). Correct the file, permissions, or device selection before trying again.
- **Erase may have started:** keep the **same keyboard connected to the same port**. Do not take a fresh backup of a partially written board. Keep the original backup and image files. If the TEX bootloader still enumerates, repeat the command with the same `--model` **without `--serial`**, replacing `--backup` with `--resume-from` and the original backup path. Shura example:

  ```sh
  tex-flash flash --updater ./AP_0532_0.18_20230914.exe --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf \
    --resume-from ./first-flash.backup.json
  ```

  This restarts the transfer, not an individual block. The tool checks the image hash, port, bootloader info and remaining metadata against the saved values. A port identifies a connection, **not a unique keyboard**. Never use another board's backup. Treat recovery files as private; do not attach them to public issues.
- **Transfer verified but application not seen:** inspect `lsusb` before attempting another write. Failure to observe the application isn't itself proof that programming failed.
- **No TEX bootloader:** this tool cannot recover a missing or damaged loader. `--stock` installs the selected package's application; it does not restore a full-device backup, profiles, or Bluetooth bonds.

## Development and license

After installing from the checkout, run `python -m unittest discover -s tests -v`. Tests use synthetic inputs; no keyboard or vendor download is required. For a bug report, include the keyboard model, command (redact serials and private paths), error text, and the USB VID:PID.

**Shinobi verification:** for stock 4.04, the upstream v1.2 QMK release, and a separately built QMK ELF/BIN, offline checks matched all 28,076 payload bytes and all 551 reports in the upstream command plan. Metadata readback was tested with simulated replies. This was **not a replay of a captured Shinobi USB session**. Linux bootloader descriptors, timing, and the return to typing still need a keyboard test.

GPL-2.0-or-later; see [LICENSE](LICENSE). The updater container codec is adapted from [Mauro DiBenedetto's TEX QMK tools](https://github.com/cyclistmass/tex-qmk/tree/bf4a40841d3b3ecd226fc2e0ebb09cdc67b1c7da/shinobi/tools). `tex-flash` is an independent project, not an official TEX utility.
