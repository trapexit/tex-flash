# tex-flash

Install a QMK build or the official TEX 0.18 application on a **TEX Shura** keyboard from Linux. The tool talks to the keyboard's existing TEX USB bootloader. It does not run the Windows updater, build QMK, flash the Bluetooth module, or support the TEX Shinobi.

**Experimental.** An earlier implementation installed QMK on one Shura. In an offline replay, this tool generated all 662 HID requests from that successful transfer byte-for-byte and accepted its recorded replies. The standalone tool has not yet been tested end-to-end on hardware.

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

For a local desktop login using systemd-logind, install the supplied udev rule once, then **unplug and reconnect** the Shura. The rule grants the active user access to the keyboard and bootloader HID nodes. Run `tex-flash` as your normal user.

```sh
sudo install -m 644 udev/50-tex-shura.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

## Check your files (no keyboard required)

Download the **Shura 0.18** update from [TEX Downloads](https://tex.com.tw/pages/download) and extract `AP_0532_0.18_20230914.exe`. Both stock and QMK installs require that exact file. Its SHA-256 is `1b9678d235cecaa7affea40ff8858a2f5993795b24dd7b7d2a34aa7b193c0f99`. No TEX firmware or updater is distributed here.

For QMK, keep the `.bin` **and the unstripped `.elf` from the same Shura build**. Use regular files, not symlinks. Currently the tool recognizes the Shura port's four-layer, 8 × 11 keymap layout. It checks the image layout, vector targets, bootloader handoff space, Shura compatibility record, and agreement between the ELF and binary. These checks do not establish that the firmware is trustworthy or that a keymap works. Only install code you trust.

```sh
updater=./AP_0532_0.18_20230914.exe
tex-flash check --updater "$updater" --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf
# To check the official application instead:
tex-flash check --updater "$updater" --stock
```

## Flash over USB

`flash` starts the update without an interactive prompt. Connect **one Shura**. Unmount its configuration disk if mounted. Close VIA, any TEX updater, and other programs using its raw HID interface. Pick a new backup filename in a writable directory; the tool will not overwrite it.

**From stock firmware:** find the Shura's `iSerial` value (for example, `lsusb -v -d 04d9:0532`). Supply the exact USB serial, including leading zeroes. `--serial` selects the *running stock application*, not the image you want to install.

```sh
tex-flash flash --serial 'YOUR_USB_SERIAL' --updater "$updater" \
  --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf --backup ./first-flash.backup.json
```

**From supported Shura QMK or the TEX bootloader:** omit `--serial`. The tool finds the single supported device and follows the same physical port across USB re-enumeration. If your QMK build has no supported raw HID endpoint, enter its bootloader first: hold Escape while plugging in the board (requires Bootmagic). That is not a stock-firmware shortcut.

```sh
tex-flash flash --updater "$updater" --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf \
  --backup ./qmk-update.backup.json

# To install the official 0.18 application instead of QMK:
tex-flash flash --updater "$updater" --stock --backup ./before-stock.backup.json
```

Before erasing, the tool checks the loader and its flash geometry, reads the 180 bytes of version metadata the loader exposes, and saves them to a private file. It rechecks the device, erases once, checks the write pointers and bootloader checksum, restores and reads back the metadata, then waits for the expected application on the same port. A zero exit status means these checks passed; test typing and your layout separately. There is no force flag or automatic retry.

## Interrupted flash

- **Error before erase:** nothing has been programmed. The keyboard may already be in the bootloader (`04d9:1532`). Read the error; correct the file, permissions, or device selection before trying again.
- **Erase may have started:** keep the **same keyboard connected to the same port**. Do not take a fresh backup of a partially written board. Keep the original backup and image files. If the TEX bootloader still enumerates, repeat the command **without `--serial`**, replacing `--backup` with `--resume-from` and the original backup path. For example:

  ```sh
  tex-flash flash --updater "$updater" --bin ./ShuraQMK.bin --elf ./ShuraQMK.elf \
    --resume-from ./first-flash.backup.json
  ```

  This restarts the transfer, not an individual block. The tool checks the image hash, port, bootloader info and remaining metadata against the saved values. A port identifies a connection, **not a unique keyboard**. Never use another board's backup. Treat recovery files as private; do not attach them to public issues.
- **Transfer verified but application not seen:** inspect `lsusb` before attempting another write. Failure to observe the application isn't itself proof that programming failed.
- **No TEX bootloader:** this tool cannot recover a missing or damaged loader. `--stock` installs the packaged 0.18 application; it does not restore the original installed version, bootloader, profiles, or Bluetooth bonds from a backup.

## Development and license

After installing from the checkout, run `python -m unittest discover -s tests -v`. Tests use synthetic inputs; no hardware or vendor download is required. For a bug report, include the command (redact serials and private paths), the error text, and whether USB shows `04d9:0532` or `04d9:1532`.

GPL-2.0-or-later; see [LICENSE](LICENSE). The updater container codec is adapted from [Mauro DiBenedetto's TEX QMK tools](https://github.com/cyclistmass/tex-qmk/tree/bf4a40841d3b3ecd226fc2e0ebb09cdc67b1c7da/shinobi/tools). `tex-flash` is an independent project, not an official TEX utility.
