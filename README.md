# flipper-pack

A pack of useful apps for the Flipper Zero that aren't included in popular firmwares.

| App | Category | What it does |
| --- | --- | --- |
| NFC Ident (`nfc_ident`) | NFC | Identify an NFC card's type/variant, or fingerprint an NFC reader. |
| NTAG Convert (`nfc_convert`) | NFC | Retype a saved NTAG dump between NTAG213/215/216 layouts. |
| NFC Compare (`nfc_compare`) | NFC | Scan two cards in turn and report whether their data matches. |

## Requirements

- A Flipper Zero (hardware target `f7`) running **official firmware 1.4.3 or later**. The apps are built against the official 1.4.3 SDK; FAPs built for one firmware API version won't load on another, so rebuild if you're on a different firmware.
- Python 3.8+ on your computer, to run [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) (the Flipper micro build tool).
- A USB-C cable, or an SD card reader.

## Install

### 1. Install ufbt

```bash
git clone https://github.com/codingconcepts/flipper-pack.git
cd flipper-pack

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade ufbt
```

The first build downloads the Flipper SDK and ARM toolchain into `~/.ufbt` (a few hundred MB, one time only).

### 2. Build the apps

Build one app:

```bash
cd nfc_ident
ufbt
```

The result lands in `nfc_ident/dist/nfc_ident.fap`.

Or build all three:

```bash
for app in nfc_ident nfc_convert nfc_compare; do (cd "$app" && ufbt); done
```

### 3. Put them on the Flipper

**Over USB (easiest).** Plug the Flipper in, close qFlipper and the Flipper CLI first (only one thing can hold the serial port), then run from inside the app's own directory:

```bash
(cd nfc_ident && ufbt launch)
```

This uploads the FAP to the SD card and starts it on the device.

ufbt acts on whichever app's `application.fam` is in the current directory, so every `ufbt` command has to be run from an app directory - not from the repo root. From the root it reports `missing manifest (application.fam)` and, for `launch`, `More than one app is runnable`. There is no `APPID=` shortcut for this.

**By SD card.** Copy each `dist/*.fap` to `/ext/apps/NFC/` on the Flipper's SD card - either by dragging it there in [qFlipper](https://flipperzero.one/update)'s file browser, or by putting the SD card in your computer and copying to `apps/NFC/`.

Either way, the apps then appear on the Flipper under **Apps → NFC**.

### Custom firmware (Momentum, Unleashed, RogueMaster, …)

ufbt targets the official release channel by default. Point it at your firmware's SDK before building, for example:

```bash
ufbt update --index-url=https://up.momentum-fw.dev/firmware/directory.json
```

Then rebuild and reinstall as above. See your firmware's docs for its index URL.

## Troubleshooting

- **"App version mismatch" or the app won't start.** The FAP was built against a different firmware API version. Run `ufbt update` to match your firmware, then rebuild.
- **`ufbt launch` can't find the Flipper.** Unplug anything else holding the serial port (qFlipper, a `ufbt cli` session, a serial monitor) and try again.
- **`More than one app is runnable` / `missing manifest (application.fam)`.** You're in the repo root. `cd` into the app directory first.

## Development

Two helper scripts live in the repo root; they need `pip install pyserial pillow`.

- `flipcli.py` - send commands to the Flipper CLI over serial and print the replies, e.g. `python flipcli.py "log" "ps"`. Useful for reading app logs while debugging; `ufbt`'s own `cli` subcommand wants a tty, which is awkward to script.
- `make_icons.py` - regenerate the 10x10 1-bit FAP icons from the ASCII grids in the script. Run it from the repo root after editing a grid.

Debug builds: `ufbt` also writes `dist/debug/<app>_d.elf`, which pairs with `ufbt debug` for on-device GDB.

Formatting: run `ufbt format` inside an app directory before committing C changes.
