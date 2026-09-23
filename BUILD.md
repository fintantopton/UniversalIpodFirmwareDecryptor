# Build Instructions

## macOS (Apple Silicon / Intel) — recommended for Mac users

### Requirements

- macOS 11 or later (Apple Silicon arm64 or Intel x86_64)
- Python 3.9+ **with Tk**:
  - [python.org](https://www.python.org/downloads/macos/) Python includes Tk out of the box (preferred), or
  - Homebrew Python + `brew install python-tk`
- Optional:
  - `brew install go` — lets `build_macos.sh` compile a native wInd3x build automatically
  - `brew install libusb` — needed only for the Nano 2G iBugger path; also used by the Go wInd3x binary

### One-shot build

```bash
./build_macos.sh              # -> dist/iPodFirmwareDecryptor.app
./build_macos.sh --pkg        # + dist/iPodFirmwareDecryptor-3.3.0.pkg
./build_macos.sh --dmg        # + dist/iPodFirmwareDecryptor-3.3.0.dmg
./build_macos.sh --all        # app + pkg + dmg
./build_macos.sh --require-wind3x   # fail if no native wInd3x can be produced
```

The script:

1. checks macOS + a Python with Tk,
2. creates `.venv-macos` and installs `pyinstaller` + `pycryptodome`,
3. converts `ICON.png` → `macos/AppIcon.icns` (sips/iconutil),
4. prepares `vendor/`:
   - `wInd3x-darwin-arm64` (or `-x86_64`) — built with `GOOS=darwin GOARCH=... go build ./cmd/wInd3x` from [freemyipod/wInd3x](https://github.com/freemyipod/wInd3x) when Go is available, or expected pre-placed;
   - `libusb-1.0.dylib` — copied from Homebrew when present,
5. runs PyInstaller with `iPodUniversalDecrypt_b-macos.spec` (onedir `.app`, windowed, bundle id `org.freemyipod.UniversalIpodFirmwareDecryptor`),
6. ad-hoc code-signs the app (`codesign --force --deep -s -`),
7. optionally builds the installer:
   - `.pkg` via `pkgbuild`/`productbuild` — installs `/Applications/iPodFirmwareDecryptor.app` and an `ipod-decrypt` CLI shim in `/usr/local/bin` (which execs the bundled binary with `--cli`),
   - `.dmg` via `hdiutil`.

### Vendor directory (macOS)

```text
UniversalIpodFirmwareDecryptor/
└── vendor/
    ├── wInd3x-darwin-arm64     # Go+libusb wInd3x build (Apple Silicon)
    ├── wInd3x-darwin-x86_64    # (Intel)
    └── libusb-1.0.dylib        # optional (Homebrew)
```

Only files that are present are bundled. Without a wInd3x binary the app still works for:
unencrypted extraction (Category 1), Nano 2G (Categories 3/4, libusb needed for 4),
and raw/plaintext MSE member export (including Nano 5G RSRC + SilverImagesDB).
Device-AES (Category 2) needs the wInd3x binary; Nano 4G/5G device-AES additionally
requires bare-metal Linux per upstream wInd3x and is clearly gated on macOS.

### Run from source

```bash
./run_macos.sh               # GUI
./run_macos.sh --check       # preflight report
./run_macos.sh --cli --ipsw /path/iPod_26.1.1.3.ipsw --yes
```

### Notes

- No elevation and no driver installation: raw USB access works with the system
  stack. If an Apple USB service holds the DFU interface (rare), use the
  “Release Apple USB service (admin)” button in the Prerequisites panel —
  it stops the matching `launchctl` jobs (admin password dialog) and records
  them for the “Restore Apple USB service” button.
- The bundled app is ad-hoc signed (no Developer ID / notarization): confirm
  the first launch (right-click → Open).
- PyInstaller onedir layout: data/vendor files land in
  `iPodFirmwareDecryptor.app/Contents/MacOS/` (or `Contents/Resources/`
  depending on PyInstaller version); the app finds them in either place
  (`ipod_platform.get_bundled_path`).

## Windows

### Requirements

- Windows 10/11
- Python 3.11+ recommended
- PyInstaller
- External native dependencies in `vendor/`:
  - `wInd3x-win.exe`
  - `libusb-1.0.dll`
  - `wInd3x` (Linux binary, retained for compatibility with the existing spec)
  - `wInd3x-write-musl` (optional compatibility binary)
  - `zadig.exe` (optional driver installer)

The dependency binaries are intentionally not committed. Obtain wInd3x from [freemyipod/wInd3x](https://github.com/freemyipod/wInd3x), and obtain Zadig/libusb from their respective upstream projects.

### Prepare the vendor directory

```text
UniversalIpodFirmwareDecryptor/
└── vendor/
    ├── wInd3x-win.exe
    ├── libusb-1.0.dll
    ├── wInd3x
    ├── wInd3x-write-musl
    └── zadig.exe
```

Only files that are present are bundled by the build specification. The native Windows executable requires `wInd3x-win.exe` and `libusb-1.0.dll`; the other binaries are optional compatibility assets.

### Install Python build dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install pyinstaller pycryptodome
```

`pycryptodome` is optional for historical software-AES comparison code; device-AES paths use the device hardware engine.

### Development run

```powershell
python ipod_universal_decrypt_b.py
```

### Compile the executable

```powershell
python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec
```

Output:

```text
dist\iPodUniversalDecrypt_v3.3.0_b40.exe
```

The included `build_b.bat` performs the same build after checking Python, PyInstaller, and the required vendor files.

### Driver setup for hardware-AES paths

1. Put the target iPod in the correct device mode.
2. Install WinUSB for its Apple DFU interface using Zadig.
3. Stop Apple Mobile Device Service and iPodService before native USB access.
4. Use direct native USB for trampoline devices; do not use USB/IP for those paths.

## Cross-platform: tests and CLI

The test suite uses synthetic firmware fixtures (no real IPSW, no hardware) and
passes on any platform:

```bash
python3 -m unittest discover -s tests -v
```

Covered: IPSW filename parsing (including the format-2/format-1 ambiguity),
MSE member parsing, Category 1 extraction (MSE + header-strip fallback),
Category 3 Nano 2G software-AES round-trip with the public key, Category 2
raw-member export without a device, Nano 5G FAT16 SilverImagesDB extraction,
platform module behavior, and iBugger transport import/status.

Headless CLI (any platform, also installed as `ipod-decrypt` by the macOS .pkg):

```bash
python3 ipod_universal_decrypt_b.py --check
python3 ipod_universal_decrypt_b.py --cli --ipsw ./file.ipsw --output ~/Desktop/out --partitions osos,rsrc --yes
```

## Validation

```powershell
python -m py_compile ipod_universal_decrypt_b.py ipod_platform.py ibugger_transport.py nano2g_device_decrypt.py nano2g_ibugger_usb.py nano5g_resources.py
```

## Release packaging

Do not commit:

- `dist/`
- `build/`
- `macos/*.icns`
- `.venv-macos/`
- firmware/IPSW files
- extracted partitions
- recovery files
- dependency binaries (vendor/)
- `*.pkg` / `*.dmg`

Attach the compiled executable (Windows) or `.app`/`.pkg` (macOS) to a GitHub Release instead.
