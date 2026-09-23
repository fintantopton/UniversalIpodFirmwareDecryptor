# Universal iPod Firmware Decryptor

Cross-platform application (Windows and macOS) for extracting and decrypting iPod RetailOS (OSOS) firmware and exporting plaintext resource files.

![Universal iPod Firmware Decryptor application window](docs/images/iPodFirmwareDecryptor.png)

**Current source:** v3.3.0 / build 40
**Platforms:**

| Platform | Status | Notes |
|---|---|---|
| macOS 11+, Apple Silicon (arm64) | ✅ Full support | Native `wInd3x` darwin build + libusb; no drivers or elevation needed |
| macOS 11+, Intel (x86_64) | ✅ Full support | Same flow, x86_64 binaries |
| Windows 10/11 (x64) | ✅ Full support | `wInd3x-win.exe` + WinUSB (Zadig) |
| Linux | 🧪 Development/testing | Plain-text paths work; trampoline device-AES (Nano 4G/5G) needs bare-metal Linux per upstream wInd3x |

**Release executables/apps:** See the GitHub Releases page. Binaries and `.app`/`.pkg` artifacts are distributed as release assets, not committed to the source repository.

## Implemented methods

- **Plaintext extraction:** IPSW/MSE extraction with an IMG1-header fallback for unencrypted firmware families.
- **Native hardware AES:** `haxdfu` plus on-device AES for the supported Classic/Nano 3G/4G/5G paths, via `wInd3x-win.exe` (Windows) or a native darwin `wInd3x` build (macOS).
- **Legacy hardware AES:** Separate Notes/Loader/Core device-AES transport — WinUSB on Windows (`nano2g_device_decrypt.py`), libusb on macOS (`nano2g_ibugger_usb.py`) — with shared payloads in `nano2g_payloads.py`.
- **Nano 5G resource export:** Plaintext RSRC/FAT16 parsing with `SilverImagesDB.LE.bin` export in `nano5g_resources.py`.
- **Historical software reconstruction:** Retained only for forensic comparison; it is not a valid source of ground-truth decrypted firmware.

The current detailed method matrix is documented in `DECRYPTION_METHODS.md`, with build instructions in `BUILD.md` and operational notes in `KNOWLEDGE_BASE.md`.

## Quick start — macOS (Apple Silicon)

```bash
# 1. Build the .app (and optionally a .pkg installer / .dmg)
./build_macos.sh --all

# 2. First launch (ad-hoc signed, not notarized)
open dist/iPodFirmwareDecryptor.app
#    — if Gatekeeper prompts, right-click the app → Open.

# 3. Or install via the .pkg (puts the app in /Applications and a
#    `ipod-decrypt` CLI in /usr/local/bin)
open dist/iPodFirmwareDecryptor-3.3.0.pkg
```

Run from source instead of building:

```bash
./run_macos.sh            # GUI
./run_macos.sh --check    # preflight: tkinter, openssl, libusb, wInd3x
./run_macos.sh --cli --ipsw ~/Downloads/iPod_1.0.2_34A20020.ipsw -y
```

macOS prerequisites are minimal: a Python with Tk (python.org Python works out of the box; Homebrew needs `brew install python-tk`), plus optionally `brew install libusb` for the Nano 2G iBugger path. If a native wInd3x build is not found, the script compiles it with Go (`brew install go`), or the app falls back to raw/plaintext export and a clear warning for the device-AES models.

## Quick start — headless CLI (all platforms)

```bash
python3 ipod_universal_decrypt_b.py --check
python3 ipod_universal_decrypt_b.py --cli \
    --ipsw ./iPod_26.1.1.3.ipsw \
    --output ~/Desktop/decrypted_nano3g \
    --partitions osos,rsrc --yes
```

## Quick start — Windows

See `BUILD.md` (Windows section) and `build_b.bat`.

## Source layout

```text
ipod_universal_decrypt_b.py       Cross-platform app: decrypt controller + Tk GUI + CLI
ipod_platform.py                  Platform layer (USB scan, services, bundled files)
ibugger_transport.py              iBugger backend selector (WinUSB vs libusb)
nano2g_device_decrypt.py          Windows WinUSB legacy device transport
nano2g_ibugger_usb.py             macOS/Linux libusb legacy device transport
nano2g_payloads.py                Embedded RAM-resident device payloads
nano5g_resources.py               Nano 5G RSRC/FAT16 extraction
mse_members.py                    Read-only MSE member parser
tests/                            Synthetic-firmware test suite (unittest)
iPodUniversalDecrypt_b.spec       Windows PyInstaller spec
iPodUniversalDecrypt_b-macos.spec macOS PyInstaller spec (.app)
build_macos.sh                    macOS build: .app / .pkg / .dmg
run_macos.sh                      Run the macOS GUI from source
DECRYPTION_METHODS.md             Per-model decryption methods
BUILD.md                          Complete source/build instructions
KNOWLEDGE_BASE.md                 Application knowledge base
```

## Runtime dependencies

External components are kept in `vendor/` and are **not** committed (see `vendor/README.md`):

- **Windows:** `wInd3x-win.exe`, `libusb-1.0.dll`, optional `wInd3x` / `wInd3x-write-musl` / `zadig.exe`
- **macOS:** `wInd3x-darwin-arm64` (or `-x86_64`) — a native Go+libusb build of [freemyipod/wInd3x](https://github.com/freemyipod/wInd3x) — and optionally `libusb-1.0.dylib` (Homebrew)
- **Windows only:** WinUSB bound to the target DFU interface, normally installed with Zadig
- **macOS:** no driver installation or elevation; if an Apple USB service holds the DFU interface, the app offers a (optional, admin-prompt) release/restore step
- **Any platform:** PyCryptodome, `cryptography`, or OpenSSL for the historical software-AES comparison code

The active device paths do not expose or require a software copy of the fused AES key.

## Build

- **macOS:** `./build_macos.sh [--pkg|--dmg|--all]` — creates a venv, generates the `.icns` from `ICON.png`, bundles vendor binaries, runs PyInstaller (onedir `.app`), ad-hoc code-signs, and optionally produces a `.pkg` installer (installs the app plus an `ipod-decrypt` CLI shim in `/usr/local/bin`) and a `.dmg`.
- **Windows:** `build_b.bat`, or `python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec`.

Both flows use the local `vendor/` directory for external dependencies. Release artifacts are published separately as GitHub Release assets and are excluded from Git by `.gitignore`.

## Safety

The device-side exploit/decryption paths are intended to be RAM-resident. They do not write NAND, NOR, or firmware storage as part of normal extraction/decryption. Resource-only RSRC extraction does not require a connected device.

## Research and limitations

- Nano 4G/5G trampoline paths require direct native USB; USB/IP bridges are unreliable for the intentional timeout/re-enumeration sequence. Per upstream wInd3x, these trampolines are only possible on **bare-metal Linux** (the host must abort a DFU transfer after exactly 0x40 bytes); on macOS those models support raw/plaintext member export (e.g. Nano 5G RSRC + SilverImagesDB) but not device AES.
- S5Late-era models are not current decrypt-supported targets even if exploit/code-execution experiments exist.
- Category 2 output validation should be strengthened beyond the current file-size gate before treating every output as cryptographic proof.
- Classic 7G Rev C (FamilyID 38, DFU PID `0x1250`) may not be recognized by a stock wInd3x build (upstream tracks PID `0x1223` for the S5L8702 family); the app warns about this.

## Use at your own risk

Universal iPod Firmware Decryptor is experimental reverse-engineering software intended for research, preservation, and firmware analysis. It performs low-level USB communication, may stop Apple-device services (Windows, or opt-in on macOS), invokes external exploit/decryption tooling, and can upload and execute RAM-resident payloads on compatible devices.

The software is provided without warranty. The author is not responsible for data loss, device malfunction, firmware corruption, security issues, antivirus detections, or any other damage resulting from its use. Review the source code, verify external dependencies, maintain device and data backups, and use an isolated test system where possible.

Microsoft Defender may flag the unsigned PyInstaller executable as `Trojan:Win32/Wacatac.B!ml`. This may be a heuristic false positive caused by the executable's packaging, native USB access, subprocess execution, administrator privileges, and embedded device payloads, but it has not been independently cleared by Microsoft. Users should whitelist or restore the executable at their own risk. Building from source is recommended for users who want to review the implementation directly.

macOS builds are ad-hoc signed (no Developer ID, no notarization). Gatekeeper will ask you to confirm the first launch (right-click → Open, or System Settings → Privacy & Security).
