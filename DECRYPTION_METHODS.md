# Decryption Methods by iPod

This is the operational guide for the active v3.3 application.

## Platform support

| Platform | Category 1 (plaintext) | Category 2 (device AES) | Category 3 (Nano 2G software) | Category 4 (Nano 2G iBugger) |
|---|---|---|---|---|
| Windows 10/11 | ✅ | ✅ (wInd3x-win.exe + WinUSB) | ✅ | ✅ (WinUSB) |
| macOS 11+ (Apple Silicon / Intel) | ✅ | ✅ for S5L8702 (Classic, Nano 3G) via native darwin wInd3x; Nano 4G/5G gated (Linux-only trampoline) — raw export still works | ✅ | ✅ (libusb) |
| Linux (dev) | ✅ | ✅ (upstream native paths) | ✅ | ✅ (libusb) |

macOS specifics: no driver installation or elevation is required; the app can
optionally release/restore Apple USB `launchctl` services via an admin dialog
when a service holds the DFU interface. Nano 4G (31) / Nano 5G (34) device AES
uses the `blx r0` trampoline, which upstream wInd3x restricts to bare-metal
Linux (host transfer-abort semantics); on macOS these models export
raw/plaintext members instead (e.g. Nano 5G RSRC + SilverImagesDB). Classic 7G
Rev C (family 38, DFU PID `0x1250`) may not be recognized by stock wInd3x
builds (upstream tracks `0x1223` for the S5L8702 family).

## Model matrix

| iPod/model group | FamilyID | SoC | Method | Device state | Status |
|---|---:|---|---|---|---|
| iPod 1G | 1 | PP5002 | Plaintext IPSW/MSE extraction | None | Supported |
| iPod 3G | 2 | PP5020 | Plaintext IPSW/MSE extraction | None | Supported |
| iPod Mini 1G | 3, 6 | PP5020C | Plaintext IPSW/MSE extraction | None | Supported |
| iPod 4G Mono | 4, 10 | PP5020C | Plaintext IPSW/MSE extraction | None | Supported |
| iPod 4G Photo/Color | 5, 11 | PP5020/PP5021 | Plaintext IPSW/MSE extraction | None | Supported |
| Nano 1G | 12, 14, 17 | PP5021C | Plaintext IPSW/MSE extraction | None | Supported |
| iPod 5G Video | 13 | BCM2722 | Plaintext IPSW/MSE extraction | None | Supported |
| iPod 5G Video Late | 20 | BCM2722 | Plaintext IPSW/MSE extraction | None | Supported |
| iPod 5.5G Video Enhanced | 25 | BCM2722 | Plaintext IPSW/MSE extraction | None | Supported |
| Classic 6G/6.5G/7G revisions | 24, 33, 35, 38 | S5L8702 | Native Windows wInd3x hardware AES | Apple DFU, PID `0x1223`/`0x1250` | Supported path |
| Nano 3G | 26, 27 | S5L8702 | Native Windows wInd3x hardware AES | Apple DFU, PID `0x1223` | Supported path |
| Nano 4G | 31 | S5L8720 | `epNano4G` wInd3x trampoline + hardware AES | Apple DFU, PID `0x1225` | Integrated; physical validation should be recorded per device |
| Nano 5G | 34 | S5L8730 | `epNano5G` wInd3x trampoline + hardware AES | Apple DFU, PID `0x1231` | Successfully decrypted and locally verified (OSOS 1.0.1 and 1.0.2) |
| Nano 6G | 36 | S5L8723 | S5Late research path | Apple DFU, PID `0x1232` | Not current decrypt support |
| Nano 7G | 37 | S5L8740 | S5Late research path | Apple DFU, PID `0x1234` | Not current decrypt support |
| Legacy Notes/iBugger target | 19, 29 | S5L87xx | Notes → Loader → Core → device AES | Disk-mode staging; Unified iBugger `FFFF:8642` | Separate hardware path |

## Method details

### Plaintext IPSW/MSE extraction

Implemented in:

```text
ipod_universal_decrypt_b.py::_decrypt_category1
```

The app opens the IPSW as a ZIP, locates the top-level firmware member, tries:

```text
wInd3x-win.exe mse extract Firmware.MSE -o <directory>\
```

If native extraction is unavailable, it uses the historical IMG1/header-strip fallback. No device or AES operation is needed.

### Native wInd3x hardware AES

Implemented in:

```text
ipod_universal_decrypt_b.py::_decrypt_category2_native
```

Workflow:

1. Platform preparation (Windows: stop Apple services + unbind usbipd;
   macOS: no-op, with optional launchctl service release from the GUI).
2. Extract MSE members (read-only parser; members are materialized to a
   temp directory).
3. Run `wInd3x haxdfu -v` (wInd3x-win.exe on Windows, native darwin build on
   macOS).
4. Run `wInd3x decrypt <input> <output> -v -r <recovery>` for each encrypted
   member; plaintext/raw members are exported byte-for-byte without the device.
5. Restore platform device access (and re-bootstrap released Apple services
   on macOS).

Nano 4G and Nano 5G use trampoline RCE paths. Direct native USB is required;
USB/IP bridges are unreliable for the intentional timeout/re-enumeration
sequence, and upstream wInd3x restricts those trampolines to bare-metal
Linux (the host must abort a DFU transfer after exactly 0x40 bytes).

The SoC-specific parameters are supplied by upstream wInd3x in:

```text
vendor dependency source: freemyipod/wInd3x
upstream file: pkg/exploit/wind3x_n45g.go
```

### Legacy Loader/Core hardware AES

Implemented in:

```text
nano2g_device_decrypt.py
nano2g_payloads.py
ipod_universal_decrypt_b.py::_decrypt_category4_nano2g_device
```

Workflow:

1. Stage the patched `loader.htm` in the device Notes folder from Disk Mode.
2. Connect to Unified iBugger over native WinUSB.
3. Upload the RAM-resident Core if needed.
4. Upload/execute the RAM-resident AES payload.
5. Download decrypted output.
6. Remove or restore `loader.htm` afterward.

The transport is RAM-resident and does not write NAND, NOR, or firmware storage.

### Nano 5G resource export

Implemented in:

```text
nano5g_resources.py
ipod_universal_decrypt_b.py::_export_nano5g_rsrc_files
```

Nano 5G `rsrc` is a plaintext format-4 IMG1 image containing FAT16. The app can export:

```text
Resources/UI/SilverImagesDB.LE.bin
```

Resource-only extraction does not require a device. The RSRC image must not be sent through hardware AES.

### Historical software reconstruction

The source retains a historical software-AES comparison branch. It is not mapped to an active model and must not be used as a valid decryption method or source of ground-truth firmware.

## Output validation limitation

The native hardware-AES path currently uses a basic output-size gate. Before treating a result as cryptographically verified, validate IMG1 magic/version/format, body alignment, header/footer lengths, code plausibility, and expected firmware strings.

## Relevant files

```text
ipod_universal_decrypt_b.py       Active application and dispatch
nano2g_device_decrypt.py          Native WinUSB Loader/Core transport
nano2g_payloads.py                Embedded legacy device payloads
nano5g_resources.py                Nano 5G RSRC/FAT16 parser
nano5g_dfu_probe.py               DFU probe utilities
nano2g_ibugger_host.py            Host-side legacy transport tool
nano2g_ibugger_winusb_probe.py    Native WinUSB probe
nano2g_ibugger_wsl_probe.py       WSL/libusb diagnostic probe
nano2g_dfu_probe.py               DFU diagnostic probe
_patch_all_native.py               Native wInd3x patch helper
ipod_dfu_winusb.inf                WinUSB driver INF
```

## Verified Nano 5G OSOS outputs

The Nano 5G hardware-AES process has successfully produced coherent decrypted OSOS firmware for two firmware versions:

```text
OSOS 1.0.1
size:   7,276,688 bytes
SHA256: EA4BAD8DC8C8C57EA3144F9615B92D6865AB34BEC267229B41E7B12CF6B491F4

OSOS 1.0.2
size:   7,286,720 bytes
SHA256: 3269D9EDA2E7E7C406D7BFD6895BD83F27603F03A2C9F52C6CF415924E41AF81
```

Both outputs validate as S5L8730 IMG1 images with magic `8730`, version `2.0`, format 4, internally consistent length fields, 16-byte-aligned bodies, valid unsigned-image signature/certificate placeholders, and expected RetailOS anchors including `RTXC`, `MeCCA`, `SQLite`, `DiskMode`, `TCCamera`, and `N33FirmwareWin`.

The current output-validation code still uses a basic file-size gate, so future runs should apply the structural/content checks above rather than treating file creation alone as proof.
