# Nano 5G Implementation Handover

**Project:** Universal iPod Firmware Decryptor  
**Target:** iPod Nano 5th Generation / FamilyID 34 / S5L8730  
**Reference IPSW:** `C:\KIRO\ipod_IPSWAnalyze\IPSW\Nano5\iPod_1.0.2_34A20020.ipsw`  
**Application build:** v3.2.0, build 30  
**Last packaged executable:** `C:\KIRO\iPodUniversalDecrypt\dist\iPodUniversalDecrypt_v3.2.0_b30.exe`

This document explains how the Nano 5G implementation works, what is verified, what code is reusable, and what another session should do next.

---

## 1. Current Status

The Nano 5G implementation is integrated into the Category 2 native Windows hardware-AES path.

Implemented and verified:

- FamilyID 34 detection.
- S5L8730 model identification.
- DFU PID `0x1231` mapping.
- Native Windows wInd3x invocation.
- MSE extraction from Nano 5G IPSWs.
- OSOS/AUPD/etc. IMG1 input handling through wInd3x.
- Recovery-file support for long-running decryption.
- Nano 5G RSRC recognition as plaintext data.
- FAT16 parsing of the RSRC resource image.
- `Resources/UI/SilverImagesDB.LE.bin` extraction.
- Nano 5G-specific SilverImagesDB checkbox in the UI.
- PyInstaller packaging of the new resource module.
- Source and packaged executable launch validation.

Important status distinction:

- Static firmware/output validation is complete.
- The existing local decrypted Nano 5G OSOS artifacts are structurally valid.
- The current app path still needs a fresh physical Nano 5G DFU run on this PC for independent end-to-end confirmation if that has not yet been performed in the next session.

No NAND, NOR, flash, or firmware-storage write is part of this implementation.

---

## 2. Main Source Files

Application entry point and workflow:

```text
C:\KIRO\iPodUniversalDecrypt\ipod_universal_decrypt_b.py
```

Nano 5G RSRC/FAT16/SilverImagesDB extraction:

```text
C:\KIRO\iPodUniversalDecrypt\nano5g_resources.py
```

PyInstaller specification:

```text
C:\KIRO\iPodUniversalDecrypt\iPodUniversalDecrypt_b.spec
```

Packaged executable:

```text
C:\KIRO\iPodUniversalDecrypt\dist\iPodUniversalDecrypt_v3.2.0_b30.exe
```

Bundled/native wInd3x source and binaries:

```text
C:\KIRO\AppPatcher\wInd3x-src\
```

Relevant upstream/local wInd3x source files:

```text
pkg\devices\devices.go
pkg\exploit\wind3x_n45g.go
pkg\exploit\decrypt\decrypt.go
pkg\mse\mse.go
pkg\image\image.go
```

Relevant upstream repository:

```text
https://github.com/freemyipod/wInd3x
```

Technical exploit write-up:

```text
https://q3k.org/wInd3x.html
```

---

## 3. Model Detection

The application maps Nano 5G as:

```python
34: ("iPod Nano 5th Gen (S5L8730)", 2, "S5L8730", "1231")
```

The IPSW filename format is:

```text
iPod_1.0.2_34A20020.ipsw
```

The first two digits of the build code identify FamilyID 34.

Expected detection result:

```text
FamilyID: 34
Model:    iPod Nano 5th Gen (S5L8730)
Category: 2 — Hardware AES
DFU PID:  0x1231
```

---

## 4. Nano 5G Hardware/Exploit Parameters

Nano 5G is implemented by the upstream `epNano5G` wInd3x parameter set. It inherits the shared `epNano45G` transport layout but has its own bootrom addresses.

| Parameter | Nano 5G value |
|---|---:|
| SoC image code | `8730` |
| DFU PID | `0x1231` |
| DFU protocol | Version 2 |
| Trampoline address | `0x37c` |
| DFU buffer | `0x2202db00` |
| Payload execution address | `0x2202de08` |
| USB buffer | `0x2202e300` |
| Haxed-DFU no-op/return address | `0x20000cbc` |
| USB send handler | `0x2000a474` |
| LR fixup | `0x20004d70` |
| AES call | `0x200020ec` |
| Disable I-cache call | `0x200003c0` |

These values are supplied by the wInd3x binary. The Python app does not recreate the exploit payload or duplicate these addresses; it invokes the native wInd3x executable.

The Nano 5G exploit uses the trampoline-based path. Native Windows USB is preferred because the exploit intentionally creates a USB timeout/re-enumeration sequence that is unreliable through USB/IP bridges.

---

## 5. Runtime Decryption Workflow

The Category 2 workflow is implemented in:

```python
UniversalDecryptorApp._decrypt_category2_native()
```

The workflow is:

### Step 1 — Prepare native USB

The application attempts to stop services that may hold the iPod USB interface:

```text
Apple Mobile Device Service
iPodService
```

It also attempts to unbind `usbipd` so native Windows USB access is available.

### Step 2 — Extract Firmware.MSE

The IPSW is opened as a ZIP archive. The top-level `Firmware.MSE` member is extracted to a temporary file.

The application invokes native wInd3x:

```text
wInd3x-win.exe mse extract Firmware.MSE -o <temporary-output>\
```

The extracted members include:

```text
disk
diag
appl
lbat
bdsw
bdhw
chrg
rsrc
osos
```

### Step 3 — Run haxed DFU

For encrypted partitions, the application invokes:

```text
wInd3x-win.exe haxdfu -v
```

The iPod must be in DFU mode and must enumerate as:

```text
VID 05ac / PID 1231
```

The exploit is RAM-resident and temporary.

### Step 4 — Decrypt encrypted IMG1 members

For each selected encrypted partition, the application invokes:

```text
wInd3x-win.exe decrypt <input> <output> -v -r <recovery-file>
```

The upstream decrypt implementation processes the IMG1 body in small blocks using the device AES engine. Recovery files allow a long operation to resume after interruption.

Output is rebuilt as an unsigned IMG1 image by wInd3x.

---

## 6. Nano 5G IMG1/MSE Format Findings

Nano 5G OSOS MSE input is an S5L8730 IMG1 image:

```text
Magic:      8730
Version:    2.0
Input form: format 3 / encrypted
```

A reconstructed decrypted image has:

```text
Magic:      8730
Version:    2.0
Output:     format 4 / unsigned
Header:     0x600 bytes
```

Known valid local decrypted OSOS images:

```text
C:\KIRO\iPodKnowledgeDB\Decrypted BIN\osos_decrypted_iPod_Nano_5th_Gen_1.0.1.bin
C:\KIRO\iPodKnowledgeDB\Decrypted BIN\osos_decrypted_iPod_Nano_5th_Gen_1.0.2.bin
```

### OSOS 1.0.1

```text
Size:   7,276,688 bytes
SHA256: EA4BAD8DC8C8C57EA3144F9615B92D6865AB34BEC267229B41E7B12CF6B491F4
```

### OSOS 1.0.2

```text
Size:   7,286,720 bytes
SHA256: 3269D9EDA2E7E7C406D7BFD6895BD83F27603F03A2C9F52C6CF415924E41AF81
```

The output image contains the expected wInd3x unsigned-image placeholders:

```text
Signature area:     0x80 bytes of 'S' (0x53)
Certificate area:   0x300 bytes of 'C' (0x43)
```

Output validation should check more than file size. At minimum validate:

- `8730` magic.
- `2.0` version.
- Format 4.
- Header/body/data lengths.
- 16-byte body alignment.
- Footer bounds.
- Plausible ARM/Thumb code.
- Expected RetailOS strings.

The current Category 2 output gate still primarily checks that an output file exists and is larger than 1000 bytes. This should be strengthened before treating every future output as cryptographically/content-valid.

---

## 7. RSRC and SilverImagesDB Handling

Nano 5G `rsrc` is different from encrypted OSOS. It is a plaintext format-4 resource image containing a FAT16 filesystem.

The app must not send Nano 5G `rsrc` through the hardware AES decrypt command.

For the validated 1.0.2 resource image:

```text
MSE-extracted RSRC:
C:\KIRO\iPodUniversalDecrypt\mse_out\rsrc
```

The filesystem layout is:

```text
IMG1 header:       offset 0x0000
FAT16 volume:      offset 0x0600
FAT16 signature:   offset 0x07FE
```

Observed FAT16 values:

```text
Bytes per sector:       512
Sectors per cluster:    8
Reserved sectors:       1
Number of FATs:         2
Root directory entries: 624
FAT size:               121 sectors
```

The application integration is:

```python
from nano5g_resources import (
    Nano5GResourceError,
    extract_silver_images_db,
)
```

The Nano 5G UI adds:

```text
SilverImagesDB.LE.bin (Nano 5G)
```

When selected, the application implicitly includes `rsrc`, parses the FAT16 image, and exports:

```text
SilverImagesDB.LE.bin
```

Validated 1.0.2 extraction:

```text
Path:   Resources/UI/SilverImagesDB.LE.bin
Size:   9,793,432 bytes
SHA256: 692f8ee8102987e92d8255ae2bc54ea116b474f5a1cc80c2cfb6cbd09a96c5ff
```

The RSRC extraction path does not need a connected device. If OSOS or another encrypted member is also selected, DFU/hardware AES is still required for those encrypted members.

---

## 8. Fonts and Text Resources

### Fonts

Fonts are stored in the RSRC FAT16 image under:

```text
Resources/Fonts/
```

Validated Nano 5G 1.0.2 font files:

```text
AppleGothicRegular.ttf
ArialHB.ttf
CinecavXMono.otf
GeezaPro.ttf
Helvetica.ttf
HelveticaBold.ttf
HKGPW3UI.ttf
ipod_glyphs.ttf
STHeiti-Medium.ttc
Thonburi.ttf
```

Approximate sizes range from 8,720 bytes for `ipod_glyphs.ttf` to approximately 27 MB for `STHeiti-Medium.ttc`.

### Embedded OSOS text

The decrypted OSOS contains approximately 30,615 strings of at least six characters. Known anchors include:

```text
RTXC
MeCCA
SQLite
DiskMode
TCCamera
N33FirmwareWin
```

Previously observed approximate 1.0.2 offsets:

```text
RTXC             0x0000063D
SQLite           0x00058A74
MeCCA            0x0006C904
N33FirmwareWin   0x0045F3CB
```

These are binary-version-specific analysis anchors, not stable public APIs.

### Localized Silver databases

The RSRC `Resources/UI` directory contains many locale-specific files named:

```text
SilverDB.<locale>.LE.bin
```

Examples include:

```text
SilverDB.en_GB.LE.bin
SilverDB.de_DE.LE.bin
SilverDB.fr_FR.LE.bin
SilverDB.ja_JP.LE.bin
SilverDB.zh_CN.LE.bin
SilverDB.zh_TW.LE.bin
```

The SilverDB format has not yet been fully reversed.

---

## 9. UI Integration

The application currently exposes Category 2 partitions through the generic partition checklist:

```text
osos
aupd
rsrc
disk
diag
appl
chrg
bdsw
bdhw
lbat
```

The Nano 5G-specific SilverImagesDB row is dynamically shown only when:

```python
family_id == 34
```

The helper `_get_selected_partitions()` returns:

```text
silverimagesdb
```

when the Nano 5G checkbox is selected. The Category 2 workflow then ensures `rsrc` is available internally and exports the selected resource file without AES processing.

---

## 10. Build and Packaging

The PyInstaller spec includes the helper module:

```python
hiddenimports=[
    'Crypto',
    'Crypto.Cipher',
    'Crypto.Cipher.AES',
    'nano2g_device_decrypt',
    'nano2g_payloads',
    'nano5g_resources',
]
```

The packaged application is:

```text
C:\KIRO\iPodUniversalDecrypt\dist\iPodUniversalDecrypt_v3.2.0_b30.exe
```

The package was rebuilt after the Nano 5G resource integration and after the duplicate footer separator was removed.

Validation performed:

- `python -m py_compile ipod_universal_decrypt_b.py nano5g_resources.py` passed.
- Diagnostics returned no errors.
- Real RSRC fixture extraction passed.
- FamilyID 34 UI detection passed.
- SilverImagesDB extraction size/hash matched the fixture.
- PyInstaller build passed.
- Packaged executable launch passed.

---

## 11. Required Physical Test

For a fresh independent end-to-end test, use a physical Nano 5G in DFU mode:

```text
VID: 05ac
PID: 1231
```

Requirements:

- Stock Apple firmware.
- Direct native Windows USB connection.
- WinUSB driver bound to the DFU interface.
- Apple Mobile Device Service stopped.
- `iPodService` stopped.
- Avoid WSL/usbipd for this trampoline path.
- Use a persistent recovery-file location.

Recommended first test:

1. Load `iPod_1.0.2_34A20020.ipsw`.
2. Select OSOS only.
3. Run `haxdfu -v`.
4. Confirm haxed DFU re-enumeration.
5. Run OSOS decryption with recovery enabled.
6. Apply IMG1/content validation.
7. Compare output structure and, where applicable, known-good hashes.

Resource-only RSRC/SilverImagesDB extraction can be tested without the device.

---

## 12. Known Limitations and Next Work

1. Strengthen Category 2 output validation beyond file size.
2. Add a complete RSRC export mode for all resource files.
3. Add a font-export option and SHA-256 manifest.
4. Add SilverDB locale database export.
5. Reverse-engineer SilverDB and SilverImagesDB formats.
6. Verify fresh physical Nano 5G OSOS decryption on this Windows host.
7. Preserve and verify recovery state carefully during multi-hour decrypt operations.
8. Avoid firmware-storage writes; all current Nano 5G work is extraction/decryption or RAM-resident exploit execution.
