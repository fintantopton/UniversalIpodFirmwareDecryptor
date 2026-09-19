# Nano 5G Strings, Fonts, and Resource Storage Findings

**Purpose:** Handover document for continued Nano 5G firmware inspection and resource extraction work.

**Device:** iPod Nano 5th Generation, FamilyID 34, Samsung S5L8730  
**Reference IPSW:** `C:\KIRO\ipod_IPSWAnalyze\IPSW\Nano5\iPod_1.0.2_34A20020.ipsw`  
**Firmware build:** Nano 5G RetailOS 1.0.2 / `34A20020` / `N33FirmwareWin-261`

---

## Executive Findings

Nano 5G firmware content is split across two important images:

1. **OSOS IMG1** — encrypted in the IPSW and decrypted through the Nano 5G hardware AES path. It contains RetailOS executable code, constant data, UI controller data, and a large number of embedded text strings.
2. **RSRC IMG1** — plaintext format-4 resource image containing a FAT16 filesystem. It contains fonts, UI databases, sounds, games, voices, and other resource files. It does not require an attached device for extraction.

The main locations are:

```text
Decrypted OSOS body:
  embedded strings, executable code, UI/controller data

RSRC FAT16 filesystem:
  Resources/Fonts/
  Resources/UI/
  Resources/Sounds/
  Resources/Games/
  Resources/Voices/
  Resources/Speakable/
  Resources/TrainerTemplates/
```

The UI image database is:

```text
Resources/UI/SilverImagesDB.LE.bin
```

The application now exports this file through the Nano 5G-only option:

```text
SilverImagesDB.LE.bin (Nano 5G)
```

---

## Verified Decrypted OSOS Images

Known local files:

```text
C:\KIRO\iPodKnowledgeDB\Decrypted BIN\osos_decrypted_iPod_Nano_5th_Gen_1.0.1.bin
C:\KIRO\iPodKnowledgeDB\Decrypted BIN\osos_decrypted_iPod_Nano_5th_Gen_1.0.2.bin
```

### 1.0.1

```text
Size:   7,276,688 bytes
SHA256: EA4BAD8DC8C8C57EA3144F9615B92D6865AB34BEC267229B41E7B12CF6B491F4
```

### 1.0.2

```text
Size:   7,286,720 bytes
SHA256: 3269D9EDA2E7E7C406D7BFD6895BD83F27603F03A2C9F52C6CF415924E41AF81
```

The files have valid S5L8730 IMG1 structure:

```text
Magic:          8730
Version:        2.0
Format:         4
IMG1 header:    0x600 bytes
Body:           16-byte aligned
```

The reconstructed output contains the expected unsigned-image placeholders:

```text
Signature area:     0x80 bytes of 0x53 ('S')
Certificate area:   0x300 bytes of 0x43 ('C')
```

The format is consistent with the upstream wInd3x `MakeUnsigned` output format.

---

## Text String Storage

### Embedded OSOS strings

Most executable/UI text is embedded directly in the decrypted OSOS image. It is not stored as one simple text file.

The 1.0.2 analysis identified approximately:

```text
30,615 strings of at least 6 characters
32,358 detected function prologues
 1,649 ARM function prologues
30,709 Thumb function prologues
```

The text is mixed with executable code, constant tables, controller structures, and resource path references.

Examples of known strings/markers in the decrypted 1.0.2 OSOS image include:

```text
RTXC
MeCCA
SQLite
DiskMode
TCCamera
N33FirmwareWin
```

Previously observed approximate offsets in the decrypted OSOS image:

```text
RTXC             around 0x0000063D
SQLite           around 0x00058A74
MeCCA            around 0x0006C904
N33FirmwareWin   around 0x0045F3CB
```

These offsets are useful anchors for reverse engineering, but should be revalidated against the exact OSOS version before patching. The OSOS IMG1 body begins at file offset `0x600`.

### OSOS resource path references

The OSOS binary contains references to resource paths, including:

```text
Resources/UI/SilverImagesDB.LE.bin
```

This confirms that the RetailOS executable expects the resource files to be available from the RSRC filesystem.

### Localized/Silver UI databases

The RSRC `Resources/UI` directory contains language-specific Silver databases:

```text
SilverDB.ar_SA.LE.bin
SilverDB.cs_CZ.LE.bin
SilverDB.da_DK.LE.bin
SilverDB.de_DE.LE.bin
SilverDB.el_GR.LE.bin
SilverDB.en_GB.LE.bin
SilverDB.es_ES.LE.bin
SilverDB.fi_FI.LE.bin
SilverDB.fr_FR.LE.bin
SilverDB.he_IL.LE.bin
SilverDB.hr_HR.LE.bin
SilverDB.hu_HU.LE.bin
SilverDB.it_IT.LE.bin
SilverDB.ja_JP.LE.bin
SilverDB.ko_KR.LE.bin
SilverDB.nl_NL.LE.bin
SilverDB.no_NO.LE.bin
SilverDB.pl_PL.LE.bin
SilverDB.pt_BR.LE.bin
SilverDB.pt_PT.LE.bin
SilverDB.ro_RO.LE.bin
SilverDB.ru_RU.LE.bin
SilverDB.sk_SK.LE.bin
SilverDB.sv_SE.LE.bin
SilverDB.th_TH.LE.bin
SilverDB.tr_TR.LE.bin
SilverDB.zh_CN.LE.bin
SilverDB.zh_HK.LE.bin
SilverDB.zh_TW.LE.bin
```

These files are the primary candidates for localized Silver UI metadata and text-related data. They need a format-specific parser before their records can be safely edited.

`SilverImagesDB.LE.bin` is the image database and should not be assumed to contain ordinary UI text.

---

## Font Storage

Fonts are stored as ordinary files in the plaintext RSRC FAT16 filesystem:

```text
Resources/Fonts/
```

The validated Nano 5G 1.0.2 resource image contains:

| File | Approximate size |
|---|---:|
| `AppleGothicRegular.ttf` | 6,735,688 bytes |
| `ArialHB.ttf` | 25,748 bytes |
| `CinecavXMono.otf` | 79,916 bytes |
| `GeezaPro.ttf` | 89,384 bytes |
| `Helvetica.ttf` | 165,416 bytes |
| `HelveticaBold.ttf` | 166,664 bytes |
| `HKGPW3UI.ttf` | 431,696 bytes |
| `ipod_glyphs.ttf` | 8,720 bytes |
| `STHeiti-Medium.ttc` | 26,986,176 bytes |
| `Thonburi.ttf` | 241,928 bytes |

The font files can be exported without an attached Nano 5G by extracting the RSRC image and parsing its FAT16 filesystem.

---

## RSRC Image Structure

For Nano 5G 1.0.2, the MSE-extracted RSRC member is:

```text
C:\KIRO\iPodUniversalDecrypt\mse_out\rsrc
```

It begins with an S5L8730 IMG1 header:

```text
IMG1 offset:       0x0000
FAT16 volume:      0x0600
FAT16 signature:   0x0600 + 0x1FE = 0x07FE
```

Observed FAT16 BPB values:

```text
Bytes per sector:       512
Sectors per cluster:    8
Reserved sectors:       1
Number of FATs:         2
Root directory entries: 624
FAT size:               121 sectors
```

The RSRC image is format 4 and is structurally plaintext. It must not be sent through the Nano 5G AES decrypt command.

---

## SilverImagesDB Verification

The application now extracts:

```text
Resources/UI/SilverImagesDB.LE.bin
```

Validated output from the Nano 5G 1.0.2 RSRC fixture:

```text
Size:   9,793,432 bytes
SHA256: 692f8ee8102987e92d8255ae2bc54ea116b474f5a1cc80c2cfb6cbd09a96c5ff
```

The extraction code is located at:

```text
C:\KIRO\iPodUniversalDecrypt\nano5g_resources.py
```

The application integration is located at:

```text
C:\KIRO\iPodUniversalDecrypt\ipod_universal_decrypt_b.py
```

The option is visible only for FamilyID 34:

```text
SilverImagesDB.LE.bin (Nano 5G)
```

Selecting only SilverImagesDB/RSRC content does not require DFU mode or an attached device. Selecting OSOS or another encrypted IMG1 member still requires the native Nano 5G hardware-AES workflow.

---

## Current Application/Build State

Updated source files:

```text
C:\KIRO\iPodUniversalDecrypt\ipod_universal_decrypt_b.py
C:\KIRO\iPodUniversalDecrypt\nano5g_resources.py
C:\KIRO\iPodUniversalDecrypt\iPodUniversalDecrypt_b.spec
```

Packaged executable:

```text
C:\KIRO\iPodUniversalDecrypt\dist\iPodUniversalDecrypt_v3.2.0_b30.exe
```

The PyInstaller spec explicitly includes:

```text
nano5g_resources
```

Validation completed:

- Python compilation passed.
- Diagnostics passed with no errors.
- Real RSRC fixture extraction passed.
- SilverImagesDB size and SHA-256 matched the validated fixture.
- Nano 5G UI detection confirmed FamilyID 34.
- SilverImagesDB checkbox appears for FamilyID 34 and is hidden for other models.
- Packaged executable build passed.
- Packaged executable launch passed.

---

## Recommended Next-Session Work

1. **Export all Nano 5G fonts automatically.**
   - Add a `Nano 5G Fonts` option to the application.
   - Export the complete `Resources/Fonts` directory.
   - Preserve original filenames and record SHA-256 values.

2. **Export all Silver UI databases.**
   - Add a `SilverDB language databases` option.
   - Export every `SilverDB.*.LE.bin` file from `Resources/UI`.
   - Record size and SHA-256 for each locale.

3. **Reverse-engineer the SilverDB format.**
   - Compare locale files structurally.
   - Identify headers, record tables, offsets, string tables, and image/resource references.
   - Use the OSOS references to determine how the database is loaded.

4. **Analyze `SilverImagesDB.LE.bin`.**
   - Identify its header and record format.
   - Map image IDs to Silver UI screens and controls.
   - Determine whether records contain compressed images, palettes, or metadata.

5. **Extract and catalog all RSRC files.**
   - Export `Resources/Sounds`, `Resources/Games`, `Resources/Voices`, `Resources/Speakable`, and `Resources/TrainerTemplates`.
   - Produce a manifest containing path, size, SHA-256, and detected file type.

6. **Improve OSOS text analysis.**
   - Separate code/data strings from UI/localization strings.
   - Identify string-reference tables.
   - Determine whether language selection changes which strings are loaded from OSOS or RSRC.

7. **Create a safe modification pipeline.**
   - Extract a target string/font/resource.
   - Modify only the selected file.
   - Rebuild the RSRC filesystem while preserving FAT layout and alignment.
   - Validate that the rebuilt image remains structurally readable before considering device testing.

---

## Important Safety Boundary

This document concerns static extraction and analysis. RSRC extraction is read-only and does not require device access. OSOS decryption uses the existing RAM-resident hardware-AES/wInd3x workflow and should not be confused with writing modified firmware back to NAND, NOR, or flash storage.
