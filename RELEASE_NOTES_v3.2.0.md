# Universal iPod Firmware Decryptor v3.2.0

## Included

- Native Windows wInd3x hardware-AES workflow for supported Classic/Nano 3G/4G/5G paths.
- Legacy Loader/Core hardware-AES transport.
- Nano 5G plaintext RSRC/FAT16 export.
- Nano 5G `Resources/UI/SilverImagesDB.LE.bin` extraction.
- Dynamic model/category UI and native WinUSB setup guidance.
- Updated implementation and resource handover documentation.
- Footer/UI layout cleanup and packaged executable build.

## Release asset

The Windows executable is attached to the GitHub Release as:

```text
iPodUniversalDecrypt_v3.2.0_b30.exe
```

It is not committed to the source repository.

## Verification

- Python compilation passed.
- Diagnostics passed.
- Nano 5G SilverImagesDB fixture extraction passed.
- PyInstaller build passed.
- Packaged executable launch smoke test passed.

## Important

Hardware-AES decryption requires the correct physical device state, native Windows USB access, and the required wInd3x/WinUSB dependencies. See `KNOWLEDGE_BASE.md` and `NANO5G_IMPLEMENTATION_HANDOVER.md` before use.
