# Universal iPod Firmware Decryptor v3.2.1

This release is the cleaned open-source package for the v3.2 application.

## Included

- Active application source and supporting decryption modules.
- Per-model method documentation in `DECRYPTION_METHODS.md`.
- Complete build instructions in `BUILD.md`.
- Portable PyInstaller dependency layout using ignored `vendor/` files.
- Runtime safety, third-party, and contribution documentation.
- Nano 5G plaintext RSRC/SilverImagesDB export support.
- Native Windows hardware-AES integration for supported models.

## Executable

The latest compiled executable remains:

```text
iPodUniversalDecrypt_v3.2.0_b30.exe
```

It is attached as a release asset and is not committed to the source repository. The source/package cleanup in this release does not change the executable binary.

## Excluded

The repository and release source package intentionally exclude firmware/IPSW samples, extracted device data, recovery files, generated build output, dependency binaries, and handover-only documents.

## Build

See `BUILD.md`. Place the required external dependencies in the ignored `vendor/` directory, then run:

```powershell
python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec
```
