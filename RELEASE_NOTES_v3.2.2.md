# Universal iPod Firmware Decryptor v3.2.2

Packaging/build follow-up to v3.2.1.

## Changes

- Build specification now bundles only vendor files that are present in the local `vendor/` directory.
- Complete per-model decryption documentation is in `DECRYPTION_METHODS.md`.
- Complete compile instructions are in `BUILD.md`.
- Handover-only documents and old release notes are not part of the source package.
- The executable is unchanged from the validated v3.2.0 build 30 and remains available as a release asset.

## Build

Place external dependencies in the ignored `vendor/` directory and run:

```powershell
python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec
```

See `BUILD.md` for the complete layout and dependency sources.
