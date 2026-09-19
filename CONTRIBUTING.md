# Contributing

## Scope

Contributions should improve extraction correctness, device compatibility, documentation, validation, or safe resource analysis.

## Before opening a change

- Keep firmware images, device dumps, recovery files, executables, and generated build output out of commits.
- Do not add credentials, USB captures containing user data, or personal device data.
- Preserve the RAM-only/no-firmware-storage-write safety boundary.
- Distinguish verified behavior from exploratory or inferred behavior.
- Update the relevant method documentation when changing a decryption path.

## Validation

For Python changes:

```powershell
python -m py_compile ipod_universal_decrypt_b.py nano2g_device_decrypt.py nano5g_resources.py
```

For a packaged build:

```powershell
python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec
```

For resource extraction changes, validate against a known fixture and record size/hash results without committing the fixture.

## Pull requests

Describe:

1. The affected device/path.
2. Whether behavior is verified on hardware, a fixture, or static analysis only.
3. The safety implications.
4. The validation commands and results.
