# Build Instructions

## Requirements

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

## Prepare the vendor directory

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

## Install Python build dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install pyinstaller pycryptodome
```

`pycryptodome` is optional for historical software-AES comparison code; device-AES paths use the device hardware engine.

## Development run

```powershell
python ipod_universal_decrypt_b.py
```

## Compile the executable

```powershell
python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec
```

Output:

```text
dist\iPodUniversalDecrypt_v3.2.0_b30.exe
```

The included `build_b.bat` performs the same build after checking Python, PyInstaller, and the required vendor files.

## Validation

```powershell
python -m py_compile ipod_universal_decrypt_b.py nano2g_device_decrypt.py nano5g_resources.py
```

For Nano 5G resource extraction, validate against a known RSRC fixture without committing that fixture:

```powershell
python -c "from nano5g_resources import extract_silver_images_db; print('module import OK')"
```

## Driver setup for hardware-AES paths

1. Put the target iPod in the correct device mode.
2. Install WinUSB for its Apple DFU interface using Zadig.
3. Stop Apple Mobile Device Service and iPodService before native USB access.
4. Use direct native USB for trampoline devices; do not use USB/IP for those paths.

## Release packaging

Do not commit:

- `dist/`
- `build/`
- firmware/IPSW files
- extracted partitions
- recovery files
- dependency binaries

Attach the compiled executable to a GitHub Release instead.
