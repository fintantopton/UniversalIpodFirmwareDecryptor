# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the macOS (Apple Silicon / Intel) .app bundle.

Build with (see build_macos.sh for the full flow):

    python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b-macos.spec

Produces: dist/iPodFirmwareDecryptor.app  (onedir, fast launch)

The app is ad-hoc code-signed by the build script. Vendor binaries
(wInd3x darwin build, libusb dylib) are bundled when present in vendor/.
"""

import os
import platform
import re

# Keep the bundle version in sync with the app source.
# (PyInstaller execs the spec with CWD == the spec's directory; __file__
# is not defined in the spec namespace on Python 3.13.)
with open("ipod_universal_decrypt_b.py", encoding="utf-8") as _f:
    _src = _f.read()
_APP_VERSION = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', _src, re.MULTILINE).group(1)
_APP_BUILD = re.search(r'^APP_BUILD\s*=\s*(\d+)', _src, re.MULTILINE).group(1)

_ARCH = platform.machine().lower()  # arm64 on Apple Silicon
if _ARCH not in ("arm64", "x86_64"):
    _ARCH = "arm64"


def _vendor(name):
    """Include a vendor file when it exists (build script prepares them)."""
    path = os.path.join("vendor", name)
    if os.path.isfile(path):
        return (path, ".")
    return None


_icon = "macos/AppIcon.icns"
if not os.path.isfile(_icon):
    _icon = None

_datas = [
    item for item in (
        _vendor(f"wInd3x-darwin-{_ARCH}"),
        _vendor("wInd3x-darwin"),
        _vendor("wInd3x"),
        _vendor("libusb-1.0.dylib"),
    ) if item
]

a = Analysis(
    ["ipod_universal_decrypt_b.py"],
    pathex=[],
    binaries=[],
    datas=_datas,
    # The Nano 2G iBugger transport (nano2g_ibugger_usb.py) uses libusb via
    # ctypes — no Python USB dependency is required.
    hiddenimports=[
        # pycryptodome (AES for the Nano 2G public-key decrypt)
        "Crypto", "Crypto.Cipher", "Crypto.Cipher.AES",
        # local modules (imported lazily in places — make sure they ship)
        "ipod_platform", "ibugger_transport",
        "nano2g_device_decrypt", "nano2g_ibugger_usb", "nano2g_payloads",
        "nano5g_resources", "mse_members",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["numpy", "pandas", "matplotlib", "scipy", "PIL", "cv2"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# PyInstaller 6.x: BUNDLE takes COLLECT (onedir) / EXE — not the Analysis.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="iPodFirmwareDecryptor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # GUI app; CLI mode still prints to the launching terminal
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="iPodFirmwareDecryptor",
)
app = BUNDLE(
    coll,
    name="iPodFirmwareDecryptor.app",
    icon=_icon,
    bundle_identifier="org.freemyipod.UniversalIpodFirmwareDecryptor",
    info_plist={
        "CFBundleShortVersionString": _APP_VERSION,
        # Apple expects a plain dotted/numeric string here (the GUI shows
        # the full "v3.3.0 (build 40)" from the app source itself).
        "CFBundleVersion": _APP_BUILD,
        "CFBundleDisplayName": "Universal iPod Firmware Decryptor",
        "NSHumanReadableCopyright":
            "2026 Ricardo de Koning. Experimental research software.",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "11.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
    },
)
