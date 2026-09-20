# -*- mode: python ; coding: utf-8 -*-

import os


def _dependency(name):
    """Use portable vendor assets first, then the local development layout."""
    for path in (
        os.path.join('vendor', name),
        os.path.join('..', 'AppPatcher', 'wInd3x-src', name),
    ):
        if os.path.isfile(path):
            return (path, '.')
    return None


_vendor_files = [
    'wInd3x', 'wInd3x-write-musl', 'wInd3x-win.exe',
    'libusb-1.0.dll', 'zadig.exe',
]
_datas = [item for item in (_dependency(name) for name in _vendor_files) if item]
_datas.append(('icon.ico', '.'))

a = Analysis(
    ['ipod_universal_decrypt_b.py'],
    pathex=[],
    binaries=[],
    datas=_datas,
    # Nano 2G device-based decrypt (nano2g_device_decrypt.py, nano2g_payloads.py)
    # is a local import next to the entry script, so PyInstaller's Analysis
    # bundles it automatically. It needs no external DLL — only
    # winusb.dll/setupapi.dll/kernel32.dll, which ship with Windows.
    hiddenimports=['Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES',
                   'nano2g_device_decrypt', 'nano2g_payloads',
                   'nano5g_resources', 'mse_members'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'pandas', 'matplotlib', 'scipy', 'PIL', 'cv2'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='iPodUniversalDecrypt_v3.2.2_b32',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon='icon.ico',
)
