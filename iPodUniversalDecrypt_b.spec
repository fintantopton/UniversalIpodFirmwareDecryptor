# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['ipod_universal_decrypt_b.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('../AppPatcher/wInd3x-src/wInd3x', '.'),
        ('../AppPatcher/wInd3x-src/wInd3x-write-musl', '.'),
        ('../AppPatcher/wInd3x-src/wInd3x-win.exe', '.'),
        ('../AppPatcher/wInd3x-src/libusb-1.0.dll', '.'),
        ('zadig.exe', '.'),
        ('icon.ico', '.'),
    ],
    # Nano 2G device-based decrypt (nano2g_device_decrypt.py, nano2g_payloads.py)
    # is a local import next to the entry script, so PyInstaller's Analysis
    # bundles it automatically. It needs no external DLL — only
    # winusb.dll/setupapi.dll/kernel32.dll, which ship with Windows.
    hiddenimports=['Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES',
                   'nano2g_device_decrypt', 'nano2g_payloads',
                   'nano5g_resources'],
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
    name='iPodUniversalDecrypt_v3.2.0_b30',
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
