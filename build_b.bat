@echo off
setlocal

echo ========================================
echo Universal iPod Firmware Decryptor build
echo ========================================

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python was not found in PATH.
    exit /b 1
)

python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: PyInstaller is not installed.
    echo Install it with: python -m pip install pyinstaller
    exit /b 1
)

if not exist "vendor\wInd3x-win.exe" (
    echo ERROR: vendor\wInd3x-win.exe is missing.
    echo See BUILD.md for external dependency setup.
    exit /b 1
)
if not exist "vendor\libusb-1.0.dll" (
    echo ERROR: vendor\libusb-1.0.dll is missing.
    echo See BUILD.md for external dependency setup.
    exit /b 1
)

python -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b.spec
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    exit /b 1
)

echo.
echo Build complete:
echo dist\iPodUniversalDecrypt_v3.2.0_b30.exe
endlocal
