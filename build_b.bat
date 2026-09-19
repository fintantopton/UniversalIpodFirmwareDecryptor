@echo off
REM ============================================================
REM Universal iPod Firmware Decryptor v2.1.0 - Build Script
REM Standalone build - bundles wInd3x binary
REM ============================================================

echo.
echo ========================================
echo  Building iPodUniversalDecrypt_b.exe
echo  (Standalone - bundled wInd3x)
echo ========================================
echo.

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH!
    echo Install Python from python.org
    pause
    exit /b 1
)

REM Check for PyInstaller
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

REM Verify wInd3x binary exists
if not exist "..\AppPatcher\wInd3x-src\wInd3x" (
    echo ERROR: wInd3x binary not found at ..\AppPatcher\wInd3x-src\wInd3x
    echo Make sure the Linux wInd3x binary is in that location.
    pause
    exit /b 1
)

REM Build the EXE using spec file
echo Building EXE with bundled wInd3x...
python -m PyInstaller --clean iPodUniversalDecrypt_b.spec

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Build complete!
echo  EXE: dist\iPodUniversalDecrypt_b.exe
echo ========================================
echo.
pause
