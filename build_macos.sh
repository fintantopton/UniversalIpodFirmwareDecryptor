#!/usr/bin/env bash
# ============================================================================
# build_macos.sh — build the Universal iPod Firmware Decryptor for macOS
# (Apple Silicon arm64 primary, Intel x86_64 supported).
#
# Usage:
#   ./build_macos.sh                 # build dist/iPodFirmwareDecryptor.app
#   ./build_macos.sh --pkg           # also build a .pkg installer
#   ./build_macos.sh --dmg           # also build a .dmg (drag-to-Applications)
#   ./build_macos.sh --all           # app + pkg + dmg
#   ./build_macos.sh --require-wind3x  # fail if no native wInd3x can be made
#
# Prerequisites:
#   * macOS 11+ (Apple Silicon or Intel)
#   * Python 3.9+ WITH Tk (python.org "python3" works out of the box;
#     Homebrew Python needs: brew install python-tk)
#   * Optional: Go >= 1.23 (to compile wInd3x for macOS when no binary is vendored)
#   * Optional: brew install libusb   (Nano 2G iBugger path + wInd3x support)
#
# Output:
#   dist/iPodFirmwareDecryptor.app        GUI app (ad-hoc signed)
#   dist/iPodFirmwareDecryptor-<v>.pkg    installer (.app + /usr/local/bin CLI)
#   dist/iPodFirmwareDecryptor-<v>.dmg    disk image
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

BUILD_PKG=0
BUILD_DMG=0
REQUIRE_WIND3X=0
for arg in "$@"; do
  case "$arg" in
    --pkg)            BUILD_PKG=1 ;;
    --dmg)            BUILD_DMG=1 ;;
    --all)            BUILD_PKG=1; BUILD_DMG=1 ;;
    --require-wind3x) REQUIRE_WIND3X=1 ;;
    -h|--help)        grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg (see --help)"; exit 2 ;;
  esac
done

# ----------------------------------------------------------------------------
# 1. Environment checks
# ----------------------------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: build_macos.sh must run on macOS (use the Windows build on Windows)." >&2
  exit 1
fi

ARCH="$(uname -m)"          # arm64 | x86_64
echo "==> Building for macOS ($ARCH)"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "ERROR: $PYTHON not found. Install Python 3.9+ (https://www.python.org/downloads/macos/)." >&2
  exit 1
fi
if ! "$PYTHON" -c 'import tkinter' >/dev/null 2>&1; then
  echo "ERROR: this Python has no Tkinter." >&2
  echo "  * python.org Python includes Tk — preferred." >&2
  echo "  * Homebrew Python:  brew install python-tk" >&2
  exit 1
fi
echo "==> Using $($PYTHON -c 'import sys; print(sys.executable)') ($($PYTHON --version 2>&1))"

# ----------------------------------------------------------------------------
# Go helper: wInd3x requires Go >= 1.23 (log/slog, slices, toolchain line)
# ----------------------------------------------------------------------------
GO_MIN="1.23.0"
go_version_of() {
  "$1" version 2>/dev/null | awk '{print $3}' | sed 's/^go//'
}
go_version_ok() {
  local ver
  ver=$(go_version_of "$1")
  [ -n "$ver" ] || return 1
  [ "$(printf '%s\n%s\n' "$ver" "$GO_MIN" | sort -V | head -n 1)" = "$GO_MIN" ]
}

# ----------------------------------------------------------------------------
# 2. Virtualenv with build deps
# ----------------------------------------------------------------------------
VENV=".venv-macos"
if [[ ! -d "$VENV" ]]; then
  echo "==> Creating virtualenv $VENV"
  "$PYTHON" -m venv "$VENV"
fi
VENV_PY="$VENV/bin/python"
echo "==> Installing/updating build dependencies"
"$VENV_PY" -m pip install --quiet --upgrade pip
"$VENV_PY" -m pip install --quiet "pyinstaller>=6.0" "pycryptodome>=3.15"

# ----------------------------------------------------------------------------
# 3. App icon (ICON.png -> macos/AppIcon.icns via sips/iconutil)
# ----------------------------------------------------------------------------
if [[ -f "macos/AppIcon.icns" && -f "ICON.png" && \
      ! "ICON.png" -nt "macos/AppIcon.icns" ]]; then
  echo "==> App icon up to date"
else
  echo "==> Generating macos/AppIcon.icns from ICON.png"
  mkdir -p macos build/icon.iconset
  rm -f build/icon.iconset/*
  for size in 16 32 64 128 256 512; do
    sips -z "$size" "$size" ICON.png \
      --out "build/icon.iconset/icon_${size}x${size}.png" >/dev/null
  done
  cp build/icon.iconset/icon_32x32.png   build/icon.iconset/icon_16x16@2x.png
  cp build/icon.iconset/icon_64x64.png   build/icon.iconset/icon_32x32@2x.png
  cp build/icon.iconset/icon_256x256.png build/icon.iconset/icon_128x128@2x.png
  cp build/icon.iconset/icon_512x512.png build/icon.iconset/icon_256x256@2x.png
  # 512@2x (1024) — sips upscales; acceptable for an ad-hoc build
  sips -z 1024 1024 ICON.png \
    --out build/icon.iconset/icon_512x512@2x.png >/dev/null
  iconutil -c icns build/icon.iconset -o macos/AppIcon.icns
  echo "==> Wrote macos/AppIcon.icns"
fi

# ----------------------------------------------------------------------------
# 4. Vendor binaries
# ----------------------------------------------------------------------------
WIND3X_NAME="wInd3x-darwin-${ARCH}"
have_wind3x=0
if [[ -f "vendor/$WIND3X_NAME" ]]; then
  have_wind3x=1
  echo "==> Vendored wInd3x found: vendor/$WIND3X_NAME"
fi

if [[ $have_wind3x -eq 0 ]]; then
  # Pick the newest suitable Go: Homebrew locations first, then PATH.
  GO_BIN=""
  for candidate in /opt/homebrew/bin/go /usr/local/bin/go; do
    if [[ -x "$candidate" ]] && go_version_ok "$candidate"; then
      GO_BIN="$candidate"
      break
    fi
  done
  if [[ -z "$GO_BIN" ]] && command -v go >/dev/null 2>&1 \
      && go_version_ok "$(command -v go)"; then
    GO_BIN="$(command -v go)"
  fi

  if [[ -n "$GO_BIN" ]]; then
    echo "==> Building wInd3x for macOS with Go ($(go_version_of "$GO_BIN"), $GO_BIN)"
    mkdir -p build
    if [[ ! -d "build/wInd3x-src" ]]; then
      git clone --depth 1 https://github.com/freemyipod/wInd3x.git build/wInd3x-src
    fi
    ( cd build/wInd3x-src \
      && GOOS=darwin GOARCH="$ARCH" CGO_ENABLED=0 \
         "$GO_BIN" build -o "../../vendor/$WIND3X_NAME" ./cmd/wInd3x )
    have_wind3x=1
  else
    # Report the best Go we could find so the error message is actionable.
    found_ver=""
    for candidate in /opt/homebrew/bin/go /usr/local/bin/go \
                     "$(command -v go 2>/dev/null)"; do
      if [[ -n "$candidate" && -x "$candidate" ]]; then
        found_ver="$(go_version_of "$candidate")"
        break
      fi
    done
    if [[ -n "$found_ver" ]]; then
      echo "ERROR: wInd3x requires Go >= $GO_MIN, but found Go $found_ver." >&2
      echo "  Upgrade it with:   brew install go   (or: brew upgrade go)" >&2
      echo "  or download:       https://go.dev/dl/" >&2
    else
      echo "ERROR: no Go toolchain found, and wInd3x needs Go >= $GO_MIN." >&2
      echo "  Install it with:   brew install go" >&2
    fi
    echo "  (or place a prebuilt binary at vendor/$WIND3X_NAME" >&2
    echo "   — source: https://github.com/freemyipod/wInd3x)" >&2
    if [[ $REQUIRE_WIND3X -eq 1 ]]; then
      exit 1
    fi
    echo "WARNING: continuing without wInd3x — device-AES decrypt" >&2
    echo "         (Category 2) will be unavailable; raw/plaintext" >&2
    echo "         extraction, Nano 2G and Nano 5G exports still work." >&2
  fi
fi

# libusb (optional; needed for the Nano 2G iBugger transport and useful for
# the Go wInd3x binary, which links libusb dynamically).
if [[ -f "vendor/libusb-1.0.dylib" ]]; then
  echo "==> Bundling vendor/libusb-1.0.dylib"
else
  LIBUSB=""
  for prefix in /opt/homebrew /usr/local; do
    if [[ -f "$prefix/opt/libusb/lib/libusb-1.0.dylib" ]]; then
      LIBUSB="$prefix/opt/libusb/lib/libusb-1.0.dylib"
      break
    fi
  done
  if [[ -n "$LIBUSB" ]]; then
    cp "$LIBUSB" vendor/libusb-1.0.dylib
    echo "==> Copied libusb from $LIBUSB -> vendor/libusb-1.0.dylib"
  else
    echo "NOTE: libusb not found (brew install libusb)." >&2
    echo "      Only the Nano 2G iBugger path needs it; the app will tell you" >&2
    echo "      if it is required." >&2
  fi
fi

# Point wInd3x at the bundled libusb (Go/cgo builds link
# @rpath/libusb-1.0.dylib; add an rpath to the binary's own directory).
if [[ -f "vendor/$WIND3X_NAME" && -f "vendor/libusb-1.0.dylib" ]]; then
  install_name_tool -add_rpath "@executable_path" "vendor/$WIND3X_NAME" 2>/dev/null || true
fi

# ----------------------------------------------------------------------------
# 5. PyInstaller (onedir .app)
# ----------------------------------------------------------------------------
echo "==> Running PyInstaller"
rm -rf "build/iPodUniversalDecrypt_b-macos"
"$VENV_PY" -m PyInstaller --clean --noconfirm iPodUniversalDecrypt_b-macos.spec

APP="dist/iPodFirmwareDecryptor.app"
if [[ ! -d "$APP" ]]; then
  echo "ERROR: PyInstaller did not produce $APP" >&2
  exit 1
fi

# ----------------------------------------------------------------------------
# 6. Ad-hoc code signature (local builds; no Developer ID required)
# ----------------------------------------------------------------------------
echo "==> Code-signing (ad-hoc)"
codesign --force --deep --sign - "$APP"

echo
echo "==> Built: $APP"
echo "    First launch: right-click the app -> Open (ad-hoc signed, not notarized)."
echo "    CLI check:    $APP/Contents/MacOS/iPodFirmwareDecryptor --check"

VERSION="$("$VENV_PY" - <<'EOF'
import re
src = open("ipod_universal_decrypt_b.py", encoding="utf-8").read()
print(re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', src, re.M).group(1))
EOF
)"

# ----------------------------------------------------------------------------
# 7. Optional .pkg installer
# ----------------------------------------------------------------------------
if [[ $BUILD_PKG -eq 1 ]]; then
  echo
  echo "==> Building .pkg installer (pkgbuild/productbuild)"
  PKG_STAGE="build/pkgroot"
  rm -rf "$PKG_STAGE"
  mkdir -p "$PKG_STAGE/Applications" "$PKG_STAGE/usr/local/bin"
  cp -R "$APP" "$PKG_STAGE/Applications/"
  cat > "$PKG_STAGE/usr/local/bin/ipod-decrypt" <<'EOS'
#!/bin/sh
# Universal iPod Firmware Decryptor — CLI entry point (installed by the .pkg)
exec "/Applications/iPodFirmwareDecryptor.app/Contents/MacOS/iPodFirmwareDecryptor" --cli "$@"
EOS
  chmod +x "$PKG_STAGE/usr/local/bin/ipod-decrypt"

  IDENT="org.freemyipod.UniversalIpodFirmwareDecryptor"
  rm -f build/App.pkg
  pkgbuild --root "$PKG_STAGE" \
    --identifier "$IDENT" \
    --version "$VERSION" \
    build/App.pkg
  productbuild --components build/App.pkg "/Applications/iPodFirmwareDecryptor" \
    "dist/iPodFirmwareDecryptor-${VERSION}.pkg"
  echo "==> Built: dist/iPodFirmwareDecryptor-${VERSION}.pkg"
  echo "    Installs the .app to /Applications and 'ipod-decrypt' to /usr/local/bin."
fi

# ----------------------------------------------------------------------------
# 8. Optional .dmg
# ----------------------------------------------------------------------------
if [[ $BUILD_DMG -eq 1 ]]; then
  echo
  echo "==> Building .dmg"
  DMG_SRC="build/dmg"
  rm -rf "$DMG_SRC"
  mkdir -p "$DMG_SRC"
  cp -R "$APP" "$DMG_SRC/"
  ln -s /Applications "$DMG_SRC/Applications"
  hdiutil create -volname "iPodFirmwareDecryptor-${VERSION}" \
    -srcfolder "$DMG_SRC" -ov -format UDZO \
    "dist/iPodFirmwareDecryptor-${VERSION}.dmg"
  echo "==> Built: dist/iPodFirmwareDecryptor-${VERSION}.dmg"
fi

echo
echo "All done. Run './run_macos.sh' to launch the app from source."
