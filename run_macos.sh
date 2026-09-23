#!/usr/bin/env bash
# run_macos.sh — run the GUI from source on macOS (development).
#
#   ./run_macos.sh                # launch the Tkinter GUI
#   ./run_macos.sh --check        # preflight platform checks
#   ./run_macos.sh --cli ...      # headless mode (any --cli arguments)
#
# Requirements: a Python 3.9+ with Tk (python.org Python, or
# `brew install python-tk`). Optional: `brew install libusb` (Nano 2G)
# and a native wInd3x build in vendor/ (Category 2 device AES).
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# Prefer a project venv if one was created by build_macos.sh.
if [[ -x ".venv-macos/bin/python" ]]; then
  PYTHON=".venv-macos/bin/python"
fi

"$PYTHON" -c 'import tkinter' 2>/dev/null || {
  echo "ERROR: Tkinter is not available for $PYTHON." >&2
  echo "  python.org Python includes Tk; for Homebrew Python: brew install python-tk" >&2
  echo "  You can still use the CLI: $PYTHON ipod_universal_decrypt_b.py --cli" >&2
  exit 1
}

exec "$PYTHON" ipod_universal_decrypt_b.py "$@"
