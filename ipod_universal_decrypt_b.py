"""
Universal iPod Firmware Decryptor v3.0.0
=========================================
Decrypts the iPod RetailOS (OSOS) for ALL iPod models.

Category 1 (Not Encrypted):
  iPod 1G-5G, Nano 1G, Mini 1G/2G — extract from IPSW, no device needed.

Category 2 (Hardware AES):
  iPod Nano 2G-7G, iPod Classic — requires device in DFU mode.

Standalone Windows build. No WSL required.
Uses native wInd3x-win.exe with WinUSB/libusb for direct USB communication.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import os
import sys
import time
import zipfile
import re
import ctypes
import shutil
import json
import struct
import tempfile
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nano2g_device_decrypt as nano2g_device  # noqa: E402
from nano5g_resources import (  # noqa: E402
    Nano5GResourceError,
    extract_silver_images_db,
)

# ============================================================
# Constants
# ============================================================
APP_NAME = "Universal iPod Firmware Decryptor"
APP_VERSION = "3.2.0"
APP_BUILD = 30

APPLE_VID = "05ac"
DFU_PIDS = ["1223", "1225", "1231", "1232", "1234", "1242", "1250"]

WIND3X_WIN_NAME = 'wInd3x-win.exe'
LIBUSB_DLL_NAME = 'libusb-1.0.dll'
ZADIG_NAME = 'zadig.exe'

# Recovery state persists next to output file on Windows filesystem
RECOVERY_SUFFIX = '.recovery.dat'
PROGRESS_SUFFIX = '.progress.json'
MAX_RETRY_ATTEMPTS = 10

# Nano 2G (S5L8701) AES-128-CBC key — publicly known "0x837" key
# Source: TheAppleWiki AES Keys page (derived from S5L8900 GID key)
NANO2G_KEY = bytes.fromhex('188458A6D15034DFE386F23B61D43774')
NANO2G_IV = bytes(16)  # All zeros
NANO2G_HEADER_SIZE = 0x800  # Per-partition header retained before AES body
NANO2G_OUTER_MARKER_OFFSET = 0x100
NANO2G_OUTER_MARKER = b']ih['
NANO2G_DIRECTORY_OFFSET = 0x4800
NANO2G_DIRECTORY_RECORD_SIZE = 0x28
NANO2G_DIRECTORY_RECORD_FORMAT = '<4s4s8I'
NANO2G_PARTITION_ALIASES = {
    b'crsr': 'rsrc',
    b'soso': 'osos',
    b'dpua': 'aupd',
}
NANO2G_SUPPORTED_PARTITIONS = frozenset(NANO2G_PARTITION_ALIASES.values())


def parse_nano2g_partitions(fw_data):
    """Parse and validate the S5L8701 DNAN partition directory.

    Returns canonical UI names mapped to exact (offset, total_length) source
    ranges. The directory length is the encrypted payload length; the Nano 2G
    format adds a local 0x800-byte header before that payload. Inter-partition
    bytes are therefore not gaps and are never omitted from an export.
    """
    marker_end = NANO2G_OUTER_MARKER_OFFSET + len(NANO2G_OUTER_MARKER)
    if len(fw_data) < marker_end or fw_data[NANO2G_OUTER_MARKER_OFFSET:marker_end] != NANO2G_OUTER_MARKER:
        raise ValueError("Nano 2G outer ]ih[ marker not found")

    records = {}
    offset = NANO2G_DIRECTORY_OFFSET
    for index in range(64):
        start = offset + index * NANO2G_DIRECTORY_RECORD_SIZE
        end = start + NANO2G_DIRECTORY_RECORD_SIZE
        if end > len(fw_data):
            raise ValueError("Nano 2G directory is truncated")

        device, raw_name, _reserved, part_offset, part_length, *_ = struct.unpack(
            NANO2G_DIRECTORY_RECORD_FORMAT, fw_data[start:end])
        if device == b'\x00' * 4:
            break
        if device != b'DNAN':
            raise ValueError(f"Unexpected Nano 2G directory device marker at record {index}")
        canonical_name = NANO2G_PARTITION_ALIASES.get(raw_name)
        if canonical_name is None:
            raise ValueError(f"Unsupported Nano 2G partition name: {raw_name!r}")
        if canonical_name in records:
            raise ValueError(f"Duplicate Nano 2G partition: {canonical_name}")
        if part_length <= 0 or part_length % 16:
            raise ValueError(f"Invalid {canonical_name} partition length: {part_length:#x}")
        part_end = part_offset + NANO2G_HEADER_SIZE + part_length
        if part_offset < 0 or part_end > len(fw_data):
            raise ValueError(
                f"{canonical_name} partition range {part_offset:#x}:{part_end:#x} exceeds firmware"
            )
        records[canonical_name] = (part_offset, part_end - part_offset)

    if set(records) != NANO2G_SUPPORTED_PARTITIONS:
        missing = sorted(NANO2G_SUPPORTED_PARTITIONS - set(records))
        raise ValueError(f"Nano 2G directory missing partitions: {', '.join(missing)}")
    return records


def decrypt_nano2g_body(encrypted_body):
    """AES-CBC decrypt one validated, block-aligned Nano 2G partition body."""
    if not encrypted_body or len(encrypted_body) % 16:
        raise ValueError("Nano 2G encrypted body is not AES-block aligned")

    try:
        from Crypto.Cipher import AES
        return AES.new(NANO2G_KEY, AES.MODE_CBC, NANO2G_IV).decrypt(encrypted_body)
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            decryptor = Cipher(
                algorithms.AES(NANO2G_KEY), modes.CBC(NANO2G_IV)
            ).decryptor()
            return decryptor.update(encrypted_body) + decryptor.finalize()
        except ImportError:
            temp_enc = temp_dec = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as enc_file:
                    temp_enc = enc_file.name
                    enc_file.write(encrypted_body)
                with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as dec_file:
                    temp_dec = dec_file.name
                result = subprocess.run(
                    ['openssl', 'enc', '-d', '-aes-128-cbc', '-K', NANO2G_KEY.hex(),
                     '-iv', NANO2G_IV.hex(), '-in', temp_enc, '-out', temp_dec, '-nopad'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    raise RuntimeError(f"openssl AES decryption failed: {result.stderr.strip()}")
                with open(temp_dec, 'rb') as dec_file:
                    return dec_file.read()
            finally:
                for path in (temp_enc, temp_dec):
                    if path:
                        try:
                            os.remove(path)
                        except OSError:
                            pass


def prepare_nano2g_partition(canonical_name, partition_data):
    """Prepare one exact Nano 2G range for export.

    RSRC is structurally plaintext and is copied unchanged. OSOS/AUPD retain
    their local 0x800-byte container header while only the following body is
    AES-CBC processed. The key/mode are known, but the result is intentionally
    not called cryptographically verified without a known-good fixture/device.
    """
    if canonical_name == 'rsrc':
        return partition_data, 'raw/plaintext'
    if canonical_name not in ('osos', 'aupd'):
        raise ValueError(f"Unsupported Nano 2G partition: {canonical_name}")
    if len(partition_data) <= NANO2G_HEADER_SIZE:
        raise ValueError(f"{canonical_name} partition has no body after local header")
    header = partition_data[:NANO2G_HEADER_SIZE]
    body = decrypt_nano2g_body(partition_data[NANO2G_HEADER_SIZE:])
    return header + body, 'AES body processed; local 0x800-byte header retained'

# ============================================================
# Model Database
# ============================================================
# Format: family_id -> (model_name, category, soc, dfu_pid)
# category 1 = not encrypted, category 2 = hardware AES
IPOD_MODELS = {
    # iPod (PortalPlayer — NOT encrypted)
    1:  ("iPod 1st Gen (PP5002)", 1, "PP5002", None),
    2:  ("iPod 3rd Gen (PP5020)", 1, "PP5020", None),
    3:  ("iPod Mini 1st Gen (PP5020C)", 1, "PP5020C", None),
    4:  ("iPod 4th Gen Mono (PP5020C)", 1, "PP5020C", None),
    5:  ("iPod 4th Gen Photo (PP5020C)", 1, "PP5020C", None),
    6:  ("iPod Mini 1st Gen (PP5020C) alt", 1, "PP5020C", None),
    7:  ("iPod Mini 2nd Gen (PP5020C)", 1, "PP5020C", None),
    10: ("iPod 4th Gen Mono (PP5020C) alt", 1, "PP5020C", None),
    11: ("iPod 4th Gen Color (PP5020C)", 1, "PP5020C", None),
    12: ("iPod Nano 1st Gen (PP5021C)", 1, "PP5021C", None),
    13: ("iPod 5th Gen Video (BCM2722)", 1, "BCM2722", None),
    14: ("iPod Nano 1st Gen 2GB (PP5021C)", 1, "PP5021C", None),
    17: ("iPod Nano 1st Gen 4GB (PP5021C)", 1, "PP5021C", None),
    # iPod Nano 2G (S5L8701 — Hardware AES via Notes-exploit iBugger Loader/Core.
    # The public "0x837" key does NOT apply to this device; the real key is
    # fused in hardware and only accessible by running the AES engine on the
    # device itself. See iPodKnowledgeDB/RESEARCH_DOCS/
    # NANO2G_S5L8701_USB_TRANSPORT_AND_DECRYPTION.md for the full record.)
    19: ("iPod Nano 2nd Gen (S5L8701)", 4, "S5L8701", "8642"),
    29: ("iPod Nano 2nd Gen 8GB (S5L8701)", 4, "S5L8701", "8642"),
    # iPod 5th Gen Video / 5.5G (BCM2722 — NOT encrypted)
    20: ("iPod 5th Gen Video Late (BCM2722)", 1, "BCM2722", None),
    25: ("iPod 5.5G Video Enhanced (BCM2722)", 1, "BCM2722", None),
    # iPod Classic (S5L8702 — Hardware AES)
    24: ("iPod Classic 6G Initial (S5L8702)", 2, "S5L8702", "1223"),
    33: ("iPod Classic 6.5G Rev A 120GB (S5L8702)", 2, "S5L8702", "1223"),
    35: ("iPod Classic 7G Rev B (S5L8702)", 2, "S5L8702", "1223"),
    38: ("iPod Classic 7G Rev C (S5L8702)", 2, "S5L8702", "1250"),
    # iPod Nano 3G+ (S5L87xx — Hardware AES)
    26: ("iPod Nano 3rd Gen 4GB (S5L8702)", 2, "S5L8702", "1223"),
    27: ("iPod Nano 3rd Gen 8GB (S5L8702)", 2, "S5L8702", "1223"),
    31: ("iPod Nano 4th Gen (S5L8720)", 2, "S5L8720", "1225"),
    34: ("iPod Nano 5th Gen (S5L8730)", 2, "S5L8730", "1231"),
    36: ("iPod Nano 6th Gen (S5L8723)", 2, "S5L8723", "1232"),
    37: ("iPod Nano 7th Gen (S5L8740)", 2, "S5L8740", "1234"),
}

# DFU PID to model name mapping for device detection
DFU_PID_MODELS = {
    "1223": "iPod Nano 3G / Classic (S5L8702)",
    "1225": "iPod Nano 4G (S5L8720)",
    "1231": "iPod Nano 5G (S5L8730)",
    "1232": "iPod Nano 6G (S5L8723)",
    "1234": "iPod Nano 7G (S5L8740)",
    "1242": "iPod Nano 3G Recovery (S5L8702)",
    "1250": "iPod Classic Rev C (S5L8702)",
}


# ============================================================
# Utility Functions
# ============================================================
def _get_startupinfo():
    """Get STARTUPINFO that hides command windows."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return si


def run_cmd(cmd, timeout=30):
    """Run a command and return (success, stdout, stderr). No visible window."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=0x08000000,
            startupinfo=_get_startupinfo()
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def get_bundled_path(filename):
    """Get path to a bundled file (works in dev and PyInstaller)."""
    if hasattr(sys, '_MEIPASS'):
        p = os.path.join(sys._MEIPASS, filename)
        if os.path.isfile(p):
            return p
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    p = os.path.join(exe_dir, filename)
    if os.path.isfile(p):
        return p
    # Dev fallback
    for candidate in [
        os.path.join(r'c:\KIRO\AppPatcher\wInd3x-src', filename),
        os.path.join(r'c:\KIRO\iPodUniversalDecrypt', filename),
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


def run_native_wind3x(args, timeout=30):
    """Run wInd3x-win.exe natively on Windows. Returns (success, stdout, stderr)."""
    wind3x = get_bundled_path(WIND3X_WIN_NAME)
    if not wind3x:
        return False, "", "wInd3x-win.exe not found"

    # Ensure libusb-1.0.dll is next to it
    dll_src = get_bundled_path(LIBUSB_DLL_NAME)
    dll_dest = os.path.join(os.path.dirname(wind3x), LIBUSB_DLL_NAME)
    if dll_src and not os.path.isfile(dll_dest):
        shutil.copy2(dll_src, dll_dest)

    try:
        result = subprocess.run(
            [wind3x] + args,
            capture_output=True, text=True, timeout=timeout,
            creationflags=0x08000000,
            cwd=os.path.dirname(wind3x)
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def check_winusb_installed(pid):
    """Check if WinUSB driver (via libwdi/Zadig) is installed for a given PID."""
    try:
        result = subprocess.run(
            ['pnputil', '/enum-drivers'],
            capture_output=True, text=True, timeout=10,
            creationflags=0x08000000
        )
        return f'PID_{pid}' in result.stdout.upper() and 'libwdi' in result.stdout.lower()
    except Exception:
        return False


def launch_zadig():
    """Launch Zadig for WinUSB driver installation."""
    zadig_path = get_bundled_path(ZADIG_NAME)
    if not zadig_path:
        raise RuntimeError("Zadig not found in bundle")
    subprocess.Popen([zadig_path], creationflags=0x08000000)


def remove_winusb_driver(pid):
    """Remove the libwdi WinUSB driver for a specific PID."""
    try:
        result = subprocess.run(
            ['pnputil', '/enum-drivers'],
            capture_output=True, text=True, timeout=10,
            creationflags=0x08000000
        )
        lines = result.stdout.splitlines()
        oem_inf = None
        for i, line in enumerate(lines):
            if f'PID_{pid}' in line.upper() and 'libwdi' in line.lower():
                for j in range(max(0, i - 5), i):
                    if 'Published Name:' in lines[j]:
                        oem_inf = lines[j].split(':')[1].strip()
                        break
                if oem_inf:
                    break
        if oem_inf:
            subprocess.run(
                ['pnputil', '/delete-driver', oem_inf, '/uninstall'],
                capture_output=True, timeout=15,
                creationflags=0x08000000
            )
            return True
    except Exception:
        pass
    return False


def parse_ipsw_filename(filepath):
    """Parse IPSW filename to determine Family ID and model.
    Returns (family_id, model_name, category) or (None, None, None).

    Two filename formats exist:
      Format 2: iPod_X.X.X_XXYZZZZZ.ipsw — FamilyID is first 2 digits of build code
                e.g. iPod_1.0.2_34A20020.ipsw → FamilyID 34 (Nano 5G)
      Format 1: iPod_XX.X.X.X.ipsw — FamilyID is the first number
                e.g. iPod_26.1.1.3.ipsw → FamilyID 26 (Nano 3G)

    Format 2 must be checked FIRST because filenames like iPod_1.0.2_34A20020.ipsw
    would falsely match Format 1 as FamilyID 1 (iPod 1st Gen).
    """
    basename = os.path.basename(filepath)

    # Format 2 first: iPod_X.X.X_XXYZZZZZ.ipsw
    match2 = re.match(r'iPod_[\d.]+_(\d{2})[A-Z]\d+\.ipsw', basename, re.IGNORECASE)
    if match2:
        family_id = int(match2.group(1))
        if family_id in IPOD_MODELS:
            name, cat, soc, pid = IPOD_MODELS[family_id]
            return family_id, name, cat
        return family_id, f"Unknown iPod (FamilyID {family_id})", None

    # Format 1: iPod_XX.X.X.X.ipsw
    match1 = re.match(r'iPod_(\d+)\.\d+', basename, re.IGNORECASE)
    if match1:
        family_id = int(match1.group(1))
        if family_id in IPOD_MODELS:
            name, cat, soc, pid = IPOD_MODELS[family_id]
            return family_id, name, cat
        return family_id, f"Unknown iPod (FamilyID {family_id})", None

    return None, None, None


# ============================================================
# Auto-Elevate to Administrator
# ============================================================
def auto_elevate():
    """Re-launch as administrator if not already elevated."""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True

    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{a}"' for a in sys.argv[1:]])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    if ret > 32:
        sys.exit(0)
    return False


# ============================================================
# Main Application
# ============================================================
class UniversalDecryptorApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        # Height is NOT fixed - it is recalculated by _autosize_window()
        # every time the visible sections change (e.g. no IPSW selected vs.
        # a Category 4 Nano 2G firmware showing extra panels), so the
        # window always matches its actual content instead of showing
        # empty space or clipping widgets. Only an initial width and a
        # capped starting height are set here; _autosize_window() runs
        # immediately after the first build and adjusts it for real.
        self.root.geometry("820x500")
        self.root.resizable(True, True)
        self.root.minsize(700, 300)
        # The content area is still wrapped in a scrollable canvas (see
        # _build_ui) as a safety net for screens too short to fit the
        # tallest possible combination of panels, and the footer bar stays
        # pinned to the bottom of the window independently of content
        # height in all cases.

        # Set window icon
        icon_path = get_bundled_path('icon.ico')
        if icon_path:
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        # State
        self.ipsw_path = tk.StringVar(value="")
        self.output_path = tk.StringVar(
            value=os.path.join(os.path.expanduser("~"), "Desktop", "osos_decrypted.bin")
        )
        self.detected_family_id = None
        self.detected_model = None
        self.detected_category = None
        self.is_running = False

        self._build_ui()
        self._autosize_window()

    def _build_ui(self):
        """Build the complete UI.

        Structure: a footer bar is packed to the bottom of the window
        first, so the action buttons and the "Created by" credit are
        always pinned to the bottom regardless of window size or how
        many optional sections (hardware AES / Nano 2G panels) are
        showing. The rest of the content is packed directly above it and
        the window height is kept in sync with that content's real
        requested size by _autosize_window() (called on build and on
        every visibility change), so there is never leftover blank space
        below the log box, and no permanent scrollbar for content that
        already fits.
        """
        # --- Footer: always pinned to the bottom of the window ---
        # The footer itself provides the single bottom boundary. Do not add
        # a ttk.Separator here: on Windows the themed separator renders as
        # a second visible line next to the window/footer edge.
        footer_frame = ttk.Frame(self.root, padding=(10, 6))
        self.btn_frame = footer_frame
        footer_frame.pack(side="bottom", fill="x")

        self.decrypt_btn = ttk.Button(footer_frame, text="🔓 Decrypt Firmware",
                                      command=self._start_decrypt)
        self.decrypt_btn.pack(side="right", padx=(5, 0))
        ttk.Button(footer_frame, text="📋 Copy Log",
                   command=self._copy_log).pack(side="right", padx=5)
        ttk.Button(footer_frame, text="Exit", command=self.root.quit).pack(side="right")
        ttk.Label(footer_frame, text="2026 Created by Ricardo de Koning",
                  font=("Segoe UI", 8), foreground="gray").pack(side="left")

        # --- Content area: packed directly, window height tracks it ---
        # Bottom padding is intentionally 0 (vs. 10 on the other sides) so
        # there's no dead strip between the last section (Log) and the
        # footer separator; the Log frame's own pady already provides a
        # small, consistent gap above the footer.
        main_frame = ttk.Frame(self.root, padding=(10, 10, 10, 0))
        self.main_frame = main_frame
        main_frame.pack(side="top", fill="both", expand=True)

        # Title
        self.title_frame = ttk.Frame(main_frame)
        self.title_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(self.title_frame, text=APP_NAME,
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(self.title_frame, text=f"v{APP_VERSION} — Native Windows (no WSL required)",
                  font=("Segoe UI", 9)).pack(anchor="w")

        # IPSW Selection
        ipsw_frame = ttk.LabelFrame(main_frame, text="Firmware Source", padding=8)
        self.ipsw_frame = ipsw_frame
        ipsw_frame.pack(fill="x", pady=(0, 5))

        ipsw_row = ttk.Frame(ipsw_frame)
        ipsw_row.pack(fill="x")
        ttk.Label(ipsw_row, text="IPSW:").pack(side="left")
        self.ipsw_entry = ttk.Entry(ipsw_row, textvariable=self.ipsw_path, width=55)
        self.ipsw_entry.pack(side="left", padx=5, expand=True, fill="x")
        ttk.Button(ipsw_row, text="Browse...", command=self._browse_ipsw).pack(side="right")

        # Detected model row
        model_row = ttk.Frame(ipsw_frame)
        model_row.pack(fill="x", pady=(5, 0))
        ttk.Label(model_row, text="Detected:").pack(side="left")
        self.model_label = ttk.Label(model_row, text="(select an IPSW file)",
                                     font=("Segoe UI", 9, "italic"),
                                     foreground="gray")
        self.model_label.pack(side="left", padx=5)
        self.mode_label = ttk.Label(model_row, text="",
                                    font=("Segoe UI", 9, "bold"))
        self.mode_label.pack(side="right")

        # Prerequisites frame (shown for Category 2)
        self.prereq_frame = ttk.LabelFrame(main_frame, text="Prerequisites (Hardware Decrypt)", padding=8)
        self.wind3x_label = ttk.Label(self.prereq_frame, text="⏳ wInd3x-win.exe: Not checked")
        self.wind3x_label.pack(anchor="w")
        self.driver_status_label = ttk.Label(self.prereq_frame, text="⏳ WinUSB Driver: Not checked")
        self.driver_status_label.pack(anchor="w")

        # Device frame (shown for Category 2)
        self.device_frame = ttk.LabelFrame(main_frame, text="Device (DFU Mode)", padding=8)
        self.device_label = ttk.Label(self.device_frame,
                                      text="⚠️ Put iPod in DFU mode: hold Menu+Center until screen stays black")
        self.device_label.pack(anchor="w")

        dev_btn_row = ttk.Frame(self.device_frame)
        dev_btn_row.pack(fill="x", pady=(5, 0))
        ttk.Button(dev_btn_row, text="🔍 Scan for iPod in DFU",
                   command=self._scan_device).pack(side="left")
        self.device_info_label = ttk.Label(dev_btn_row, text="")
        self.device_info_label.pack(side="left", padx=10)

        # Driver install/remove buttons
        self.driver_frame = ttk.Frame(self.device_frame)
        self.driver_label = ttk.Label(self.driver_frame,
                                      text="⚠️ WinUSB driver required for native Windows decrypt")
        self.driver_label.pack(anchor="w")
        drv_btn_row = ttk.Frame(self.driver_frame)
        drv_btn_row.pack(fill="x", pady=(3, 0))
        ttk.Button(drv_btn_row, text="⚙ Install WinUSB Driver (Zadig)",
                   command=self._install_driver).pack(side="left", padx=(0, 5))
        ttk.Button(drv_btn_row, text="❌ Remove WinUSB Driver",
                   command=self._remove_driver).pack(side="left")

        # Nano 2G device frame (shown for Category 4 — iBugger Loader/Core)
        self.nano2g_device_frame = ttk.LabelFrame(
            main_frame, text="iPod Nano 2G — Notes Exploit (Hardware AES)", padding=8)
        self.nano2g_status_label = ttk.Label(
            self.nano2g_device_frame,
            text="⚠️ Stage loader.htm in Notes, then eject/reconnect the iPod")
        self.nano2g_status_label.pack(anchor="w")
        nano2g_btn_row = ttk.Frame(self.nano2g_device_frame)
        nano2g_btn_row.pack(fill="x", pady=(5, 0))
        ttk.Button(nano2g_btn_row, text="📝 Stage loader.htm to iPod Notes",
                   command=self._nano2g_stage_loader).pack(side="left", padx=(0, 5))
        ttk.Button(nano2g_btn_row, text="🔍 Check iBugger Status",
                   command=self._nano2g_scan_device).pack(side="left", padx=(0, 5))
        ttk.Button(nano2g_btn_row, text="🧹 Remove loader.htm (restore iPod)",
                   command=self._nano2g_cleanup_loader).pack(side="left")
        # Not packed here on purpose: an empty ttk.Label still reserves a
        # full line of height, which showed up as dead space under the
        # button row before any status text existed. It's packed/unpacked
        # on demand by _nano2g_set_device_info() instead.
        self.nano2g_device_info_label = ttk.Label(self.nano2g_device_frame, text="")

        # Partition selection frame (for Category 2, 3, and 4)
        self.partition_frame = ttk.LabelFrame(main_frame, text="Partitions to Decrypt", padding=8)
        partition_names = ["osos", "aupd", "rsrc", "disk", "diag",
                           "appl", "chrg", "bdsw", "bdhw", "lbat"]
        self.partition_vars = {}
        row1_frame = ttk.Frame(self.partition_frame)
        row1_frame.pack(fill="x")
        row2_frame = ttk.Frame(self.partition_frame)
        row2_frame.pack(fill="x", pady=(3, 0))
        for i, name in enumerate(partition_names):
            var = tk.BooleanVar(value=True)
            self.partition_vars[name] = var
            parent_row = row1_frame if i < 5 else row2_frame
            ttk.Checkbutton(parent_row, text=name, variable=var).pack(side="left", padx=(0, 12))

        # Nano 5G's Silver resource database is a file inside the plaintext
        # RSRC FAT16 image, not a standalone MSE partition. Keep the option
        # hidden for other models and expose it only for FamilyID 34.
        self.silverimagesdb_var = tk.BooleanVar(value=True)
        self.silverimagesdb_row = ttk.Frame(self.partition_frame)
        self.silverimagesdb_checkbutton = ttk.Checkbutton(
            self.silverimagesdb_row,
            text="SilverImagesDB.LE.bin (Nano 5G)",
            variable=self.silverimagesdb_var,
        )

        # Output path
        out_frame = ttk.LabelFrame(main_frame, text="Output", padding=8)
        self.out_frame = out_frame
        out_frame.pack(fill="x", pady=(0, 5))

        out_row = ttk.Frame(out_frame)
        out_row.pack(fill="x")
        ttk.Label(out_row, text="Save to:").pack(side="left")
        self.out_entry = ttk.Entry(out_row, textvariable=self.output_path, width=55)
        self.out_entry.pack(side="left", padx=5, expand=True, fill="x")
        ttk.Button(out_row, text="Browse...", command=self._browse_output).pack(side="right")

        # Progress
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding=8)
        self.progress_frame = progress_frame
        progress_frame.pack(fill="x", pady=(0, 5))

        self.progress = ttk.Progressbar(progress_frame, mode="determinate", length=400)
        self.progress.pack(fill="x")
        self.status_label = ttk.Label(progress_frame, text="Ready — select an IPSW to begin",
                                      font=("Segoe UI", 9))
        self.status_label.pack(anchor="w", pady=(4, 0))

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=5)
        self.log_frame = log_frame
        log_frame.pack(fill="x", pady=(0, 8))

        log_inner = ttk.Frame(log_frame)
        log_inner.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_inner, height=5, font=("Consolas", 8),
                                wrap="word", state="normal")
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(log_inner, orient="vertical",
                                  command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # Listen to IPSW path changes
        self.ipsw_path.trace_add("write", self._on_ipsw_changed)

    # ============================================================
    # UI Helpers
    # ============================================================
    def _log(self, msg):
        """Append message to log."""
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.root.update_idletasks()

    def _nano2g_set_device_info(self, text):
        """Set the Nano 2G device-info label text, packing/unpacking it so
        it takes up zero height when empty instead of reserving a blank
        line under the button row."""
        self.nano2g_device_info_label.config(text=text)
        if text:
            if not self.nano2g_device_info_label.winfo_ismapped():
                self.nano2g_device_info_label.pack(anchor="w", pady=(3, 0))
        else:
            self.nano2g_device_info_label.pack_forget()

    def _set_status(self, msg):
        """Update status label."""
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def _copy_log(self):
        """Copy log to clipboard and save to file."""
        text = self.log_text.get("1.0", "end").strip()
        text = text.replace('\x00', '')
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        try:
            log_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'decrypt_log.txt')
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(text)
            self._set_status("Log copied + saved to decrypt_log.txt")
        except Exception:
            self._set_status("Log copied to clipboard")

    def _repack_ui(self, show_hardware=False, show_partitions=False,
                   show_nano2g=False, show_silverimagesdb=False):
        """Repack all main frame children in correct order.

        Named attributes are used instead of positional winfo_children()
        indices so that adding/removing frames cannot silently shift the
        layout of unrelated sections.
        """
        self.silverimagesdb_row.pack_forget()
        self.silverimagesdb_checkbutton.pack_forget()
        for frame in (
            self.title_frame, self.ipsw_frame, self.prereq_frame,
            self.device_frame, self.nano2g_device_frame, self.partition_frame,
            self.out_frame, self.progress_frame, self.log_frame,
        ):
            frame.pack_forget()

        self.title_frame.pack(fill="x", pady=(0, 8))
        self.ipsw_frame.pack(fill="x", pady=(0, 5))

        if show_hardware:
            self.prereq_frame.pack(fill="x", pady=(0, 5))
            self.device_frame.pack(fill="x", pady=(0, 5))

        if show_nano2g:
            self.nano2g_device_frame.pack(fill="x", pady=(0, 5))

        if show_partitions:
            self.partition_frame.pack(fill="x", pady=(0, 5))
            if show_silverimagesdb:
                self.silverimagesdb_row.pack(fill="x", pady=(3, 0))
                self.silverimagesdb_checkbutton.pack(side="left")

        self.out_frame.pack(fill="x", pady=(0, 5))
        self.progress_frame.pack(fill="x", pady=(0, 5))
        self.log_frame.pack(fill="x", pady=(0, 8))
        # btn_frame (footer) is packed directly to self.root in _build_ui
        # and stays pinned to the bottom of the window at all times; it is
        # intentionally not part of this repack cycle.

        self._autosize_window()

    def _autosize_window(self):
        """Resize the window height to fit exactly what's currently
        visible (title/IPSW/output/progress/log, plus whichever optional
        hardware/Nano2G/partition panels the loaded firmware needs).

        Different firmware families show different combinations of
        panels (e.g. a Category 1 unencrypted model shows almost nothing
        extra, while a Category 4 Nano 2G IPSW adds the Notes-exploit
        panel and the partition picker), so a single fixed window height
        either wastes space or clips content. This measures the real
        requested height of the content after layout and applies it,
        capped to the working area of the screen so the window never
        grows off-screen. If content is ever taller than that cap, the
        window is capped at that height and Tk's own scrollable Text log
        widget plus normal window resizing let the user reach everything.

        Rather than hand-summing individual frame heights (which drifts
        from reality and causes stale/ghosted pixels on Windows when it
        disagrees with what pack() actually laid out), this releases any
        previous explicit size with geometry("") so Tk recomputes the
        window's true natural size from its current packed content, then
        re-applies that exact size. This stays correct no matter which
        combination of panels a given firmware/category shows, and stays
        correct for in-place label/text changes too (e.g. status text
        that grows to two lines), as long as this is called again after
        any change that could affect layout height.
        """
        self.root.update_idletasks()
        self.root.geometry("")  # release any previous fixed size
        self.root.update_idletasks()

        natural_width = self.root.winfo_reqwidth()
        natural_height = self.root.winfo_reqheight()

        screen_height = self.root.winfo_screenheight()
        max_height = int(screen_height * 0.9)

        current_width = self.root.winfo_width()
        width = max(current_width, natural_width, 820)
        height = min(natural_height, max_height)

        self.root.geometry(f"{width}x{height}")
        self.root.update_idletasks()

    def _on_ipsw_changed(self, *args):
        """Called when IPSW path changes — detect model and update UI."""
        path = self.ipsw_path.get()
        if not path:
            self.model_label.config(text="(select an IPSW file)",
                                    foreground="gray",
                                    font=("Segoe UI", 9, "italic"))
            self.mode_label.config(text="")
            self._repack_ui(show_hardware=False, show_partitions=False)
            return

        family_id, model_name, category = parse_ipsw_filename(path)
        self.detected_family_id = family_id
        self.detected_model = model_name
        self.detected_category = category

        if family_id is None:
            self.model_label.config(
                text="⚠️ Could not detect model from filename",
                foreground="orange", font=("Segoe UI", 9, "bold"))
            self.mode_label.config(text="")
            self._repack_ui(show_hardware=False, show_partitions=False)
            return

        self.model_label.config(text=f"📱 {model_name} (FamilyID {family_id})",
                                foreground="black", font=("Segoe UI", 9, "bold"))

        if category == 1:
            self.mode_label.config(text="✅ No device needed (unencrypted)",
                                   foreground="green")
            self._repack_ui(show_hardware=False, show_partitions=False)
        elif category == 3:
            self.mode_label.config(text="🔑 Software decrypt (no device needed)",
                                   foreground="green")
            self._repack_ui(show_hardware=False, show_partitions=True)
        elif category == 4:
            self.mode_label.config(
                text="🔐 Hardware AES via Notes exploit (device required)",
                foreground="blue")
            self._repack_ui(show_hardware=False, show_partitions=True, show_nano2g=True)
        elif category == 2:
            self.mode_label.config(text="🔐 Hardware AES (device required)",
                                   foreground="blue")
            self._repack_ui(
                show_hardware=True,
                show_partitions=True,
                show_silverimagesdb=(family_id == 34),
            )
            # Show driver buttons for ALL Category 2
            self.driver_frame.pack(fill="x", pady=(5, 0))
            self._autosize_window()
            self._check_prerequisites()
        else:
            self.mode_label.config(text="❓ Unknown category", foreground="red")
            self._repack_ui(show_hardware=False, show_partitions=False)

        # Update default output filename
        safe_name = re.sub(r'[^\w]', '_', model_name.split('(')[0].strip())
        basename = os.path.basename(self.ipsw_path.get())
        ver_match = re.match(r'iPod_(\d+[\.\d]+)', basename, re.IGNORECASE)
        if ver_match:
            version_str = ver_match.group(1)
        else:
            ver_match2 = re.match(r'iPod_([\d.]+_[A-Z0-9]+)', basename, re.IGNORECASE)
            version_str = ver_match2.group(1) if ver_match2 else str(family_id)
        if category in (2, 3, 4):
            # Use directory for multi-partition output
            self.output_path.set(
                os.path.join(os.path.expanduser("~"), "Desktop",
                             f"decrypted_{safe_name}_{version_str}")
            )
        else:
            self.output_path.set(
                os.path.join(os.path.expanduser("~"), "Desktop",
                             f"osos_decrypted_{safe_name}_{version_str}.bin")
            )

    def _check_prerequisites(self):
        """Check wInd3x-win.exe bundled and WinUSB driver installed."""
        def check():
            # wInd3x-win.exe
            wind3x = get_bundled_path(WIND3X_WIN_NAME)
            if wind3x:
                self.wind3x_label.config(text=f"✅ wInd3x-win.exe: Found ({os.path.basename(wind3x)})")
            else:
                self.wind3x_label.config(text="❌ wInd3x-win.exe: Not found (must be bundled)")
                self.root.after(0, self._autosize_window)
                return

            # WinUSB driver check
            pid = None
            if self.detected_family_id in IPOD_MODELS:
                _, _, _, pid = IPOD_MODELS[self.detected_family_id]
            if pid and check_winusb_installed(pid):
                self.driver_status_label.config(text=f"✅ WinUSB Driver: Installed for PID {pid}")
            elif pid:
                self.driver_status_label.config(
                    text=f"⚠️ WinUSB Driver: Not detected for PID {pid} (use Zadig below)")
            else:
                self.driver_status_label.config(text="⏳ WinUSB Driver: No PID to check")
            self.root.after(0, self._autosize_window)

        threading.Thread(target=check, daemon=True).start()

    def _browse_ipsw(self):
        """Open file dialog for IPSW selection."""
        path = filedialog.askopenfilename(
            title="Select iPod IPSW Firmware",
            filetypes=[("IPSW files", "*.ipsw"), ("All files", "*.*")]
        )
        if path:
            self.ipsw_path.set(path)

    def _browse_output(self):
        """Open file dialog for output path."""
        if self.detected_category in (2, 3, 4):
            path = filedialog.askdirectory(title="Select Output Directory")
        else:
            path = filedialog.asksaveasfilename(
                title="Save Decrypted OSOS As",
                defaultextension=".bin",
                filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
            )
        if path:
            self.output_path.set(path)

    def _get_selected_partitions(self):
        """Return checked MSE partitions plus the optional Nano 5G file."""
        selected = [name for name, var in self.partition_vars.items() if var.get()]
        if (self.detected_family_id == 34 and
                self.silverimagesdb_var.get()):
            selected.append("silverimagesdb")
        return selected

    def _install_driver(self):
        """Launch Zadig to install WinUSB driver for iPod DFU."""
        self._log("Launching Zadig for WinUSB driver installation...")
        self._log("  In Zadig: select the iPod device, choose WinUSB, click Install.")
        try:
            launch_zadig()
        except Exception as e:
            self._log(f"  ERROR: {e}")
            messagebox.showerror("Error", f"Cannot launch Zadig:\n{e}")

    def _remove_driver(self):
        """Remove the WinUSB driver for the detected iPod PID."""
        if not self.detected_category:
            messagebox.showinfo("Info", "Select an IPSW first to detect the device.")
            return
        pid = None
        if self.detected_family_id in IPOD_MODELS:
            _, _, _, pid = IPOD_MODELS[self.detected_family_id]
        if not pid:
            messagebox.showinfo("Info", "No DFU PID known for this model.")
            return
        self._log(f"Removing WinUSB driver for PID {pid}...")
        if remove_winusb_driver(pid):
            self._log("  ✅ Driver removed. Original Apple driver will load on next plug.")
            messagebox.showinfo("Done",
                                "WinUSB driver removed.\nReconnect the iPod for the Apple driver to reload.")
        else:
            self._log("  No libwdi/Zadig driver found for this PID (may already be removed).")

    def _scan_device(self):
        """Scan for iPod in DFU mode via native USB enumeration."""
        self.device_label.config(text="🔍 Scanning...")
        self._autosize_window()

        # Use wInd3x-win.exe to probe for DFU device
        ok, out, err = run_native_wind3x(['haxdfu', '--dry-run'], timeout=10)
        combined = out + err

        # Also check pnputil for Apple DFU devices
        found_pid = None
        try:
            result = subprocess.run(
                ['pnputil', '/enum-devices', '/connected'],
                capture_output=True, text=True, timeout=10,
                creationflags=0x08000000
            )
            for pid in DFU_PIDS:
                if f'PID_{pid}' in result.stdout.upper() or f'pid_{pid}' in result.stdout.lower():
                    found_pid = pid
                    break
        except Exception:
            pass

        if found_pid:
            # Use the detected model name from IPSW if available (more specific)
            if self.detected_model:
                display_name = self.detected_model
            else:
                display_name = DFU_PID_MODELS.get(found_pid, f"Unknown (PID 0x{found_pid})")
            self.device_label.config(text=f"✅ Found: {display_name} (PID 0x{found_pid})")
            self._log(f"Device found: {display_name} (PID 0x{found_pid})")
        elif "found" in combined.lower() or "nano" in combined.lower() or "apple" in combined.lower():
            self.device_label.config(text="✅ iPod DFU device detected by wInd3x")
            self._log("iPod DFU device detected by wInd3x.")
        else:
            self.device_label.config(
                text="❌ No iPod in DFU mode found. Hold Menu+Center until screen stays black.")
            self._log("No iPod DFU device detected.")
        self._autosize_window()

    # ============================================================
    # Decrypt Logic
    # ============================================================
    def _start_decrypt(self):
        """Start the decrypt process."""
        if self.is_running:
            return

        ipsw = self.ipsw_path.get()
        if not ipsw:
            messagebox.showerror("Error", "Please select an IPSW file first.")
            return
        if not os.path.isfile(ipsw):
            messagebox.showerror("Error", f"IPSW file not found:\n{ipsw}")
            return
        if self.detected_category is None:
            messagebox.showerror("Error",
                                 "Could not detect iPod model from filename.\n"
                                 "Expected format: iPod_XX.X.X.X.ipsw")
            return

        self.is_running = True
        self.decrypt_btn.config(state="disabled")
        self.progress["value"] = 0
        threading.Thread(target=self._decrypt_thread, daemon=True).start()

    def _decrypt_thread(self):
        """Main decrypt thread — dispatches by category."""
        try:
            if self.detected_category == 1:
                self._decrypt_category1()
            elif self.detected_category == 2:
                self._decrypt_category2_native()
            elif self.detected_category == 3:
                self._decrypt_category3()
            elif self.detected_category == 4:
                self._decrypt_category4_nano2g_device()
            else:
                self._log("ERROR: Unknown device category")
                self._set_status("Failed: Unknown category")
        except Exception as e:
            self._log(f"ERROR: {e}")
            self._set_status(f"Failed: {e}")
        finally:
            self.is_running = False
            self.decrypt_btn.config(state="normal")

    # ============================================================
    # Category 1: Not Encrypted (extract only)
    # ============================================================
    def _decrypt_category1(self):
        """Handle unencrypted iPods — extract OSOS from IPSW."""
        ipsw_path = self.ipsw_path.get()
        output_path = self.output_path.get()

        self._log("=" * 55)
        self._log(f"Model: {self.detected_model} (Category 1 — Not Encrypted)")
        self._log("=" * 55)
        self._set_status("Extracting firmware from IPSW...")
        self.progress["value"] = 10

        # Step 1: Extract firmware file from IPSW ZIP
        self._log("\n[1/3] Extracting firmware from IPSW (ZIP archive)...")
        try:
            fw_data = None
            fw_name = None
            with zipfile.ZipFile(ipsw_path, 'r') as z:
                for name in z.namelist():
                    if (name.lower().startswith('firmware') and
                            not name.endswith('.plist') and
                            '/' not in name):
                        self._log(f"  Found firmware file: {name}")
                        fw_data = z.read(name)
                        fw_name = name
                        break

            if not fw_data:
                self._log("ERROR: No firmware file found in IPSW archive!")
                self._set_status("Failed: No firmware in IPSW")
                return

            self._log(f"  Size: {len(fw_data):,} bytes")
            self.progress["value"] = 30

        except zipfile.BadZipFile:
            self._log("ERROR: File is not a valid IPSW/ZIP archive!")
            self._set_status("Failed: Invalid IPSW")
            return

        # Step 2: Try MSE extract via native wInd3x, fallback to header strip
        self._log("\n[2/3] Extracting OSOS from firmware container...")
        self._set_status("Extracting OSOS from MSE/IMG container...")
        self.progress["value"] = 40

        # Save firmware to temp file for wInd3x
        temp_dir = os.environ.get('TEMP', 'C:\\Temp')
        temp_fw = os.path.join(temp_dir, 'ipod_fw_temp.bin')
        temp_mse_dir = os.path.join(temp_dir, 'ipod_mse_cat1')
        os.makedirs(temp_mse_dir, exist_ok=True)
        with open(temp_fw, 'wb') as f:
            f.write(fw_data)

        osos_data = None

        # Try wInd3x mse extract natively
        wind3x = get_bundled_path(WIND3X_WIN_NAME)
        if wind3x:
            self._log("  Trying wInd3x mse extract (native)...")
            ok, out, err = run_native_wind3x(
                ['mse', 'extract', temp_fw, '-o', temp_mse_dir + '\\'], timeout=60)
            combined = out + err
            self._log(f"  {combined[:200]}" if combined else "  (no output)")

            osos_path = os.path.join(temp_mse_dir, 'osos')
            if os.path.isfile(osos_path) and os.path.getsize(osos_path) > 0:
                osos_size = os.path.getsize(osos_path)
                self._log(f"  ✅ MSE extract successful! OSOS size: {osos_size:,} bytes")
                shutil.copy2(osos_path, output_path)
                self.progress["value"] = 80
            else:
                wind3x = None  # Trigger fallback

        if not wind3x or (not os.path.isfile(output_path) or os.path.getsize(output_path) == 0):
            # Fallback: strip IMG1/8900 header (first 0x800 bytes)
            self._log("  MSE extract unavailable/failed. Falling back to header strip (0x800 bytes)...")
            if len(fw_data) > 0x800:
                osos_data = fw_data[0x800:]
                self._log(f"  Stripped 0x800 header. OSOS size: {len(osos_data):,} bytes")
                with open(output_path, 'wb') as f:
                    f.write(osos_data)
                self.progress["value"] = 80
            else:
                self._log("ERROR: Firmware file too small to contain OSOS!")
                self._set_status("Failed: Firmware too small")
                self._cleanup_temp(temp_fw)
                return

        # Step 3: Verify output
        self._log("\n[3/3] Verifying output...")
        self._set_status("Verifying output file...")
        self.progress["value"] = 90

        if os.path.exists(output_path) and os.path.getsize(output_path) > 1000:
            size = os.path.getsize(output_path)
            self._log(f"\n{'=' * 55}")
            self._log(f"✅ SUCCESS! OSOS extracted (plaintext, not encrypted).")
            self._log(f"   File: {output_path}")
            self._log(f"   Size: {size:,} bytes ({size / 1024 / 1024:.2f} MB)")
            self._log(f"{'=' * 55}")
            self._set_status("✅ Extraction complete!")
            self.progress["value"] = 100
            messagebox.showinfo("Success",
                                f"OSOS extracted successfully!\n\n"
                                f"Model: {self.detected_model}\n"
                                f"File: {output_path}\n"
                                f"Size: {size:,} bytes\n\n"
                                f"Note: This firmware is NOT encrypted.")
        else:
            self._log("❌ Output file not found or empty.")
            self._set_status("❌ Extraction failed")

        self._cleanup_temp(temp_fw)

    # ============================================================
    # Category 3: Software AES Decrypt (Nano 2G — known key)
    # ============================================================
    def _decrypt_category3(self):
        """Parse, extract, and process Nano 2G S5L8701 partitions."""
        ipsw_path = self.ipsw_path.get()
        output_dir = self.output_path.get()

        self._log("=" * 55)
        self._log(f"Model: {self.detected_model} (Category 3 — Software Decrypt)")
        self._log("=" * 55)
        self._log("Using the validated S5L8701 DNAN directory; no native MSE fallback.\n")
        self._set_status("Reading Nano 2G partition directory...")
        self.progress["value"] = 10

        self._log("[1/3] Extracting firmware from IPSW...")
        try:
            fw_data = None
            with zipfile.ZipFile(ipsw_path, 'r') as z:
                for name in z.namelist():
                    if (name.lower().startswith('firmware') and
                            not name.endswith('.plist') and '/' not in name):
                        self._log(f"  Found: {name}")
                        fw_data = z.read(name)
                        break
            if not fw_data:
                self._log("ERROR: No firmware file found!")
                self._set_status("Failed: No firmware in IPSW")
                return
            self._log(f"  Size: {len(fw_data):,} bytes")
        except (zipfile.BadZipFile, OSError) as exc:
            self._log(f"ERROR: Cannot read IPSW: {exc}")
            self._set_status("Failed: Invalid IPSW")
            return

        self.progress["value"] = 20
        selected_partitions = self._get_selected_partitions()
        if not selected_partitions:
            self._log("ERROR: No partitions selected!")
            self._set_status("Failed: No partitions selected")
            return

        unsupported = [name for name in selected_partitions
                       if name not in NANO2G_SUPPORTED_PARTITIONS]
        for name in unsupported:
            self._log(f"ERROR: '{name}' is not present in the validated Nano 2G directory; skipping it.")
        selected_partitions = [name for name in selected_partitions
                               if name in NANO2G_SUPPORTED_PARTITIONS]
        if not selected_partitions:
            self._log("ERROR: None of the selected partitions are supported by Nano 2G.")
            self._set_status("Failed: Unsupported Nano 2G partitions")
            return

        try:
            partition_ranges = parse_nano2g_partitions(fw_data)
        except ValueError as exc:
            self._log(f"ERROR: Invalid Nano 2G partition directory: {exc}")
            self._set_status("Failed: Invalid Nano 2G directory")
            return

        self._log("  ✅ Validated ]ih[ marker and three DNAN records at 0x4800")
        for name in ('rsrc', 'osos', 'aupd'):
            part_offset, part_length = partition_ranges[name]
            self._log(f"  {name}: offset 0x{part_offset:x}, total export size {part_length:,} bytes (0x800 header + directory payload)")
        self._log(f"  ✅ Partitions selected: {', '.join(selected_partitions)}")
        self.progress["value"] = 30

        self._log("\n[2/3] Extracting exact partition ranges and processing selected data...")
        os.makedirs(output_dir, exist_ok=True)
        exported_partitions = []
        total_partitions = len(selected_partitions)

        for part_idx, part_name in enumerate(selected_partitions):
            part_offset, part_length = partition_ranges[part_name]
            partition_data = fw_data[part_offset:part_offset + part_length]
            output_file = os.path.join(output_dir, f"{part_name}.bin")
            self._log(f"\n  Processing '{part_name}' ({part_idx + 1}/{total_partitions})...")
            self._log(f"    Exact source range: 0x{part_offset:x}:0x{part_offset + part_length:x}")
            try:
                exported_data, processing_note = prepare_nano2g_partition(
                    part_name, partition_data)
                with open(output_file, 'wb') as output:
                    output.write(exported_data)
            except (OSError, RuntimeError, ValueError) as exc:
                self._log(f"    ❌ {part_name}: {exc}")
                self._set_status(f"Failed: {part_name}")
                return

            exported_partitions.append(part_name)
            self._log(f"    ✅ {part_name}: {len(exported_data):,} bytes ({processing_note})")
            self.progress["value"] = 30 + ((part_idx + 1) / total_partitions) * 60

        self.progress["value"] = 90
        self._log("\n[3/3] Verifying output...")
        self._log("  ✅ Every output includes the local 0x800-byte header plus the full directory-defined payload; no bytes were omitted.")
        self._log("  ⚠️ OSOS/AUPD AES output is not cryptographically verified without a known-good fixture or device validation.")
        self._log(f"\n{'=' * 55}")
        self._log("✅ SUCCESS! Nano 2G partitions exported.")
        self._log(f"   Output directory: {output_dir}")
        for part_name in exported_partitions:
            out_file = os.path.join(output_dir, f"{part_name}.bin")
            size = os.path.getsize(out_file)
            self._log(f"   {part_name}.bin: {size:,} bytes")
        self._log(f"{'=' * 55}")
        self._set_status("✅ Nano 2G partition export complete")
        self.progress["value"] = 100
        messagebox.showinfo(
            "Success",
            f"Nano 2G partitions exported.\n\n"
            f"Model: {self.detected_model}\n"
            f"Partitions: {', '.join(exported_partitions)}\n"
            f"Output: {output_dir}\n\n"
            "RSRC was copied as plaintext. OSOS/AUPD retain their local "
            "0x800-byte headers and have their bodies AES-processed.\n"
            "Cryptographic correctness still requires a known-good fixture or device validation."
        )

    # ============================================================
    # Category 4: Nano 2G Hardware AES via Notes-exploit iBugger
    # ============================================================
    def _nano2g_find_ipod_notes_drive(self):
        """Find a removable drive that looks like an iPod in disk mode
        (has a Notes folder). Returns the drive path or None."""
        import string
        for letter in string.ascii_uppercase:
            notes_path = f"{letter}:\\Notes"
            if os.path.isdir(notes_path):
                return f"{letter}:\\"
        return None

    def _nano2g_stage_loader(self):
        """Write the patched loader.htm into the iPod's Notes folder.

        Backs up any existing loader.htm first. Does not modify other files
        in Notes.
        """
        drive = self._nano2g_find_ipod_notes_drive()
        if not drive:
            messagebox.showerror(
                "iPod Not Found",
                "No drive with a \\Notes folder was found.\n\n"
                "Put the iPod in Disk Mode (Menu+Select to reset, then "
                "immediately Select+Play/Pause) and try again."
            )
            return
        notes_dir = os.path.join(drive, "Notes")
        loader_path = os.path.join(notes_dir, "loader.htm")
        try:
            if os.path.isfile(loader_path):
                backup_path = loader_path + ".backup"
                if not os.path.isfile(backup_path):
                    shutil.copy2(loader_path, backup_path)
                    self._log(f"Backed up existing loader.htm to {backup_path}")
            loader_data = nano2g_device.get_loader_htm()
            with open(loader_path, "wb") as f:
                f.write(loader_data)
            self._log(f"Staged patched loader.htm ({len(loader_data):,} bytes) to {loader_path}")
            self.nano2g_status_label.config(
                text="✅ loader.htm staged. Eject the iPod, then reconnect it.")
            self._autosize_window()
            messagebox.showinfo(
                "Staged",
                f"Patched loader.htm written to:\n{loader_path}\n\n"
                "Now eject the iPod safely and reconnect it (or reset it). "
                "It should boot into Notes automatically and re-enumerate as "
                "'Unified iBugger'. Then click 'Check iBugger Status'."
            )
        except OSError as exc:
            self._log(f"ERROR: Could not stage loader.htm: {exc}")
            messagebox.showerror("Error", f"Could not write loader.htm:\n{exc}")

    def _nano2g_cleanup_loader(self):
        """Remove the Notes-exploit loader.htm from the iPod so it boots
        normally again instead of re-launching the iBugger Loader.

        Requires the iPod to be in Disk Mode (Menu+Select to reset, then
        immediately hold Select+Play/Pause) so its Notes folder is mounted
        as a drive letter. This is pure file I/O - it does not touch NAND/
        NOR/flash firmware and cannot be done while the device is running
        as USB iBugger Loader/Core (that mode has no mounted filesystem).

        If a pre-existing loader.htm was backed up by _nano2g_stage_loader
        (as loader.htm.backup), that original is restored. Otherwise the
        exploit loader.htm is simply deleted, leaving Notes/Instructions
        untouched either way.
        """
        drive = self._nano2g_find_ipod_notes_drive()
        if not drive:
            messagebox.showerror(
                "iPod Not Found",
                "No drive with a \\Notes folder was found.\n\n"
                "Put the iPod in Disk Mode (Menu+Select to reset, then "
                "immediately Select+Play/Pause) and try again.\n\n"
                "Note: if the iPod is currently running as USB iBugger "
                "Loader/Core, it has no mounted filesystem yet - reset it "
                "into Disk Mode first."
            )
            return
        notes_dir = os.path.join(drive, "Notes")
        loader_path = os.path.join(notes_dir, "loader.htm")
        backup_path = loader_path + ".backup"

        if not os.path.isfile(loader_path):
            self._log(f"No loader.htm found at {loader_path}; nothing to clean up.")
            self.nano2g_status_label.config(text="ℹ️ No loader.htm present. iPod is already clean.")
            self._autosize_window()
            messagebox.showinfo("Nothing To Do", f"No loader.htm found at:\n{loader_path}")
            return

        try:
            if os.path.isfile(backup_path):
                shutil.move(backup_path, loader_path)
                self._log(f"Restored original loader.htm from backup at {backup_path}")
                result_msg = "Original loader.htm restored from backup."
            else:
                os.remove(loader_path)
                self._log(f"Deleted exploit loader.htm at {loader_path}")
                result_msg = "Exploit loader.htm deleted (no backup existed to restore)."
            self.nano2g_status_label.config(
                text="✅ loader.htm removed. Eject the iPod, then reset/reconnect it.")
            self._autosize_window()
            messagebox.showinfo(
                "Cleaned Up",
                f"{result_msg}\n\n"
                "Now eject the iPod safely and reset/reconnect it. It should "
                "boot normally instead of launching the iBugger Loader."
            )
        except OSError as exc:
            self._log(f"ERROR: Could not clean up loader.htm: {exc}")
            messagebox.showerror("Error", f"Could not remove/restore loader.htm:\n{exc}")

    def _nano2g_scan_device(self):
        """Read-only check for the iBugger Loader/Core USB interface."""
        self.nano2g_status_label.config(text="🔍 Checking...")
        self._autosize_window()

        def check():
            try:
                stage = nano2g_device.find_device()
            except Exception as exc:
                self.nano2g_status_label.config(text=f"❌ Error: {exc}")
                self.root.after(0, self._autosize_window)
                return
            if stage == "core":
                self.nano2g_status_label.config(
                    text="✅ iBugger Core is running — ready to decrypt.")
                self.root.after(0, self._nano2g_set_device_info,
                                "Stage: Core (device_type=Nano 2G)")
            elif stage == "loader":
                self.nano2g_status_label.config(
                    text="✅ iBugger Loader is running — Core will load automatically when you decrypt.")
                self.root.after(0, self._nano2g_set_device_info, "Stage: Loader")
            else:
                self.nano2g_status_label.config(
                    text="❌ Not found. Stage loader.htm in Notes, then eject/reconnect.")
                self.root.after(0, self._nano2g_set_device_info, "")
            self.root.after(0, self._autosize_window)

        threading.Thread(target=check, daemon=True).start()

    def _decrypt_category4_nano2g_device(self):
        """Decrypt Nano 2G OSOS/AUPD using the device's real hardware AES
        engine via the patched iBugger Loader/Core (Notes-app exploit).

        This does NOT write iPod NAND/NOR/flash storage. All device-side
        code (Loader, Core, AES driver payload) runs from RAM only.

        See iPodKnowledgeDB/RESEARCH_DOCS/
        NANO2G_S5L8701_USB_TRANSPORT_AND_DECRYPTION.md for why the public
        "0x837" key does not apply here and why this device-based path is
        the only correct decryption method for this partition type.
        """
        ipsw_path = self.ipsw_path.get()
        output_dir = self.output_path.get()

        self._log("=" * 55)
        self._log(f"Model: {self.detected_model} (Category 4 — Nano 2G Hardware AES)")
        self._log("=" * 55)
        self._log(
            "Using the device's real hardware AES engine via the patched\n"
            "iBugger Loader/Core (Notes-app exploit). The public '0x837' key\n"
            "does not apply to this device and is not used here.\n"
        )
        self._set_status("Reading Nano 2G partition directory...")
        self.progress["value"] = 5

        self._log("[1/4] Extracting firmware from IPSW...")
        try:
            fw_data = None
            with zipfile.ZipFile(ipsw_path, 'r') as z:
                for name in z.namelist():
                    if (name.lower().startswith('firmware') and
                            not name.endswith('.plist') and '/' not in name):
                        self._log(f"  Found: {name}")
                        fw_data = z.read(name)
                        break
            if not fw_data:
                self._log("ERROR: No firmware file found!")
                self._set_status("Failed: No firmware in IPSW")
                return
            self._log(f"  Size: {len(fw_data):,} bytes")
        except (zipfile.BadZipFile, OSError) as exc:
            self._log(f"ERROR: Cannot read IPSW: {exc}")
            self._set_status("Failed: Invalid IPSW")
            return

        self.progress["value"] = 10
        selected_partitions = self._get_selected_partitions()
        if not selected_partitions:
            self._log("ERROR: No partitions selected!")
            self._set_status("Failed: No partitions selected")
            return

        unsupported = [name for name in selected_partitions
                       if name not in NANO2G_SUPPORTED_PARTITIONS]
        for name in unsupported:
            self._log(f"NOTE: '{name}' is not present in the validated Nano 2G directory; skipping it.")
        selected_partitions = [name for name in selected_partitions
                               if name in NANO2G_SUPPORTED_PARTITIONS]
        if not selected_partitions:
            self._log("ERROR: None of the selected partitions are supported by Nano 2G.")
            self._set_status("Failed: Unsupported Nano 2G partitions")
            return

        try:
            partition_ranges = parse_nano2g_partitions(fw_data)
        except ValueError as exc:
            self._log(f"ERROR: Invalid Nano 2G partition directory: {exc}")
            self._set_status("Failed: Invalid Nano 2G directory")
            return

        self._log("  ✅ Validated ]ih[ marker and DNAN records at 0x4800")
        for name in ('rsrc', 'osos', 'aupd'):
            part_offset, part_length = partition_ranges[name]
            self._log(f"  {name}: offset 0x{part_offset:x}, size {part_length:,} bytes")
        self.progress["value"] = 15

        # RSRC is plaintext; export it directly without touching the device.
        os.makedirs(output_dir, exist_ok=True)
        needs_device = any(name in ('osos', 'aupd') for name in selected_partitions)

        if 'rsrc' in selected_partitions:
            part_offset, part_length = partition_ranges['rsrc']
            rsrc_data = fw_data[part_offset:part_offset + part_length]
            rsrc_path = os.path.join(output_dir, "rsrc.bin")
            with open(rsrc_path, 'wb') as f:
                f.write(rsrc_data)
            self._log(f"  ✅ rsrc: {len(rsrc_data):,} bytes (raw/plaintext, no device needed)")

        device_partitions = [n for n in selected_partitions if n in ('osos', 'aupd')]
        if not device_partitions:
            self.progress["value"] = 100
            self._set_status("✅ RSRC export complete (no OSOS/AUPD selected)")
            return

        self._log(f"\n[2/4] Connecting to iPod (Loader/Core over USB)...")
        self._set_status("Connecting to iBugger...")
        self.progress["value"] = 20

        try:
            transport = nano2g_device.IBuggerTransport(log=self._log)
        except nano2g_device.DeviceNotFoundError as exc:
            self._log(f"ERROR: {exc}")
            self._set_status("Failed: iBugger not found")
            messagebox.showerror(
                "Device Not Found",
                f"{exc}\n\n"
                "Click 'Stage loader.htm to iPod Notes' first, then eject/"
                "reconnect the iPod and try again."
            )
            return
        except nano2g_device.TransportError as exc:
            self._log(f"ERROR: {exc}")
            self._set_status("Failed: USB transport error")
            messagebox.showerror("Transport Error", str(exc))
            return

        try:
            if transport.core_type == 1:
                self._log("[3/4] Device is Loader stage; loading Core (RAM only)...")
                self._set_status("Loading iBugger Core...")
                self.progress["value"] = 25
                try:
                    transport.startup_core(
                        nano2g_device.get_logo_bin(), nano2g_device.get_core_bin()
                    )
                except nano2g_device.TransportError as exc:
                    self._log(f"ERROR: Failed to load Core: {exc}")
                    self._set_status("Failed: Could not load Core")
                    messagebox.showerror("Error", f"Failed to load iBugger Core:\n{exc}")
                    return
            elif transport.core_type != 2:
                self._log(f"ERROR: Unexpected iBugger stage core_type={transport.core_type}")
                self._set_status("Failed: Unexpected device stage")
                return
            else:
                self._log("[3/4] Device is already running Core.")

            self.progress["value"] = 35
            payload = nano2g_device.get_decryptfirmware_bin()
            decrypted_partitions = []
            total = len(device_partitions)

            for idx, part_name in enumerate(device_partitions):
                part_offset, part_length = partition_ranges[part_name]
                raw = fw_data[part_offset:part_offset + part_length]
                self._log(
                    f"\n[4/4] Decrypting '{part_name}' via device AES engine "
                    f"({idx + 1}/{total}, {len(raw):,} bytes)..."
                )
                self._set_status(f"Decrypting {part_name} on device ({idx + 1}/{total})...")
                try:
                    result = transport.run_crypto_payload(payload, raw)
                except (nano2g_device.TransportError, TimeoutError, ValueError) as exc:
                    self._log(f"  ❌ {part_name}: {exc}")
                    self._set_status(f"Failed: {part_name}")
                    continue

                out_path = os.path.join(output_dir, f"{part_name}.bin")
                with open(out_path, 'wb') as f:
                    f.write(result)
                self._log(
                    f"  ✅ {part_name}: {len(result):,} bytes decrypted "
                    f"(sha256={hashlib.sha256(result).hexdigest()[:16]}...)"
                )
                decrypted_partitions.append(part_name)
                self.progress["value"] = 35 + ((idx + 1) / total) * 55
        finally:
            transport.close()

        self.progress["value"] = 95
        self._log(f"\n{'=' * 55}")
        if decrypted_partitions:
            self._log("✅ SUCCESS! Nano 2G partitions decrypted via device hardware AES.")
            self._log(f"   Output directory: {output_dir}")
            for part_name in decrypted_partitions:
                out_file = os.path.join(output_dir, f"{part_name}.bin")
                size = os.path.getsize(out_file)
                self._log(f"   {part_name}.bin: {size:,} bytes")
            self._log(f"{'=' * 55}")
            self._set_status("✅ Nano 2G device decrypt complete")
            self.progress["value"] = 100
            messagebox.showinfo(
                "Success",
                f"Nano 2G partitions decrypted using the device's real "
                f"hardware AES engine.\n\n"
                f"Model: {self.detected_model}\n"
                f"Partitions: {', '.join(decrypted_partitions)}\n"
                f"Output: {output_dir}\n\n"
                "This used the actual on-device AES engine (RAM-resident "
                "Loader/Core, no NAND/NOR/flash write) rather than the "
                "unverified public '0x837' key.\n\n"
                "To restore normal operation: reset the iPod into Disk Mode "
                "(Menu+Select, then Select+Play/Pause), then click "
                "'Remove loader.htm (restore iPod)' below."
            )
        else:
            self._log("❌ No partitions were decrypted successfully.")
            self._set_status("❌ Decrypt failed")

    # ============================================================
    # Category 2: Hardware AES Decrypt (native Windows)
    # ============================================================
    def _export_nano5g_rsrc_files(self, rsrc_path, output_dir,
                                  export_rsrc=False, export_silver=False):
        """Export Nano 5G plaintext RSRC content without AES processing."""
        with open(rsrc_path, 'rb') as f:
            rsrc_data = f.read()

        exported = []
        if export_rsrc:
            rsrc_output = os.path.join(output_dir, 'rsrc.bin')
            with open(rsrc_output, 'wb') as f:
                f.write(rsrc_data)
            self._log(
                f"  ✅ rsrc.bin exported raw/plaintext: {len(rsrc_data):,} bytes"
            )
            exported.append('rsrc')

        if export_silver:
            silver_data = extract_silver_images_db(rsrc_data)
            silver_output = os.path.join(output_dir, 'SilverImagesDB.LE.bin')
            with open(silver_output, 'wb') as f:
                f.write(silver_data)
            self._log(
                "  ✅ SilverImagesDB.LE.bin exported from "
                f"Resources/UI: {len(silver_data):,} bytes"
            )
            exported.append('SilverImagesDB.LE.bin')

        return exported

    def _decrypt_category2_native(self):
        """Decrypt firmware using native Windows wInd3x-win.exe.
        Uses direct USB via WinUSB/libusb — no WSL or usbipd needed."""
        ipsw_path = self.ipsw_path.get()
        output_path = self.output_path.get()

        self._log("=" * 55)
        self._log(f"Model: {self.detected_model} (Category 2 — Native Windows)")
        self._log("=" * 55)
        self._log("⚠️  This process takes approximately 30 min to 2 hours.")
        self._log("    Using NATIVE Windows USB (no WSL needed).\n")

        # Step 1: Stop Apple services that hold USB exclusively
        self._set_status("[1/5] Preparing USB access...")
        self._log("[1/5] Stopping Apple services for direct USB access...")
        for svc in ["Apple Mobile Device Service", "iPodService"]:
            try:
                subprocess.run(['net', 'stop', svc], capture_output=True, timeout=10,
                              creationflags=0x08000000)
            except Exception:
                pass
        self.progress["value"] = 2

        # Unbind usbipd if it's holding the device
        try:
            subprocess.run(['usbipd', 'unbind', '--all'],
                          capture_output=True, timeout=5,
                          creationflags=0x08000000, startupinfo=_get_startupinfo())
        except Exception:
            pass

        # Step 2: Extract OSOS from IPSW
        self._set_status("[2/5] Extracting firmware from IPSW...")
        self._log("\n[2/5] Extracting firmware from IPSW...")
        self.progress["value"] = 3

        try:
            fw_data = None
            with zipfile.ZipFile(ipsw_path, 'r') as z:
                for name in z.namelist():
                    if (name.lower().startswith('firmware') and
                            not name.endswith('.plist') and '/' not in name):
                        self._log(f"  Found: {name}")
                        fw_data = z.read(name)
                        break
            if not fw_data:
                self._log("ERROR: No firmware file found!")
                self._set_status("Failed: No firmware in IPSW")
                return
            self._log(f"  Size: {len(fw_data):,} bytes")
        except zipfile.BadZipFile:
            self._log("ERROR: Invalid IPSW/ZIP!")
            self._set_status("Failed: Invalid IPSW")
            return

        # Save to temp and run MSE extract natively
        temp_dir = os.environ.get('TEMP', 'C:\\Temp')
        temp_fw = os.path.join(temp_dir, 'ipod_fw_enc.bin')
        temp_mse_dir = os.path.join(temp_dir, 'ipod_mse_out')
        os.makedirs(temp_mse_dir, exist_ok=True)
        with open(temp_fw, 'wb') as f:
            f.write(fw_data)

        self._log("  Running MSE extract (native)...")
        ok, out, err = run_native_wind3x(
            ['mse', 'extract', temp_fw, '-o', temp_mse_dir + '\\'], timeout=60)
        self._log(f"  {(out + err)[:300]}" if (out + err) else "  (no output)")

        # Determine which partitions to decrypt
        selected_partitions = self._get_selected_partitions()
        if not selected_partitions:
            self._log("ERROR: No partitions selected!")
            self._set_status("Failed: No partitions selected")
            self._cleanup_temp(temp_fw)
            return

        # Determine which selected MSE members exist. SilverImagesDB is a
        # file inside Nano 5G RSRC, so selecting it implicitly requires the
        # RSRC member even if the user did not select the raw rsrc export.
        is_nano5g = self.detected_family_id == 34
        selected_mse_partitions = [
            name for name in selected_partitions if name != 'silverimagesdb'
        ]
        if is_nano5g and 'silverimagesdb' in selected_partitions:
            if 'rsrc' not in selected_mse_partitions:
                selected_mse_partitions.append('rsrc')

        available_partitions = []
        for part_name in selected_mse_partitions:
            part_path = os.path.join(temp_mse_dir, part_name)
            if os.path.isfile(part_path) and os.path.getsize(part_path) > 0:
                available_partitions.append(part_name)

        if not available_partitions:
            # Fallback: if MSE extraction failed, use raw firmware for osos only
            if 'osos' in selected_mse_partitions:
                self._log("  MSE failed, using raw firmware as osos input...")
                available_partitions = ['osos']
                osos_fallback = os.path.join(temp_mse_dir, 'osos')
                shutil.copy2(temp_fw, osos_fallback)
            else:
                self._log("ERROR: MSE extraction failed and no selected data exists!")
                self._set_status("Failed: No partition data")
                self._cleanup_temp(temp_fw)
                return

        self._log(f"  ✅ MSE members available: {', '.join(available_partitions)}")
        for part_name in available_partitions:
            part_path = os.path.join(temp_mse_dir, part_name)
            self._log(f"     {part_name}: {os.path.getsize(part_path):,} bytes")
        self.progress["value"] = 8

        output_dir = self.output_path.get()
        os.makedirs(output_dir, exist_ok=True)
        exported_partitions = []

        # Nano 5G RSRC is format-4/plaintext and contains a FAT16 volume.
        # Never send it through the hardware AES command.
        if is_nano5g and 'rsrc' in available_partitions:
            try:
                exported_partitions.extend(self._export_nano5g_rsrc_files(
                    os.path.join(temp_mse_dir, 'rsrc'),
                    output_dir,
                    export_rsrc=('rsrc' in selected_partitions),
                    export_silver=('silverimagesdb' in selected_partitions),
                ))
            except (OSError, Nano5GResourceError) as exc:
                self._log(f"  ❌ Nano 5G RSRC/SilverImagesDB export failed: {exc}")
                self._set_status("Failed: Nano 5G resource export")
                self._cleanup_temp(temp_fw)
                return

        device_partitions = [
            name for name in available_partitions
            if not (is_nano5g and name == 'rsrc')
        ]

        # Step 3: haxdfu (BootROM exploit) — only when encrypted data
        # remains to be processed. Plaintext RSRC-only exports need no device.
        if device_partitions:
            self._set_status("[3/5] Running BootROM exploit (haxdfu)...")
            self._log("\n[3/5] Running haxdfu (native Windows)...")
            self.progress["value"] = 10

            ok, out, err = run_native_wind3x(['haxdfu', '-v'], timeout=30)
            combined = out + err
            self._log(f"  {combined[:400]}" if combined else "  (no output)")

            if "Haxed DFU" in combined or "already" in combined.lower() or "triggered" in combined.lower():
                self._log("  ✅ Exploit successful!")
            else:
                self._log("  ⚠️ Exploit result uncertain, attempting decrypt anyway...")
            self.progress["value"] = 15
        else:
            self._log("\nNo encrypted partitions selected; skipped haxdfu/device AES.")
            self.progress["value"] = 85

        # Step 4/5: Decrypt encrypted IMG1 members via hardware AES
        total_partitions = len(device_partitions)
        for part_idx, part_name in enumerate(device_partitions):
            part_path = os.path.join(temp_mse_dir, part_name)
            output_file = os.path.join(output_dir, f"{part_name}.bin")
            recovery_path = output_file + RECOVERY_SUFFIX
            progress_path = output_file + PROGRESS_SUFFIX

            self._log(f"\n[5/5] Decrypting partition '{part_name}' ({part_idx + 1}/{total_partitions})...")
            self._set_status(f"Decrypting {part_name} ({part_idx + 1}/{total_partitions})...")

            # Check resume state for this partition
            resume_percent = 0
            if os.path.exists(progress_path):
                try:
                    with open(progress_path, 'r') as f:
                        state = json.load(f)
                    resume_percent = state.get('percent', 0)
                    if resume_percent > 0 and os.path.exists(recovery_path):
                        self._log(f"  📂 Resuming {part_name} from {resume_percent:.1f}%")
                    else:
                        resume_percent = 0
                except (json.JSONDecodeError, KeyError):
                    resume_percent = 0

            self._log(f"  ⏱️  Do NOT disconnect iPod.")

            # Run decrypt as streaming process
            wind3x = get_bundled_path(WIND3X_WIN_NAME)
            if not wind3x:
                self._log("ERROR: wInd3x-win.exe not found!")
                self._set_status("Failed: wInd3x-win.exe missing")
                return

            decrypt_args = [wind3x, 'decrypt', part_path, output_file, '-v', '-r', recovery_path]
            proc = subprocess.Popen(
                decrypt_args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                cwd=os.path.dirname(wind3x),
                creationflags=0x08000000
            )

            last_percent = resume_percent
            retry_count = 0
            # Progress range for this partition within overall 15-95%
            progress_base = 15 + (part_idx / total_partitions) * 80
            progress_span = 80 / total_partitions

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                if "percent=" in line:
                    try:
                        pct = float(line.split("percent=")[1].split()[0].rstrip('%,'))
                        if pct > last_percent:
                            last_percent = pct
                            self.progress["value"] = progress_base + (pct / 100.0) * progress_span
                            self._set_status(
                                f"Decrypting {part_name} ({part_idx + 1}/{total_partitions}): {pct:.1f}%")
                            if int(pct) > int(last_percent - 1):
                                self._save_progress(progress_path, pct)
                    except (ValueError, IndexError):
                        pass
                elif "timeout" in line.lower() or "retry" in line.lower():
                    retry_count += 1
                    if retry_count <= 5:
                        self._log(f"  ↻ USB retry #{retry_count} (normal)")
                    elif retry_count % 10 == 0:
                        self._log(f"  ↻ USB retries: {retry_count}")
                elif "error" in line.lower() and "timeout" not in line.lower():
                    self._log(f"  ⚠️ {line}")
                elif "done" in line.lower() or "complete" in line.lower():
                    self._log(f"  ✅ {line}")
                    break
                elif "decrypt" in line.lower() or "progress" in line.lower():
                    self._log(f"  {line}")

            proc.wait()

            # Verify partition output
            if os.path.exists(output_file) and os.path.getsize(output_file) > 1000:
                size = os.path.getsize(output_file)
                self._log(f"  ✅ {part_name} decrypted: {size:,} bytes")
                exported_partitions.append(part_name)
                self._cleanup_recovery(recovery_path, progress_path)
            else:
                self._log(f"  ❌ {part_name} output incomplete at {last_percent:.1f}%")
                self._save_progress(progress_path, last_percent)

        self.progress["value"] = 95

        # Final summary
        self._log(f"\n{'=' * 55}")
        self._log(f"✅ Decryption complete (native Windows).")
        self._log(f"   Output directory: {output_dir}")
        for part_name in exported_partitions:
            out_file = os.path.join(
                output_dir,
                part_name if part_name == 'SilverImagesDB.LE.bin' else f"{part_name}.bin",
            )
            if os.path.exists(out_file):
                size = os.path.getsize(out_file)
                self._log(f"   {os.path.basename(out_file)}: {size:,} bytes ({size / 1024 / 1024:.1f} MB)")
        self._log(f"{'=' * 55}")
        self._set_status("✅ Decryption/export complete!")
        self.progress["value"] = 100
        messagebox.showinfo("Success",
                            f"Firmware decrypted/exported!\n\n"
                            f"Model: {self.detected_model}\n"
                            f"Outputs: {', '.join(exported_partitions)}\n"
                            f"Output directory: {output_dir}")

        # Cleanup temp
        self._cleanup_temp(temp_fw)

        # Restart Apple services
        for svc in ["Apple Mobile Device Service", "iPodService"]:
            try:
                subprocess.run(['net', 'start', svc], capture_output=True, timeout=10,
                              creationflags=0x08000000)
            except Exception:
                pass

    # ============================================================
    # Helpers
    # ============================================================
    def _save_progress(self, progress_path, percent):
        """Persist current decrypt progress to disk."""
        try:
            state = {
                'percent': percent,
                'timestamp': time.time(),
                'model': self.detected_model,
                'ipsw': self.ipsw_path.get(),
            }
            with open(progress_path, 'w') as f:
                json.dump(state, f)
        except OSError:
            pass

    def _cleanup_recovery(self, recovery_path, progress_path):
        """Remove recovery/progress files after successful decrypt."""
        for path in (recovery_path, progress_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def _cleanup_temp(self, *paths):
        """Remove temporary files."""
        for path in paths:
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    # ============================================================
    # Run
    # ============================================================
    def run(self):
        """Start the application."""
        self.root.mainloop()


# ============================================================
# Entry Point
# ============================================================
if __name__ == '__main__':
    auto_elevate()
    app = UniversalDecryptorApp()
    app.run()
