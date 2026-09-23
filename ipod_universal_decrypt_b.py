"""
Universal iPod Firmware Decryptor v3.3.0
========================================
Decrypts the iPod RetailOS (OSOS) for ALL iPod models.

Category 1 (Not Encrypted):
  iPod 1G-5G, Nano 1G, Mini 1G/2G — extract from IPSW, no device needed.

Category 2 (Hardware AES):
  iPod Classic, Nano 3G-5G — requires device in DFU mode + wInd3x.

Category 3 (Software AES, public key):
  Historical S5L8701 DNAN reconstruction — no device needed.

Category 4 (Hardware AES via Notes exploit):
  iPod Nano 2G (S5L8701) — iBugger Loader/Core over USB (RAM-resident).

Platforms:
  * Windows 10/11 (x64) — WinUSB transport, wInd3x-win.exe.
  * macOS 11+ (Apple Silicon and Intel) — libusb iBugger transport,
    native wInd3x darwin build; no driver installation or elevation.
  * Linux — development/testing support (trampoline exploits for
    Nano 4G/5G only work on bare-metal Linux per upstream wInd3x).

Run the GUI with no arguments, or headless with ``--cli``.
"""

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ipod_platform as plat  # noqa: E402
import ibugger_transport  # noqa: E402
import nano2g_device_decrypt as nano2g_device  # noqa: E402
from nano5g_resources import (  # noqa: E402
    Nano5GResourceError,
    extract_silver_images_db,
)
from mse_members import (  # noqa: E402
    MseFormatError,
    parse_mse_members,
)

# ============================================================
# Constants
# ============================================================
APP_NAME = "Universal iPod Firmware Decryptor"
APP_VERSION = "3.3.0"
APP_BUILD = 40

APPLE_VID = "05ac"
DFU_PIDS = ["1223", "1225", "1231", "1232", "1234", "1242", "1250"]

WIND3X_WIN_NAME = "wInd3x-win.exe"
LIBUSB_DLL_NAME = "libusb-1.0.dll"
ZADIG_NAME = "zadig.exe"

# Recovery state persists next to output file
RECOVERY_SUFFIX = ".recovery.dat"
PROGRESS_SUFFIX = ".progress.json"
APPLE_SERVICE_STATE_NAME = ".apple_usb_services.json"
MAX_RETRY_ATTEMPTS = 10

# These models can be parsed and their plaintext RSRC can be inspected, but
# the current S5Late DFU state corruption prevents the repeated RCE/AES loop
# required for the app's decrypt command. Do not present them as supported.
UNSUPPORTED_CATEGORY2_FAMILIES = frozenset({36, 37})

# The Nano 4G/5G "blx r0" trampoline exploit (haxdfu/dump/decrypt) is only
# possible on bare-metal Linux per upstream wInd3x (the host stack must be
# able to abort a DFU transfer after exactly 0x40 bytes). On macOS these
# models can still have their RAW/plaintext MSE members exported, but
# device-AES decryption is not possible.
MACOS_LINUX_ONLY_FAMILIES = frozenset({31, 34})

# ============================================================
# Nano 2G (S5L8701) DNAN software-decrypt constants (Category 3)
# ============================================================
# Nano 2G (S5L8701) AES-128-CBC key — publicly known "0x837" key
# Source: TheAppleWiki AES Keys page (derived from S5L8900 GID key)
NANO2G_KEY = bytes.fromhex("188458A6D15034DFE386F23B61D43774")
NANO2G_IV = bytes(16)  # All zeros
NANO2G_HEADER_SIZE = 0x800  # Per-partition header retained before AES body
NANO2G_OUTER_MARKER_OFFSET = 0x100
NANO2G_OUTER_MARKER = b"]ih["
NANO2G_DIRECTORY_OFFSET = 0x4800
NANO2G_DIRECTORY_RECORD_SIZE = 0x28
NANO2G_DIRECTORY_RECORD_FORMAT = "<4s4s8I"
NANO2G_PARTITION_ALIASES = {
    b"crsr": "rsrc",
    b"soso": "osos",
    b"dpua": "aupd",
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
        if device == b"\x00" * 4:
            break
        if device != b"DNAN":
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
                with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as enc_file:
                    temp_enc = enc_file.name
                    enc_file.write(encrypted_body)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as dec_file:
                    temp_dec = dec_file.name
                result = subprocess.run(
                    ["openssl", "enc", "-d", "-aes-128-cbc", "-K", NANO2G_KEY.hex(),
                     "-iv", NANO2G_IV.hex(), "-in", temp_enc, "-out", temp_dec, "-nopad"],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    raise RuntimeError(f"openssl AES decryption failed: {result.stderr.strip()}")
                with open(temp_dec, "rb") as dec_file:
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
    if canonical_name == "rsrc":
        return partition_data, "raw/plaintext"
    if canonical_name not in ("osos", "aupd"):
        raise ValueError(f"Unsupported Nano 2G partition: {canonical_name}")
    if len(partition_data) <= NANO2G_HEADER_SIZE:
        raise ValueError(f"{canonical_name} partition has no body after local header")
    header = partition_data[:NANO2G_HEADER_SIZE]
    body = decrypt_nano2g_body(partition_data[NANO2G_HEADER_SIZE:])
    return header + body, "AES body processed; local 0x800-byte header retained"


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
    # iPod Nano 2G (S5L8701) — Category 4: Hardware AES via Notes-exploit
    # iBugger Loader/Core. The public "0x837" key does NOT apply to this
    # device; the real key is fused in hardware and only accessible by
    # running the AES engine on the device itself.
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
# IPSW filename parsing
# ============================================================
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
# Fonts (per platform)
# ============================================================
if plat.IS_WINDOWS:
    UI_FONT = "Segoe UI"
    MONO_FONT = "Consolas"
elif plat.IS_MACOS:
    UI_FONT = "Helvetica Neue"
    MONO_FONT = "Menlo"
else:
    UI_FONT = "TkDefaultFont"
    MONO_FONT = "TkFixedFont"


# ============================================================
# Shared decrypt controller (GUI + CLI)
# ============================================================
class DecryptController:
    """All decrypt logic, platform- and UI-agnostic.

    UI backends subclass this and implement the small virtual surface:
      log(msg), status(msg), progress(value), set_partition_options(options,
      hint), partition_selected (dict), get_selected_partitions(), and the
      dialog helpers popinfo/poperror. Anything emitted from worker threads
    goes through ui_emit() so GUI backends can marshal it to the main
    (Tk) thread safely.
    """

    def __init__(self, run_sync=False):
        self.run_sync = run_sync  # CLI: no worker threads
        self._ui_queue = queue.Queue()

        # IPSW / model state
        self.ipsw_path = ""
        self.output_path = ""
        self.detected_family_id = None
        self.detected_model = None
        self.detected_category = None
        self.is_running = False

        # Firmware members
        self.category2_members = {}
        self.partition_options = []       # [(name, label), ...]
        self.partition_selected = {}      # name -> bool
        self._members_token = 0

        # Nano 5G extra export
        self.silverimagesdb_enabled = True

    # ------------------------------------------------------------
    # Virtual UI surface (backends override)
    # ------------------------------------------------------------
    def log(self, msg):
        print(msg)

    def status(self, msg):
        pass

    def progress(self, value):
        pass

    def set_partition_options(self, options, hint=""):
        self.partition_options = list(options)
        if options:
            for name, _label in options:
                self.partition_selected.setdefault(name, True)

    def get_selected_partitions(self):
        selected = [name for name, var in self.partition_selected.items() if var]
        if (self.detected_family_id == 34 and "rsrc" in self.category2_members
                and self.silverimagesdb_enabled):
            selected.append("silverimagesdb")
        return selected

    def popinfo(self, title, message):
        self.ui_emit("dialog", "info", title, message)

    def poperror(self, title, message):
        self.ui_emit("dialog", "error", title, message)

    def popwarning(self, title, message):
        self.ui_emit("dialog", "warning", title, message)

    def confirm(self, title, message):
        return True

    def show_dialog(self, kind, title, message):
        """Backend hook for dialogs (called on the UI thread in the GUI,
        inline in the CLI)."""
        mark = {"info": "==", "error": "!! ERROR", "warning": "!! WARNING"}[kind]
        print(f"\n{mark} {title}\n{message}\n")

    def apply_members(self, token, ipsw_path, family_id, members, error):
        """Member-discovery result (called on a safe thread by backend)."""
        if token != self._members_token or ipsw_path != self.ipsw_path:
            return
        if error:
            self.category2_members = {}
            self.set_partition_options([], f"Could not read MSE members: {error}")
        else:
            self.category2_members = {m.name: m for m in members}
            options = []
            for m in members:
                action = "decrypt via device AES" if m.is_encrypted else "export raw/plaintext"
                options.append((m.name, f"{action} — {m.logical_length:,} bytes"))
            self.set_partition_options(options, "Members discovered from this IPSW's MSE directory.")

    # ------------------------------------------------------------
    # Thread-safe UI emission
    # ------------------------------------------------------------
    def ui_emit(self, kind, *args):
        """Queue a UI event. Worker threads MUST use this for anything that
        touches the GUI. In synchronous (CLI) mode events are dispatched
        inline because there is no separate UI thread."""
        if self.run_sync:
            self._dispatch_ui_event(kind, args)
            return
        self._ui_queue.put((kind, args))

    def _dispatch_ui_event(self, kind, args):
        """Apply one queued UI event (called on the UI thread by GUI)."""
        if kind == "log":
            self.log(args[0])
        elif kind == "status":
            self.status(args[0])
        elif kind == "progress":
            self.progress(args[0])
        elif kind == "dialog":
            self.show_dialog(args[0], args[1], args[2])
        elif kind == "members":
            self.apply_members(*args)
        elif kind == "model":
            self.model_state()
        elif kind == "mode":
            self.mode_state()
        elif kind == "nano2g_status":
            self.nano2g_stage_status(args[0])
        elif kind == "nano2g_info":
            pass  # GUI-only info line
        elif kind == "running":
            pass

    # ------------------------------------------------------------
    # Model detection / IPSW handling
    # ------------------------------------------------------------
    def on_ipsw_changed(self, path):
        """Detect model from IPSW filename and refresh all UI state."""
        path = (path or "").strip()
        self.ipsw_path = path
        if not path:
            self.detected_family_id = None
            self.detected_model = None
            self.detected_category = None
            self._set_partition_options_plain([], "(select an IPSW file)")
            self.model_state()
            return

        family_id, model_name, category = parse_ipsw_filename(path)
        self.detected_family_id = family_id
        self.detected_model = model_name
        self.detected_category = category

        if family_id is None:
            self._set_partition_options_plain([], "Could not detect model from filename")
            self.model_state()
            return

        self._update_default_output(model_name, category, family_id, path)

        if category == 1:
            self._members_token += 1
            self._set_partition_options_plain(
                [], "No partition selection is required for this plaintext firmware.")
        elif category == 3:
            self._members_token += 1
            self._set_partition_options_plain(
                [(n, "validated partition") for n in ("osos", "aupd", "rsrc")],
                "Select the partitions to process.")
        elif category == 4:
            self._members_token += 1
            self._set_partition_options_plain(
                [(n, "validated partition") for n in ("osos", "aupd", "rsrc")],
                "Select the partitions to process.")
        elif category == 2:
            if family_id in UNSUPPORTED_CATEGORY2_FAMILIES:
                self._members_token += 1
                self.category2_members = {}
                self._set_partition_options_plain(
                    [],
                    "This model's S5Late path is research-only; repeated "
                    "firmware decryption is not supported.")
            else:
                self.model_state()
                self.mode_state()
                self.discover_category2_members(path, family_id)
                return  # member discovery (async) refreshes the UI
        else:
            self._set_partition_options_plain([], "Unknown category")

        self.model_state()

    def _set_partition_options_plain(self, options, hint):
        self.set_partition_options(options, hint)

    def _update_default_output(self, model_name, category, family_id, path):
        safe_name = re.sub(r"[^\w]", "_", model_name.split("(")[0].strip())
        basename = os.path.basename(path)
        ver_match = re.match(r"iPod_(\d+[.\d]+)", basename, re.IGNORECASE)
        if ver_match:
            version_str = ver_match.group(1)
        else:
            ver_match2 = re.match(r"iPod_([\d.]+_[A-Z0-9]+)", basename, re.IGNORECASE)
            version_str = ver_match2.group(1) if ver_match2 else str(family_id)
        if category in (2, 3, 4):
            self.output_path = os.path.join(
                plat.default_desktop(), f"decrypted_{safe_name}_{version_str}")
        else:
            self.output_path = os.path.join(
                plat.default_desktop(), f"osos_decrypted_{safe_name}_{version_str}.bin")

    def discover_category2_members(self, ipsw_path, family_id):
        """Read the IPSW's MSE table (on a worker thread unless run_sync)
        and rebuild the member checklist from real members."""
        self._members_token += 1
        token = self._members_token
        self.category2_members = {}
        self._set_partition_options_plain([], "Reading actual MSE members...")

        def scan():
            try:
                with zipfile.ZipFile(ipsw_path, "r") as archive:
                    firmware_name = next(
                        name for name in archive.namelist()
                        if (name.lower().startswith("firmware")
                            and not name.lower().endswith(".plist")
                            and "/" not in name)
                    )
                    firmware = archive.read(firmware_name)
                members = parse_mse_members(
                    firmware, nano3_layout=family_id in (26, 27))
                error = None
            except (OSError, StopIteration, zipfile.BadZipFile, MseFormatError) as exc:
                members = []
                error = str(exc)
            self.ui_emit("members", token, ipsw_path, family_id, members, error)

        if self.run_sync:
            scan()
        else:
            threading.Thread(target=scan, daemon=True).start()

    # Backends call these from the main/UI thread
    def model_state(self):
        """Called after model detection so the backend can repaint."""

    def mode_state(self):
        """Called when the mode label should update."""

    # ------------------------------------------------------------
    # Decrypt entry point
    # ------------------------------------------------------------
    def start_decrypt(self):
        if self.is_running:
            return
        ipsw = self.ipsw_path
        if not ipsw or not os.path.isfile(ipsw):
            self.poperror("Error", f"Please select a valid IPSW file first:\n{ipsw or '(none)'}")
            return
        if self.detected_category is None:
            self.poperror("Error", "Could not detect iPod model from filename.\n"
                                   "Expected format: iPod_XX.X.X.X.ipsw")
            return
        self.is_running = True
        self.ui_emit("running", True)
        self.progress(0)
        if self.run_sync:
            self._decrypt_thread()
        else:
            threading.Thread(target=self._decrypt_thread, daemon=True).start()

    def _decrypt_thread(self):
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
                self.log("ERROR: Unknown device category")
                self.status("Failed: Unknown category")
        except Exception as exc:  # noqa: BLE001
            self.log(f"ERROR: {exc}")
            self.status(f"Failed: {exc}")
        finally:
            self.is_running = False
            self.ui_emit("running", False)

    # ------------------------------------------------------------
    # Category 1: Not Encrypted (extract only)
    # ------------------------------------------------------------
    def _extract_firmware_from_ipsw(self, ipsw_path):
        """Return (firmware_bytes, firmware_member_name) from an IPSW ZIP."""
        with zipfile.ZipFile(ipsw_path, "r") as archive:
            for name in archive.namelist():
                if (name.lower().startswith("firmware")
                        and not name.endswith(".plist") and "/" not in name):
                    return archive.read(name), name
        return None, None

    def _decrypt_category1(self):
        """Handle unencrypted iPods — extract OSOS from IPSW."""
        ipsw_path = self.ipsw_path
        output_path = self.output_path

        self.log("=" * 55)
        self.log(f"Model: {self.detected_model} (Category 1 — Not Encrypted)")
        self.log(f"Platform: {plat.PLATFORM_NAME}")
        self.log("=" * 55)
        self.status("Extracting firmware from IPSW...")
        self.progress(10)

        # Step 1: extract firmware file from IPSW ZIP
        self.log("\n[1/3] Extracting firmware from IPSW (ZIP archive)...")
        try:
            fw_data, fw_name = self._extract_firmware_from_ipsw(ipsw_path)
            if not fw_data:
                self.log("ERROR: No firmware file found in IPSW archive!")
                self.status("Failed: No firmware in IPSW")
                return
            self.log(f"  Found firmware file: {fw_name}")
            self.log(f"  Size: {len(fw_data):,} bytes")
            self.progress(30)
        except zipfile.BadZipFile:
            self.log("ERROR: File is not a valid IPSW/ZIP archive!")
            self.status("Failed: Invalid IPSW")
            return

        # Step 2: OSOS via MSE member parse, native wInd3x, or header strip
        self.log("\n[2/3] Extracting OSOS from firmware container...")
        self.status("Extracting OSOS from MSE/IMG container...")
        self.progress(40)

        # Preferred: our own read-only MSE parser (all platforms).
        osos_data = None
        try:
            members = parse_mse_members(fw_data)
            for member in members:
                if member.name.lower() == "osos":
                    osos_data = fw_data[member.logical_offset:
                                        member.logical_offset + member.logical_length]
                    self.log(f"  ✅ MSE member 'osos' extracted: {len(osos_data):,} bytes "
                             f"({member.detail})")
                    break
        except MseFormatError:
            pass

        # Fallback 1: native wInd3x mse extract (Windows build + darwin build)
        if osos_data is None and plat.find_wind3x():
            temp_dir = plat.temp_dir()
            temp_fw = os.path.join(temp_dir, "ipod_fw_temp.bin")
            temp_mse_dir = os.path.join(temp_dir, "ipod_mse_cat1")
            os.makedirs(temp_mse_dir, exist_ok=True)
            with open(temp_fw, "wb") as f:
                f.write(fw_data)
            self.log("  Trying native wInd3x mse extract...")
            ok, out, err = plat.run_wind3x(
                ["mse", "extract", temp_fw, "-o", temp_mse_dir], timeout=60)
            combined = out + err
            self.log(f"  {(combined[:200]).strip() or '(no output)'}")
            osos_path = os.path.join(temp_mse_dir, "osos")
            if os.path.isfile(osos_path) and os.path.getsize(osos_path) > 0:
                with open(osos_path, "rb") as f:
                    osos_data = f.read()
                self.log(f"  ✅ MSE extract successful! OSOS size: {len(osos_data):,} bytes")
            try:
                os.remove(temp_fw)
                shutil.rmtree(temp_mse_dir, ignore_errors=True)
            except OSError:
                pass

        # Fallback 2: strip IMG1/8900 header (first 0x800 bytes)
        if osos_data is None:
            self.log("  MSE extract unavailable/failed. Falling back to header strip (0x800 bytes)...")
            if len(fw_data) > 0x800:
                osos_data = fw_data[0x800:]
                self.log(f"  Stripped 0x800 header. OSOS size: {len(osos_data):,} bytes")
            else:
                self.log("ERROR: Firmware file too small to contain OSOS!")
                self.status("Failed: Firmware too small")
                return

        with open(output_path, "wb") as f:
            f.write(osos_data)
        self.progress(80)

        # Step 3: verify output
        self.log("\n[3/3] Verifying output...")
        self.status("Verifying output file...")
        self.progress(90)

        if os.path.exists(output_path) and os.path.getsize(output_path) > 1000:
            size = os.path.getsize(output_path)
            self.log(f"\n{'=' * 55}")
            self.log("✅ SUCCESS! OSOS extracted (plaintext, not encrypted).")
            self.log(f"   File: {output_path}")
            self.log(f"   Size: {size:,} bytes ({size / 1024 / 1024:.2f} MB)")
            self.log(f"{'=' * 55}")
            self.status("✅ Extraction complete!")
            self.progress(100)
            self.popinfo(
                "Success",
                f"OSOS extracted successfully!\n\n"
                f"Model: {self.detected_model}\n"
                f"File: {output_path}\n"
                f"Size: {size:,} bytes\n\n"
                "Note: This firmware is NOT encrypted.")
        else:
            self.log("❌ Output file not found or empty.")
            self.status("❌ Extraction failed")

    # ------------------------------------------------------------
    # Category 3: Software AES Decrypt (Nano 2G DNAN — known key)
    # ------------------------------------------------------------
    def _decrypt_category3(self):
        """Parse, extract, and process Nano 2G S5L8701 partitions."""
        ipsw_path = self.ipsw_path
        output_dir = self.output_path

        self.log("=" * 55)
        self.log(f"Model: {self.detected_model} (Category 3 — Software Decrypt)")
        self.log(f"Platform: {plat.PLATFORM_NAME}")
        self.log("=" * 55)
        self.log("Using the validated S5L8701 DNAN directory; no native MSE fallback.\n")
        self.status("Reading Nano 2G partition directory...")
        self.progress(10)

        self.log("[1/3] Extracting firmware from IPSW...")
        try:
            fw_data, fw_name = self._extract_firmware_from_ipsw(ipsw_path)
            if not fw_data:
                self.log("ERROR: No firmware file found!")
                self.status("Failed: No firmware in IPSW")
                return
            self.log(f"  Found: {fw_name}")
            self.log(f"  Size: {len(fw_data):,} bytes")
        except (zipfile.BadZipFile, OSError) as exc:
            self.log(f"ERROR: Cannot read IPSW: {exc}")
            self.status("Failed: Invalid IPSW")
            return

        self.progress(20)
        selected_partitions = self.get_selected_partitions()
        if not selected_partitions:
            self.log("ERROR: No partitions selected!")
            self.status("Failed: No partitions selected")
            return

        unsupported = [name for name in selected_partitions
                       if name not in NANO2G_SUPPORTED_PARTITIONS]
        for name in unsupported:
            self.log(f"ERROR: '{name}' is not present in the validated Nano 2G directory; skipping it.")
        selected_partitions = [name for name in selected_partitions
                               if name in NANO2G_SUPPORTED_PARTITIONS]
        if not selected_partitions:
            self.log("ERROR: None of the selected partitions are supported by Nano 2G.")
            self.status("Failed: Unsupported Nano 2G partitions")
            return

        try:
            partition_ranges = parse_nano2g_partitions(fw_data)
        except ValueError as exc:
            self.log(f"ERROR: Invalid Nano 2G partition directory: {exc}")
            self.status("Failed: Invalid Nano 2G directory")
            return

        self.log("  ✅ Validated ]ih[ marker and three DNAN records at 0x4800")
        for name in ("rsrc", "osos", "aupd"):
            part_offset, part_length = partition_ranges[name]
            self.log(f"  {name}: offset 0x{part_offset:x}, total export size {part_length:,} bytes (0x800 header + directory payload)")
        self.log(f"  ✅ Partitions selected: {', '.join(selected_partitions)}")
        self.progress(30)

        self.log("\n[2/3] Extracting exact partition ranges and processing selected data...")
        os.makedirs(output_dir, exist_ok=True)
        exported_partitions = []
        total_partitions = len(selected_partitions)

        for part_idx, part_name in enumerate(selected_partitions):
            part_offset, part_length = partition_ranges[part_name]
            partition_data = fw_data[part_offset:part_offset + part_length]
            output_file = os.path.join(output_dir, f"{part_name}.bin")
            self.log(f"\n  Processing '{part_name}' ({part_idx + 1}/{total_partitions})...")
            self.log(f"    Exact source range: 0x{part_offset:x}:0x{part_offset + part_length:x}")
            try:
                exported_data, processing_note = prepare_nano2g_partition(
                    part_name, partition_data)
                with open(output_file, "wb") as output:
                    output.write(exported_data)
            except (OSError, RuntimeError, ValueError) as exc:
                self.log(f"    ❌ {part_name}: {exc}")
                self.status(f"Failed: {part_name}")
                return

            exported_partitions.append(part_name)
            self.log(f"    ✅ {part_name}: {len(exported_data):,} bytes ({processing_note})")
            self.progress(30 + ((part_idx + 1) / total_partitions) * 60)

        self.progress(90)
        self.log("\n[3/3] Verifying output...")
        self.log("  ✅ Every output includes the local 0x800-byte header plus the full directory-defined payload; no bytes were omitted.")
        self.log("  ⚠️ OSOS/AUPD AES output is not cryptographically verified without a known-good fixture or device validation.")
        self.log(f"\n{'=' * 55}")
        self.log("✅ SUCCESS! Nano 2G partitions exported.")
        self.log(f"   Output directory: {output_dir}")
        for part_name in exported_partitions:
            out_file = os.path.join(output_dir, f"{part_name}.bin")
            size = os.path.getsize(out_file)
            self.log(f"   {part_name}.bin: {size:,} bytes")
        self.log(f"{'=' * 55}")
        self.status("✅ Nano 2G partition export complete")
        self.progress(100)
        self.popinfo(
            "Success",
            f"Nano 2G partitions exported.\n\n"
            f"Model: {self.detected_model}\n"
            f"Partitions: {', '.join(exported_partitions)}\n"
            f"Output: {output_dir}\n\n"
            "RSRC was copied as plaintext. OSOS/AUPD retain their local "
            "0x800-byte headers and have their bodies AES-processed.\n"
            "Cryptographic correctness still requires a known-good fixture or device validation."
        )

    # ------------------------------------------------------------
    # Category 4: Nano 2G Hardware AES via Notes-exploit iBugger
    # ------------------------------------------------------------
    def _nano2g_find_ipod_notes_drive(self):
        """Find a removable volume that looks like a disk-mode iPod
        (has a Notes folder). Returns the volume root or None."""
        return plat.find_ipod_notes_mount()

    def _nano2g_stage_loader(self):
        """Write the patched loader.htm into the iPod's Notes folder."""
        drive = self._nano2g_find_ipod_notes_drive()
        if not drive:
            self.poperror(
                "iPod Not Found",
                "No volume with a Notes folder was found.\n\n"
                "Put the iPod in Disk Mode (Menu+Select to reset, then "
                "immediately Select+Play/Pause) and try again."
                + ("\n\nOn macOS the iPod mounts under /Volumes/<name>." if plat.IS_MACOS else ""))
            return
        notes_dir = os.path.join(drive, "Notes")
        loader_path = os.path.join(notes_dir, "loader.htm")
        try:
            if os.path.isfile(loader_path):
                backup_path = loader_path + ".backup"
                if not os.path.isfile(backup_path):
                    shutil.copy2(loader_path, backup_path)
                    self.log(f"Backed up existing loader.htm to {backup_path}")
            loader_data = nano2g_device.get_loader_htm()
            with open(loader_path, "wb") as f:
                f.write(loader_data)
            self.log(f"Staged patched loader.htm ({len(loader_data):,} bytes) to {loader_path}")
            self.nano2g_stage_status("✅ loader.htm staged. Eject the iPod, then reconnect it.")
            self.popinfo(
                "Staged",
                f"Patched loader.htm written to:\n{loader_path}\n\n"
                "Now eject the iPod safely and reconnect it (or reset it). "
                "It should boot into Notes automatically and re-enumerate as "
                "'Unified iBugger'. Then click 'Check iBugger Status'.")
        except OSError as exc:
            self.log(f"ERROR: Could not stage loader.htm: {exc}")
            self.poperror("Error", f"Could not write loader.htm:\n{exc}")

    def _nano2g_cleanup_loader(self):
        """Remove the Notes-exploit loader.htm from the iPod so it boots
        normally again instead of re-launching the iBugger Loader."""
        drive = self._nano2g_find_ipod_notes_drive()
        if not drive:
            self.poperror(
                "iPod Not Found",
                "No volume with a Notes folder was found.\n\n"
                "Put the iPod in Disk Mode (Menu+Select to reset, then "
                "immediately Select+Play/Pause) and try again.\n\n"
                "Note: if the iPod is currently running as USB iBugger "
                "Loader/Core, it has no mounted filesystem yet - reset it "
                "into Disk Mode first."
                + ("\n\nOn macOS the iPod mounts under /Volumes/<name>." if plat.IS_MACOS else ""))
            return
        notes_dir = os.path.join(drive, "Notes")
        loader_path = os.path.join(notes_dir, "loader.htm")
        backup_path = loader_path + ".backup"

        if not os.path.isfile(loader_path):
            self.log(f"No loader.htm found at {loader_path}; nothing to clean up.")
            self.nano2g_stage_status("ℹ️ No loader.htm present. iPod is already clean.")
            self.popinfo("Nothing To Do", f"No loader.htm found at:\n{loader_path}")
            return

        try:
            if os.path.isfile(backup_path):
                shutil.move(backup_path, loader_path)
                self.log(f"Restored original loader.htm from backup at {backup_path}")
                result_msg = "Original loader.htm restored from backup."
            else:
                os.remove(loader_path)
                self.log(f"Deleted exploit loader.htm at {loader_path}")
                result_msg = "Exploit loader.htm deleted (no backup existed to restore)."
            self.nano2g_stage_status("✅ loader.htm removed. Eject the iPod, then reset/reconnect it.")
            self.popinfo(
                "Cleaned Up",
                f"{result_msg}\n\n"
                "Now eject the iPod safely and reset/reconnect it. It should "
                "boot normally instead of launching the iBugger Loader.")
        except OSError as exc:
            self.log(f"ERROR: Could not clean up loader.htm: {exc}")
            self.poperror("Error", f"Could not remove/restore loader.htm:\n{exc}")

    def nano2g_stage_status(self, text):
        """Backend hook for the Nano 2G staging status line."""

    def _nano2g_scan_device(self):
        """Read-only check for the iBugger Loader/Core USB interface."""
        self.nano2g_stage_status("🔍 Checking...")

        def check():
            try:
                status, stage, detail = ibugger_transport.find_device_status()
            except Exception as exc:  # noqa: BLE001
                self.ui_emit("nano2g_status", f"❌ Error: {exc}")
                return
            if status == "ok" and stage == "core":
                self.ui_emit("nano2g_status",
                             "✅ iBugger Core is running — ready to decrypt.")
                self.ui_emit("nano2g_info", "Stage: Core (device_type=Nano 2G)")
            elif status == "ok" and stage == "loader":
                self.ui_emit("nano2g_status",
                             "✅ iBugger Loader is running — Core will load automatically when you decrypt.")
                self.ui_emit("nano2g_info", "Stage: Loader")
            elif status == "present_no_winusb":
                self.ui_emit("nano2g_status",
                             "⚠️ iPod detected (VID_FFFF&PID_8642), but no driver is "
                             "bound on this system. (Should not happen on macOS — "
                             "raw libusb access needs no driver; try reconnecting.)")
                self.ui_emit("nano2g_info", "Driver setup needed")
                self.ui_emit("log", f"iBugger status: {detail}")
            elif status == "not_present":
                self.ui_emit("nano2g_status",
                             "❌ Not found. Stage loader.htm in Notes, then eject/reconnect.")
                self.ui_emit("nano2g_info", "")
            elif status == "error":
                self.ui_emit("nano2g_status", f"❌ {detail}")
                self.ui_emit("nano2g_info", "")
            else:
                self.ui_emit("nano2g_status",
                             f"❌ Unknown status: {detail}")
                self.ui_emit("nano2g_info", "")

        if self.run_sync:
            check()
        else:
            threading.Thread(target=check, daemon=True).start()

    def _decrypt_category4_nano2g_device(self):
        """Decrypt Nano 2G OSOS/AUPD using the device's real hardware AES
        engine via the patched iBugger Loader/Core (Notes-app exploit).

        This does NOT write iPod NAND/NOR/flash storage. All device-side
        code (Loader, Core, AES driver payload) runs from RAM only.
        """
        ipsw_path = self.ipsw_path
        output_dir = self.output_path

        self.log("=" * 55)
        self.log(f"Model: {self.detected_model} (Category 4 — Nano 2G Hardware AES)")
        self.log(f"Platform: {plat.PLATFORM_NAME}")
        self.log("=" * 55)
        self.log(
            "Using the device's real hardware AES engine via the patched\n"
            "iBugger Loader/Core (Notes-app exploit). The public '0x837' key\n"
            "does not apply to this device and is not used here.\n"
        )
        self.status("Reading Nano 2G partition directory...")
        self.progress(5)

        self.log("[1/4] Extracting firmware from IPSW...")
        try:
            fw_data, fw_name = self._extract_firmware_from_ipsw(ipsw_path)
            if not fw_data:
                self.log("ERROR: No firmware file found!")
                self.status("Failed: No firmware in IPSW")
                return
            self.log(f"  Found: {fw_name}")
            self.log(f"  Size: {len(fw_data):,} bytes")
        except (zipfile.BadZipFile, OSError) as exc:
            self.log(f"ERROR: Cannot read IPSW: {exc}")
            self.status("Failed: Invalid IPSW")
            return

        self.progress(10)
        selected_partitions = self.get_selected_partitions()
        if not selected_partitions:
            self.log("ERROR: No partitions selected!")
            self.status("Failed: No partitions selected")
            return

        unsupported = [name for name in selected_partitions
                       if name not in NANO2G_SUPPORTED_PARTITIONS]
        for name in unsupported:
            self.log(f"NOTE: '{name}' is not present in the validated Nano 2G directory; skipping it.")
        selected_partitions = [name for name in selected_partitions
                               if name in NANO2G_SUPPORTED_PARTITIONS]
        if not selected_partitions:
            self.log("ERROR: None of the selected partitions are supported by Nano 2G.")
            self.status("Failed: Unsupported Nano 2G partitions")
            return

        try:
            partition_ranges = parse_nano2g_partitions(fw_data)
        except ValueError as exc:
            self.log(f"ERROR: Invalid Nano 2G partition directory: {exc}")
            self.status("Failed: Invalid Nano 2G directory")
            return

        self.log("  ✅ Validated ]ih[ marker and DNAN records at 0x4800")
        for name in ("rsrc", "osos", "aupd"):
            part_offset, part_length = partition_ranges[name]
            self.log(f"  {name}: offset 0x{part_offset:x}, size {part_length:,} bytes")
        self.progress(15)

        # RSRC is plaintext; export it directly without touching the device.
        os.makedirs(output_dir, exist_ok=True)

        if "rsrc" in selected_partitions:
            part_offset, part_length = partition_ranges["rsrc"]
            rsrc_data = fw_data[part_offset:part_offset + part_length]
            rsrc_path = os.path.join(output_dir, "rsrc.bin")
            with open(rsrc_path, "wb") as f:
                f.write(rsrc_data)
            self.log(f"  ✅ rsrc: {len(rsrc_data):,} bytes (raw/plaintext, no device needed)")

        device_partitions = [n for n in selected_partitions if n in ("osos", "aupd")]
        if not device_partitions:
            self.progress(100)
            self.log(f"\n{'=' * 55}")
            self.log("✅ RSRC exported (no OSOS/AUPD selected).")
            self.log(f"   Output directory: {output_dir}")
            self.log(f"{'=' * 55}")
            self.status("✅ RSRC export complete (no OSOS/AUPD selected)")
            self.popinfo("Success",
                         f"RSRC exported (no OSOS/AUPD selected).\n\n"
                         f"Model: {self.detected_model}\n"
                         f"Output: {output_dir}")
            return

        self.log("\n[2/4] Connecting to iPod (Loader/Core over USB)...")
        if not plat.IS_WINDOWS:
            ok, detail = plat.check_libusb_loadable()
            if not ok:
                self.log(f"ERROR: {detail}")
                self.status("Failed: libusb unavailable")
                self.poperror("libusb missing", detail)
                return
            self.log("  USB transport: libusb (iBugger FFFF:8642)")
        else:
            self.log("  USB transport: WinUSB (iBugger FFFF:8642)")
        self.status("Connecting to iBugger...")
        self.progress(20)

        try:
            transport = ibugger_transport.connect(log=self.log)
        except nano2g_device.DeviceNotFoundError as exc:
            self.log(f"ERROR: {exc}")
            self.status("Failed: iBugger not found")
            self.poperror("Device Not Found", str(exc))
            return
        except nano2g_device.TransportError as exc:
            self.log(f"ERROR: {exc}")
            self.status("Failed: USB transport error")
            self.poperror("Transport Error", str(exc))
            return

        try:
            if transport.core_type == 1:
                self.log("[3/4] Device is Loader stage; loading Core (RAM only)...")
                self.status("Loading iBugger Core...")
                self.progress(25)
                try:
                    transport.startup_core(
                        nano2g_device.get_logo_bin(), nano2g_device.get_core_bin())
                except nano2g_device.TransportError as exc:
                    self.log(f"ERROR: Failed to load Core: {exc}")
                    self.status("Failed: Could not load Core")
                    self.poperror("Error", f"Failed to load iBugger Core:\n{exc}")
                    return
            elif transport.core_type != 2:
                self.log(f"ERROR: Unexpected iBugger stage core_type={transport.core_type}")
                self.status("Failed: Unexpected device stage")
                return
            else:
                self.log("[3/4] Device is already running Core.")

            self.progress(35)
            payload = nano2g_device.get_decryptfirmware_bin()
            decrypted_partitions = []
            total = len(device_partitions)

            for idx, part_name in enumerate(device_partitions):
                part_offset, part_length = partition_ranges[part_name]
                raw = fw_data[part_offset:part_offset + part_length]
                self.log(
                    f"\n[4/4] Decrypting '{part_name}' via device AES engine "
                    f"({idx + 1}/{total}, {len(raw):,} bytes)..."
                )
                self.status(f"Decrypting {part_name} on device ({idx + 1}/{total})...")
                try:
                    result = transport.run_crypto_payload(payload, raw)
                except (nano2g_device.TransportError, TimeoutError, ValueError) as exc:
                    self.log(f"  ❌ {part_name}: {exc}")
                    self.status(f"Failed: {part_name}")
                    continue

                out_path = os.path.join(output_dir, f"{part_name}.bin")
                with open(out_path, "wb") as f:
                    f.write(result)
                self.log(
                    f"  ✅ {part_name}: {len(result):,} bytes decrypted "
                    f"(sha256={hashlib.sha256(result).hexdigest()[:16]}...)"
                )
                decrypted_partitions.append(part_name)
                self.progress(35 + ((idx + 1) / total) * 55)
        finally:
            transport.close()

        self.progress(95)
        self.log(f"\n{'=' * 55}")
        if decrypted_partitions:
            self.log("✅ SUCCESS! Nano 2G partitions decrypted via device hardware AES.")
            self.log(f"   Output directory: {output_dir}")
            for part_name in decrypted_partitions:
                out_file = os.path.join(output_dir, f"{part_name}.bin")
                size = os.path.getsize(out_file)
                self.log(f"   {part_name}.bin: {size:,} bytes")
            self.log(f"{'=' * 55}")
            self.status("✅ Nano 2G device decrypt complete")
            self.progress(100)
            self.popinfo(
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
                "'Remove loader.htm (restore iPod)' below.")
        else:
            self.log("❌ No partitions were decrypted successfully.")
            self.status("❌ Decrypt failed")

    # ------------------------------------------------------------
    # Category 2: Hardware AES (wInd3x haxdfu + device AES)
    # ------------------------------------------------------------
    def _export_nano5g_rsrc_files(self, rsrc_path, output_dir,
                                  export_rsrc=False, export_silver=False):
        """Export Nano 5G plaintext RSRC content without AES processing."""
        with open(rsrc_path, "rb") as f:
            rsrc_data = f.read()

        exported = []
        if export_rsrc:
            rsrc_output = os.path.join(output_dir, "rsrc.bin")
            with open(rsrc_output, "wb") as f:
                f.write(rsrc_data)
            self.log(f"  ✅ rsrc.bin exported raw/plaintext: {len(rsrc_data):,} bytes")
            exported.append("rsrc")

        if export_silver:
            silver_data = extract_silver_images_db(rsrc_data)
            silver_output = os.path.join(output_dir, "SilverImagesDB.LE.bin")
            with open(silver_output, "wb") as f:
                f.write(silver_data)
            self.log("  ✅ SilverImagesDB.LE.bin exported from "
                     f"Resources/UI: {len(silver_data):,} bytes")
            exported.append("SilverImagesDB.LE.bin")

        return exported

    def _device_aes_supported(self):
        """Can this platform run wInd3x haxdfu/device-AES for the selected
        family? Returns (supported: bool, reason: str)."""
        family = self.detected_family_id
        if not plat.IS_WINDOWS and family in MACOS_LINUX_ONLY_FAMILIES:
            return False, (
                f"Device AES for FamilyID {family} (S5L8720/S5L8730 trampoline) "
                "is only possible on bare-metal Linux per upstream wInd3x — "
                "the host must abort a DFU transfer after exactly 0x40 bytes, "
                "which the macOS USB stack will not do. Use a Raspberry Pi "
                "(or a Windows machine) for this model. Raw/plaintext members "
                "(e.g. Nano 5G RSRC) can still be exported on this platform.")
        return True, ""

    def _decrypt_category2_native(self):
        """Decrypt firmware using wInd3x (native build for this platform).

        Windows: wInd3x-win.exe via WinUSB/libusb.
        macOS:   native darwin build of wInd3x (Go + libusb).
        """
        ipsw_path = self.ipsw_path

        self.log("=" * 55)
        self.log(f"Model: {self.detected_model} (Category 2 — Hardware AES)")
        self.log(f"Platform: {plat.PLATFORM_NAME}")
        self.log("=" * 55)
        self.log("⚠️  This process can take approximately 30 min to 2 hours.\n")

        wind3x = plat.find_wind3x()
        supported, reason = self._device_aes_supported()
        if not supported:
            self.log(f"⚠️  {reason}")
            # fall through: raw/plaintext members below are still exported.
        if not wind3x:
            # Raw/plaintext members can still be exported without wInd3x;
            # only the device-AES step needs it.
            self.log("⚠️  wInd3x binary not found — device-AES members will be "
                     "skipped, raw/plaintext members will still be exported.")
            if plat.IS_MACOS:
                self.log("  See BUILD.md: place a darwin build at vendor/wInd3x-darwin-arm64")

        # Step 1: platform preparation for raw USB access
        self.status("[1/5] Preparing USB access...")
        self.log("[1/5] Preparing raw USB access...")
        if plat.IS_WINDOWS:
            self.log("  Stopping Apple services for direct USB access...")
        plat.prepare_device_access(log=self.log)
        self.progress(2)

        # Step 2: extract OSOS from IPSW
        self.status("[2/5] Extracting firmware from IPSW...")
        self.log("\n[2/5] Extracting firmware from IPSW...")
        self.progress(3)

        try:
            fw_data, fw_name = self._extract_firmware_from_ipsw(ipsw_path)
            if not fw_data:
                self.log("ERROR: No firmware file found!")
                self.status("Failed: No firmware in IPSW")
                return
            self.log(f"  Found: {fw_name}")
            self.log(f"  Size: {len(fw_data):,} bytes")
        except zipfile.BadZipFile:
            self.log("ERROR: Invalid IPSW/ZIP!")
            self.status("Failed: Invalid IPSW")
            return

        # Parse and materialize the selected firmware's actual MSE members.
        try:
            members = parse_mse_members(
                fw_data, nano3_layout=self.detected_family_id in (26, 27))
        except MseFormatError as exc:
            self.log(f"ERROR: Cannot parse MSE member directory: {exc}")
            self.status("Failed: Invalid MSE directory")
            return
        self.category2_members = {member.name: member for member in members}

        selected_partitions = self.get_selected_partitions()
        if not selected_partitions:
            self.log("ERROR: No firmware members selected!")
            self.status("Failed: No firmware members selected")
            return
        unknown_members = [
            name for name in selected_partitions
            if name != "silverimagesdb" and name not in self.category2_members
        ]
        if unknown_members:
            self.log(f"ERROR: Unknown MSE members selected: {', '.join(unknown_members)}")
            self.status("Failed: Invalid member selection")
            return

        # SilverImagesDB is inside Nano 5G RSRC, so selecting it implicitly
        # materializes rsrc without requiring the raw rsrc checkbox.
        is_nano5g = self.detected_family_id == 34
        selected_mse_partitions = [
            name for name in selected_partitions if name != "silverimagesdb"
        ]
        if is_nano5g and "silverimagesdb" in selected_partitions and "rsrc" not in selected_mse_partitions:
            selected_mse_partitions.append("rsrc")

        temp_mse_dir = tempfile.mkdtemp(prefix="ipod_mse_")
        available_partitions = []
        try:
            for part_name in selected_mse_partitions:
                member = self.category2_members[part_name]
                part_path = os.path.join(temp_mse_dir, part_name)
                with open(part_path, "wb") as member_file:
                    member_file.write(
                        fw_data[member.logical_offset:member.logical_offset + member.logical_length])
                available_partitions.append(part_name)
        except OSError as exc:
            self.log(f"ERROR: Could not materialize MSE members: {exc}")
            self.status("Failed: MSE member extraction")
            shutil.rmtree(temp_mse_dir, ignore_errors=True)
            return

        self.log(f"  ✅ Actual MSE members selected: {', '.join(available_partitions)}")
        for part_name in available_partitions:
            member = self.category2_members[part_name]
            self.log(f"     {part_name}: {member.logical_length:,} bytes ({member.detail})")
        self.progress(8)

        output_dir = self.output_path
        os.makedirs(output_dir, exist_ok=True)
        exported_partitions = []

        # Nano 5G RSRC is format-4/plaintext and contains a FAT16 volume.
        # Never send it through the hardware AES command.
        if is_nano5g and "rsrc" in available_partitions:
            try:
                exported_partitions.extend(self._export_nano5g_rsrc_files(
                    os.path.join(temp_mse_dir, "rsrc"),
                    output_dir,
                    export_rsrc=("rsrc" in selected_partitions),
                    export_silver=("silverimagesdb" in selected_partitions),
                ))
            except (OSError, Nano5GResourceError) as exc:
                self.log(f"  ❌ Nano 5G RSRC/SilverImagesDB export failed: {exc}")
                self.status("Failed: Nano 5G resource export")
                shutil.rmtree(temp_mse_dir, ignore_errors=True)
                return

        # Raw/plaintext MSE members are copied byte-for-byte. Only validated
        # encrypted IMG1 members are sent to DFU/device AES.
        raw_partitions = [
            name for name in available_partitions
            if not self.category2_members[name].is_encrypted
        ]
        for part_name in raw_partitions:
            if is_nano5g and part_name == "rsrc":
                continue
            source_path = os.path.join(temp_mse_dir, part_name)
            target_path = os.path.join(output_dir, f"{part_name}.bin")
            try:
                shutil.copyfile(source_path, target_path)
            except OSError as exc:
                self.log(f"  ❌ Could not export raw {part_name}: {exc}")
                self.status(f"Failed: {part_name} export")
                shutil.rmtree(temp_mse_dir, ignore_errors=True)
                return
            size = os.path.getsize(target_path)
            self.log(f"  ✅ {part_name}.bin exported raw/plaintext: {size:,} bytes")
            exported_partitions.append(part_name)

        device_partitions = [
            name for name in available_partitions
            if self.category2_members[name].is_encrypted
        ]

        # Step 3: haxdfu (BootROM exploit) — only when encrypted data
        # remains to be processed. Plaintext-only exports need no device.
        if device_partitions and supported and not wind3x:
            for part_name in device_partitions:
                self.log(f"  ⏭️  {part_name}: skipped (wInd3x binary missing)")
            self.log("ERROR: wInd3x binary required for device-AES decryption "
                     "was not found. See BUILD.md.")
            self.status("Failed: wInd3x missing")
            self.poperror("wInd3x missing",
                          "The wInd3x binary is required for device-AES decryption "
                          "and was not found. Raw/plaintext members (if any) were "
                          "still exported. See BUILD.md (macOS/Windows sections).")
            shutil.rmtree(temp_mse_dir, ignore_errors=True)
            return

        if device_partitions and supported:
            self.status("[3/5] Running BootROM exploit (haxdfu)...")
            self.log("\n[3/5] Running haxdfu (native)...")
            self.log(f"  wInd3x binary: {wind3x}")
            self.progress(10)

            ok, out, err = plat.run_wind3x(["haxdfu", "-v"], timeout=60)
            combined = (out + "\n" + err).strip()
            self.log(f"  {(combined[:400]) or '(no output)'}")

            if "Haxed DFU" in combined or "already" in combined.lower() or "triggered" in combined.lower():
                self.log("  ✅ Exploit successful!")
            else:
                self.log("  ⚠️ Exploit result uncertain, attempting decrypt anyway...")
                if "no device found" in combined.lower() or "could not open" in combined.lower():
                    if plat.IS_MACOS:
                        self.log("  Hint (macOS): if Apple software is holding the DFU "
                                 "device, use the 'Release Apple USB service' button in "
                                 "the Prerequisites panel and retry.")
            self.progress(15)
        elif device_partitions and not supported:
            skipped = ", ".join(device_partitions)
            self.log(f"\n[3/5] Skipping haxdfu/device AES — not supported on "
                     f"{plat.PLATFORM_NAME} for this model ({skipped} skipped).")
        else:
            self.log("\nNo encrypted partitions selected; skipped haxdfu/device AES.")
            self.progress(85)

        # Step 4/5: decrypt encrypted IMG1 members via hardware AES
        total_partitions = len(device_partitions)
        for part_idx, part_name in enumerate(device_partitions):
            if not supported:
                self.log(f"  ⏭️  {part_name}: skipped (device AES not available on this platform)")
                continue
            part_path = os.path.join(temp_mse_dir, part_name)
            output_file = os.path.join(output_dir, f"{part_name}.bin")
            recovery_path = output_file + RECOVERY_SUFFIX
            progress_path = output_file + PROGRESS_SUFFIX

            self.log(f"\n[5/5] Decrypting partition '{part_name}' ({part_idx + 1}/{total_partitions})...")
            self.status(f"Decrypting {part_name} ({part_idx + 1}/{total_partitions})...")

            # Check resume state for this partition
            resume_percent = 0
            if os.path.exists(progress_path):
                try:
                    with open(progress_path, "r") as f:
                        state = json.load(f)
                    resume_percent = state.get("percent", 0)
                    if resume_percent > 0 and os.path.exists(recovery_path):
                        self.log(f"  📂 Resuming {part_name} from {resume_percent:.1f}% "
                                 f"(recovery buffer present)")
                    else:
                        resume_percent = 0
                except (json.JSONDecodeError, KeyError, OSError):
                    resume_percent = 0

            self.log("  ⏱️  Do NOT disconnect the iPod.")

            decrypt_args = ["decrypt", part_path, output_file, "-v", "-r", recovery_path]
            env = plat.child_env_for_wind3x(wind3x)
            try:
                proc = subprocess.Popen(
                    [wind3x] + decrypt_args,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                    cwd=os.path.dirname(wind3x),
                    env=env,
                    **plat.hidden_subprocess_kwargs(),
                )
            except OSError as exc:
                self.log(f"ERROR: could not start wInd3x decrypt: {exc}")
                self.status(f"Failed: {part_name}")
                shutil.rmtree(temp_mse_dir, ignore_errors=True)
                return

            last_percent = resume_percent
            retry_count = 0
            progress_base = 15 + (part_idx / max(total_partitions, 1)) * 80
            progress_span = 80 / max(total_partitions, 1)

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                if "percent=" in line:
                    try:
                        pct = float(line.split("percent=")[1].split()[0].rstrip("%,"))
                        if pct > last_percent:
                            last_percent = pct
                            self.progress(progress_base + (pct / 100.0) * progress_span)
                            self.status(
                                f"Decrypting {part_name} ({part_idx + 1}/{total_partitions}): {pct:.1f}%")
                            if int(pct) > int(last_percent - 1):
                                self._save_progress(progress_path, pct)
                    except (ValueError, IndexError):
                        pass
                elif "timeout" in line.lower() or "retry" in line.lower():
                    retry_count += 1
                    if retry_count <= 5:
                        self.log(f"  ↻ USB retry #{retry_count} (normal)")
                    elif retry_count % 10 == 0:
                        self.log(f"  ↻ USB retries: {retry_count}")
                elif "error" in line.lower() and "timeout" not in line.lower():
                    self.log(f"  ⚠️ {line}")
                elif "done" in line.lower() or "complete" in line.lower():
                    self.log(f"  ✅ {line}")
                    break
                elif "decrypt" in line.lower() or "progress" in line.lower():
                    self.log(f"  {line}")

            proc.wait()

            # Verify partition output (wInd3x re-wraps the plaintext body in a
            # header-padded unsigned IMG1 container).
            if os.path.exists(output_file) and os.path.getsize(output_file) > 1000:
                size = os.path.getsize(output_file)
                self.log(f"  ✅ {part_name} decrypted: {size:,} bytes")
                exported_partitions.append(part_name)
                self._cleanup_recovery(recovery_path, progress_path)
            else:
                self.log(f"  ❌ {part_name} output incomplete at {last_percent:.1f}%")
                self._save_progress(progress_path, last_percent)

        self.progress(95)

        # Final summary
        self.log(f"\n{'=' * 55}")
        self.log(f"✅ Decryption/export complete ({plat.PLATFORM_NAME}).")
        self.log(f"   Output directory: {output_dir}")
        for part_name in exported_partitions:
            out_file = os.path.join(
                output_dir,
                part_name if part_name == "SilverImagesDB.LE.bin" else f"{part_name}.bin",
            )
            if os.path.exists(out_file):
                size = os.path.getsize(out_file)
                self.log(f"   {os.path.basename(out_file)}: {size:,} bytes ({size / 1024 / 1024:.1f} MB)")
        self.log(f"{'=' * 55}")
        self.status("✅ Decryption/export complete!")
        self.progress(100)
        self.popinfo("Success",
                     f"Firmware decrypted/exported!\n\n"
                     f"Model: {self.detected_model}\n"
                     f"Outputs: {', '.join(exported_partitions) or '(none)'}\n"
                     f"Output directory: {output_dir}")

        # Cleanup temporary materialized MSE members.
        shutil.rmtree(temp_mse_dir, ignore_errors=True)

        # Restore platform device access
        plat.restore_device_access(log=self.log)
        if plat.IS_MACOS:
            state_file = os.path.join(
                plat.temp_dir(), "ipod_decrypt_apple_services.json")
            for line in plat.restore_apple_usb_services(state_file):
                self.log(f"  {line}")

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------
    def _save_progress(self, progress_path, percent):
        try:
            state = {
                "percent": percent,
                "timestamp": time.time(),
                "model": self.detected_model,
                "ipsw": self.ipsw_path,
            }
            with open(progress_path, "w") as f:
                json.dump(state, f)
        except OSError:
            pass

    def _cleanup_recovery(self, recovery_path, progress_path):
        for path in (recovery_path, progress_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass


# ============================================================
# GUI backend (Tkinter)
# ============================================================
def run_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog
    except Exception as exc:  # noqa: BLE001
        print(
            "Tkinter is not available in this Python.\n"
            "  * macOS: use a python.org Python or `brew install python-tk`,\n"
            "    or run the CLI:  python3 ipod_universal_decrypt_b.py --cli\n"
            f"  (detail: {exc})"
        )
        return 1

    global APP  # noqa: PLW0603
    APP = UniversalDecryptorApp(tk, ttk, messagebox, filedialog)
    APP.run()
    return 0


class UniversalDecryptorApp(DecryptController):
    """Tkinter GUI (Windows, macOS, Linux)."""

    def __init__(self, tk, ttk, messagebox, filedialog):
        super().__init__(run_sync=False)
        self.tk = tk
        self.ttk = ttk
        self.messagebox = messagebox
        self.filedialog = filedialog

        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("820x500")
        self.root.resizable(True, True)
        self.root.minsize(700, 300)

        if plat.IS_WINDOWS:
            icon_path = plat.get_bundled_path("icon.ico")
            if icon_path:
                try:
                    self.root.iconbitmap(icon_path)
                except Exception:  # noqa: BLE001
                    pass

        self._status_text = "Ready — select an IPSW to begin"

        self._build_ui()
        self._autosize_window()
        self.root.after(60, self._pump)

    # ------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------
    def _build_ui(self):
        tk = self.tk
        ttk = self.ttk

        # Footer: always pinned to the bottom of the window
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
                  font=(UI_FONT, 8), foreground="gray").pack(side="left")

        # Scrollable content area above the pinned footer
        content_host = ttk.Frame(self.root)
        content_host.pack(side="top", fill="both", expand=True)
        self.content_canvas = tk.Canvas(content_host, highlightthickness=0)
        self.content_scrollbar = ttk.Scrollbar(
            content_host, orient="vertical", command=self.content_canvas.yview)
        self.content_canvas.configure(yscrollcommand=self.content_scrollbar.set)
        self.content_canvas.pack(side="left", fill="both", expand=True)
        self.content_scrollbar.pack(side="right", fill="y")

        main_frame = ttk.Frame(self.content_canvas, padding=(10, 10, 10, 0))
        self.main_frame = main_frame
        self._content_window = self.content_canvas.create_window(
            (0, 0), window=main_frame, anchor="nw")

        def update_scrollregion(_event=None):
            self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))

        def fit_content_width(event):
            self.content_canvas.itemconfigure(self._content_window, width=event.width)
            update_scrollregion()

        main_frame.bind("<Configure>", update_scrollregion)
        self.content_canvas.bind("<Configure>", fit_content_width)

        # Title
        self.title_frame = ttk.Frame(main_frame)
        self.title_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(self.title_frame, text=APP_NAME,
                  font=(UI_FONT, 14, "bold")).pack(anchor="w")
        if plat.IS_WINDOWS:
            subtitle = f"v{APP_VERSION} — Native Windows (no WSL required)"
        elif plat.IS_MACOS:
            arch = "Apple Silicon" if plat.IS_ARM64 else "Intel"
            subtitle = f"v{APP_VERSION} — Native macOS ({arch})"
        else:
            subtitle = f"v{APP_VERSION} — Linux (development/testing)"
        ttk.Label(self.title_frame, text=subtitle,
                  font=(UI_FONT, 9)).pack(anchor="w")

        # IPSW selection
        ipsw_frame = ttk.LabelFrame(main_frame, text="Firmware Source", padding=8)
        self.ipsw_frame = ipsw_frame
        ipsw_frame.pack(fill="x", pady=(0, 5))

        ipsw_row = ttk.Frame(ipsw_frame)
        ipsw_row.pack(fill="x")
        ttk.Label(ipsw_row, text="IPSW:").pack(side="left")
        self.ipsw_var = tk.StringVar(value="")
        self.ipsw_entry = ttk.Entry(ipsw_row, textvariable=self.ipsw_var, width=55)
        self.ipsw_entry.pack(side="left", padx=5, expand=True, fill="x")
        ttk.Button(ipsw_row, text="Browse...", command=self._browse_ipsw).pack(side="right")

        # Detected model row
        model_row = ttk.Frame(ipsw_frame)
        model_row.pack(fill="x", pady=(5, 0))
        ttk.Label(model_row, text="Detected:").pack(side="left")
        self.model_label = ttk.Label(model_row, text="(select an IPSW file)",
                                     font=(UI_FONT, 9, "italic"),
                                     foreground="gray")
        self.model_label.pack(side="left", padx=5)
        self.mode_label = ttk.Label(model_row, text="",
                                    font=(UI_FONT, 9, "bold"))
        self.mode_label.pack(side="right")

        # Prerequisites frame (shown for Category 2 / 4)
        self.prereq_frame = ttk.LabelFrame(
            main_frame, text="Prerequisites (Hardware Decrypt)", padding=8)
        self.wind3x_label = ttk.Label(self.prereq_frame, text="⏳ wInd3x: Not checked")
        self.wind3x_label.pack(anchor="w")
        self.libusb_label = ttk.Label(self.prereq_frame, text="")
        self.driver_status_label = ttk.Label(
            self.prereq_frame, text="⏳ USB access: Not checked")
        self.driver_status_label.pack(anchor="w")
        # macOS-only: Apple service release/restore buttons
        self.svc_btn_row = ttk.Frame(self.prereq_frame)
        ttk.Button(self.svc_btn_row, text="🔓 Release Apple USB service (admin)",
                   command=self._release_apple_services).pack(side="left", padx=(0, 5))
        ttk.Button(self.svc_btn_row, text="♻️ Restore Apple USB service",
                   command=self._restore_apple_services).pack(side="left")

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

        # Driver install/remove buttons (Windows only)
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
        self.nano2g_device_info_label = ttk.Label(self.nano2g_device_frame, text="")

        # Partition selection
        self.partition_frame = ttk.LabelFrame(main_frame, text="Firmware Members", padding=8)
        self.partition_checks_frame = ttk.Frame(self.partition_frame)
        self.partition_checks_frame.pack(fill="x")
        self.partition_hint_label = ttk.Label(
            self.partition_frame,
            text="Select an IPSW to read its actual firmware members.",
            foreground="gray",
        )
        self.partition_hint_label.pack(anchor="w", pady=(3, 0))

        self.silverimagesdb_enabled = True
        self.silverimagesdb_var = tk.BooleanVar(value=True)
        self.silverimagesdb_var.trace_add("write", lambda *_a: setattr(
            self, "silverimagesdb_enabled", bool(self.silverimagesdb_var.get())))
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
        self.output_var = tk.StringVar(
            value=os.path.join(plat.default_desktop(), "osos_decrypted.bin"))
        self.out_entry = ttk.Entry(out_row, textvariable=self.output_var, width=55)
        self.out_entry.pack(side="left", padx=5, expand=True, fill="x")
        ttk.Button(out_row, text="Browse...", command=self._browse_output).pack(side="right")

        # Progress
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding=8)
        self.progress_frame = progress_frame
        progress_frame.pack(fill="x", pady=(0, 5))

        self.progress_bar = ttk.Progressbar(progress_frame, mode="determinate", length=400)
        self.progress_bar.pack(fill="x")
        self.status_label = ttk.Label(progress_frame, text=self._status_text,
                                      font=(UI_FONT, 9))
        self.status_label.pack(anchor="w", pady=(4, 0))

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=5)
        self.log_frame = log_frame
        log_frame.pack(fill="x", pady=(0, 8))

        log_inner = ttk.Frame(log_frame)
        log_inner.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_inner, height=5, font=(MONO_FONT, 8),
                                wrap="word", state="normal")
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(log_inner, orient="vertical",
                                  command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # IPSW path changes
        self.ipsw_var.trace_add("write", self._on_ipsw_changed)

        self._repack_ui(show_hardware=False, show_partitions=False)

    # ------------------------------------------------------------
    # Controller virtual surface (UI thread)
    # ------------------------------------------------------------
    def log(self, msg):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.root.update_idletasks()

    def status(self, msg):
        self._status_text = msg
        self.status_label.config(text=msg)
        self.root.update_idletasks()

    def progress(self, value):
        self.progress_bar["value"] = float(value)
        self.root.update_idletasks()

    def set_partition_options(self, options, hint=""):
        self.partition_options = list(options)
        self._rebuild_partition_checks(options)
        if hint:
            self.partition_hint_label.config(text=hint, foreground="gray")

    def _rebuild_partition_checks(self, options):
        for child in self.partition_checks_frame.winfo_children():
            child.destroy()
        if not options:
            return
        previous = dict(self.partition_selected)

        def make_sync(name):
            def _sync(_event, var):
                self.partition_selected[name] = bool(var.get())
            return _sync

        for index, (name, label) in enumerate(options):
            row, column = divmod(index, 3)
            cell = self.ttk.Frame(self.partition_checks_frame)
            cell.grid(row=row, column=column, sticky="w", padx=(0, 14), pady=2)
            var = self.tk.BooleanVar(value=previous.get(name, True))
            self.partition_selected[name] = bool(var.get())
            var.trace_add("write", make_sync(name))
            self.ttk.Checkbutton(cell, text=name, variable=var).pack(side="left")
            self.ttk.Label(cell, text=label, foreground="gray").pack(
                side="left", padx=(4, 0))
        for column in range(3):
            self.partition_checks_frame.columnconfigure(column, weight=1)

    def apply_members(self, token, ipsw_path, family_id, members, error):
        """Member discovery result — UI thread."""
        if token != self._members_token or ipsw_path != self.ipsw_path:
            return
        super().apply_members(token, ipsw_path, family_id, members, error)
        self.model_state()
        self.mode_state()
        self._repack_ui(
            show_hardware=True,
            show_partitions=True,
            show_silverimagesdb=(family_id == 34 and "rsrc" in self.category2_members),
        )
        if plat.IS_WINDOWS:
            self.driver_frame.pack(fill="x", pady=(5, 0))
        self._check_prerequisites()
        self._autosize_window()

    def model_state(self):
        """Repaint model/mode labels (UI thread)."""
        if not self.ipsw_path:
            self.model_label.config(text="(select an IPSW file)",
                                    foreground="gray",
                                    font=(UI_FONT, 9, "italic"))
            self.mode_label.config(text="")
            self._repack_ui(show_hardware=False, show_partitions=False)
            return

        family_id = self.detected_family_id
        if family_id is None:
            self.model_label.config(
                text="⚠️ Could not detect model from filename",
                foreground="orange", font=(UI_FONT, 9, "bold"))
            self.mode_label.config(text="")
            self._repack_ui(show_hardware=False, show_partitions=False)
            return

        self.model_label.config(
            text=f"📱 {self.detected_model} (FamilyID {family_id})",
            foreground="black", font=(UI_FONT, 9, "bold"))
        category = self.detected_category
        if category == 1:
            self.mode_label.config(text="✅ No device needed (unencrypted)",
                                   foreground="green")
            self._repack_ui(show_hardware=False, show_partitions=False)
        elif category == 3:
            self.mode_label.config(text="🔑 Software decrypt (no device needed)",
                                   foreground="green")
            self._repack_ui(show_hardware=False, show_partitions=True)
        elif category == 4:
            transport_note = "WinUSB" if plat.IS_WINDOWS else "libusb"
            self.mode_label.config(
                text=f"🔐 Hardware AES via Notes exploit (device required, {transport_note})",
                foreground="blue")
            self._repack_ui(show_hardware=False, show_partitions=True, show_nano2g=True)
        elif category == 2:
            self._repack_ui(
                show_hardware=True,
                show_partitions=True,
                show_silverimagesdb=False,
            )
            self._autosize_window()
        else:
            self.mode_label.config(text="❓ Unknown category", foreground="red")
            self._repack_ui(show_hardware=False, show_partitions=False)

    def mode_state(self):
        """Update the mode label (Category 2 details)."""
        family_id = self.detected_family_id
        category = self.detected_category
        if category == 2 and family_id is not None:
            if family_id in UNSUPPORTED_CATEGORY2_FAMILIES:
                self.mode_label.config(
                    text="⚠️ Hardware AES decrypt not supported for this model",
                    foreground="orange")
            elif not plat.IS_WINDOWS and family_id in MACOS_LINUX_ONLY_FAMILIES:
                self.mode_label.config(
                    text="⚠️ Device AES is Linux-only for this model (raw export still works)",
                    foreground="orange")
            elif family_id == 38:
                self.mode_label.config(
                    text="🔐 Hardware AES (device required; stock wInd3x may not know PID 1250)",
                    foreground="blue")
            else:
                self.mode_label.config(text="🔐 Hardware AES (device required)",
                                       foreground="blue")

    def show_dialog(self, kind, title, message):
        if kind == "info":
            self.messagebox.showinfo(title, message)
        elif kind == "error":
            self.messagebox.showerror(title, message)
        else:
            self.messagebox.showwarning(title, message)

    def confirm(self, title, message):
        return self.messagebox.askokcancel(title, message)

    def nano2g_stage_status(self, text):
        self.nano2g_status_label.config(text=text)
        self._autosize_window()

    # ------------------------------------------------------------
    # UI thread queue pump
    # ------------------------------------------------------------
    def _dispatch_ui_event(self, kind, args):
        if kind == "dialog":
            self.show_dialog(args[0], args[1], args[2])
        elif kind == "running":
            self.decrypt_btn.config(state="disabled" if args[0] else "normal")
            if not args[0]:
                self._autosize_window()
        elif kind == "nano2g_info":
            self._nano2g_set_device_info(args[0])
        elif kind == "device_found":
            self.device_label.config(text=f"✅ Found: {args[0]} (PID 0x{args[1]})")
            self.log(f"Device found: {args[0]} (PID 0x{args[1]})")
            self._autosize_window()
        elif kind == "device_missing":
            self.device_label.config(
                text="❌ No iPod in DFU mode found. Hold Menu+Center "
                     "until screen stays black.")
            self.log("No iPod DFU device detected.")
            self._autosize_window()
        elif kind == "prereq_wind3x":
            self.wind3x_label.config(text=args[0])
            self._autosize_window()
        elif kind == "prereq_usb":
            self.driver_status_label.config(text=args[0])
            self._autosize_window()
        elif kind == "prereq_libusb":
            self.libusb_label.config(text=args[0])
            self._autosize_window()
        elif kind == "autosize":
            self._autosize_window()
        else:
            super()._dispatch_ui_event(kind, args)

    def _pump(self):
        try:
            while True:
                kind, args = self._ui_queue.get_nowait()
                self._dispatch_ui_event(kind, args)
        except queue.Empty:
            pass
        except self.tk.TclError:
            return  # window closing
        except Exception:  # noqa: BLE001
            import traceback
            traceback.print_exc()
        try:
            if self.root.winfo_exists():
                self.root.after(60, self._pump)
        except Exception:  # noqa: BLE001
            pass

    # ============================================================
    # UI helpers
    # ============================================================
    def _nano2g_set_device_info(self, text):
        self.nano2g_device_info_label.config(text=text)
        if text:
            if not self.nano2g_device_info_label.winfo_ismapped():
                self.nano2g_device_info_label.pack(anchor="w", pady=(3, 0))
        else:
            self.nano2g_device_info_label.pack_forget()

    def _copy_log(self):
        text = self.log_text.get("1.0", "end").strip()
        text = text.replace("\x00", "")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        try:
            log_path = os.path.join(
                os.path.dirname(os.path.abspath(sys.argv[0])), "decrypt_log.txt")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(text)
            self.status("Log copied + saved to decrypt_log.txt")
        except Exception:  # noqa: BLE001
            self.status("Log copied to clipboard")

    def _repack_ui(self, show_hardware=False, show_partitions=False,
                   show_nano2g=False, show_silverimagesdb=False):
        """Repack all main frame children in correct order."""
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

        # Platform-specific extras inside the prerequisites frame
        if plat.IS_MACOS:
            self.libusb_label.pack(anchor="w", before=self.driver_status_label)
            self.svc_btn_row.pack(fill="x", pady=(3, 0))
            self.driver_frame.pack_forget()
        else:
            self.libusb_label.pack_forget()
            self.svc_btn_row.pack_forget()

        self._autosize_window()

    def _autosize_window(self):
        """Resize the window height to fit exactly what's currently visible."""
        try:
            self.root.update_idletasks()
            content_width = self.main_frame.winfo_reqwidth()
            content_height = self.main_frame.winfo_reqheight()
            footer_height = self.btn_frame.winfo_reqheight()
            scrollbar_width = self.content_scrollbar.winfo_reqwidth()

            screen_height = self.root.winfo_screenheight()
            max_height = int(screen_height * 0.9)
            width = max(820, content_width + scrollbar_width)
            height = max(460, min(content_height + footer_height + 8, max_height))

            self.root.geometry(f"{width}x{height}")
            self.root.update_idletasks()
            self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))
        except Exception:  # noqa: BLE001
            pass

    def _on_ipsw_changed(self, *args):
        """Called when the IPSW path entry changes."""
        path = self.ipsw_var.get()
        self.output_path = self.output_var.get()  # keep controller in sync
        self.on_ipsw_changed(path)
        # Sync the default output suggestion back into the entry widget.
        if path and self.output_path and self.output_path != self.output_var.get():
            self.output_var.set(self.output_path)

    def _browse_ipsw(self):
        path = self.filedialog.askopenfilename(
            title="Select iPod IPSW Firmware",
            filetypes=[("IPSW files", "*.ipsw"), ("All files", "*.*")])
        if path:
            self.ipsw_var.set(path)

    def _browse_output(self):
        if self.detected_category in (2, 3, 4):
            path = self.filedialog.askdirectory(title="Select Output Directory")
        else:
            path = self.filedialog.asksaveasfilename(
                title="Save Decrypted OSOS As",
                defaultextension=".bin",
                filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if path:
            self.output_var.set(path)
            self.output_path = path

    def _start_decrypt(self):
        self.output_path = self.output_var.get()
        super().start_decrypt()

    def _check_prerequisites(self):
        """Check wInd3x binary + USB prerequisites for this platform."""
        def check():
            wind3x = plat.find_wind3x()
            if wind3x:
                text = f"✅ wInd3x: {os.path.basename(wind3x)}"
                self.ui_emit("log", f"Prerequisites: wInd3x found: {os.path.basename(wind3x)}")
            else:
                text = "❌ wInd3x: not found (needed for device-AES decrypt)"
            self.ui_emit("prereq_wind3x", text)
            if not wind3x:
                return

            if plat.IS_WINDOWS:
                pid = None
                if self.detected_family_id in IPOD_MODELS:
                    _, _, _, pid = IPOD_MODELS[self.detected_family_id]
                if pid and plat.check_winusb_installed(pid):
                    text = f"✅ WinUSB Driver: Installed for PID {pid}"
                elif pid:
                    text = f"⚠️ WinUSB Driver: Not detected for PID {pid} (use Zadig below)"
                else:
                    text = "⏳ WinUSB Driver: No PID to check"
                self.ui_emit("prereq_usb", text)
            else:
                ok, detail = plat.check_libusb_loadable()
                text = f"✅ {detail}" if ok else f"⚠️ {detail}"
                self.ui_emit("prereq_usb", text)
                if self.detected_category == 4:
                    libtext = f"✅ libusb (iBugger): {detail}" if ok \
                        else f"❌ libusb (iBugger): {detail}"
                    self.ui_emit("prereq_libusb", libtext)
            self.ui_emit("autosize", "")

        threading.Thread(target=check, daemon=True).start()

    # ------------------------------------------------------------
    # Platform-specific actions
    # ------------------------------------------------------------
    def _install_driver(self):
        self.log("Launching Zadig for WinUSB driver installation...")
        self.log("  In Zadig: select the iPod device, choose WinUSB, click Install.")
        zadig_path = plat.get_bundled_path(ZADIG_NAME)
        if not zadig_path:
            self.log("  ERROR: Zadig not found in bundle")
            self.poperror("Error", "Zadig not found in bundle.")
            return
        try:
            subprocess.Popen([zadig_path], **plat.hidden_subprocess_kwargs())
        except Exception as exc:  # noqa: BLE001
            self.log(f"  ERROR: {exc}")
            self.poperror("Error", f"Cannot launch Zadig:\n{exc}")

    def _remove_driver(self):
        if not self.detected_category:
            self.popinfo("Info", "Select an IPSW first to detect the device.")
            return
        pid = None
        if self.detected_family_id in IPOD_MODELS:
            _, _, _, pid = IPOD_MODELS[self.detected_family_id]
        if not pid:
            self.popinfo("Info", "No DFU PID known for this model.")
            return
        self.log(f"Removing WinUSB driver for PID {pid}...")
        if plat.remove_winusb_driver(pid):
            self.log("  ✅ Driver removed. Original Apple driver will load on next plug.")
            self.popinfo("Done",
                         "WinUSB driver removed.\n"
                         "Reconnect the iPod for the Apple driver to reload.")
        else:
            self.log("  No libwdi/Zadig driver found for this PID "
                     "(may already be removed).")

    def _release_apple_services(self):
        if not plat.IS_MACOS:
            return
        self.popwarning(
            "Release Apple USB service",
            "This stops Apple's DFU/iPod-related system services so raw USB "
            "tools can open the device interface.\n\n"
            "A macOS admin-password dialog will appear.\n\n"
            "Use 'Restore Apple USB service' (or reboot) to bring them back.")
        def do_release():
            state_file = os.path.join(
                plat.temp_dir(), "ipod_decrypt_apple_services.json")
            for line in plat.release_apple_usb_services(state_file):
                self.ui_emit("log", line)
            self.ui_emit("log", "Apple USB service release step complete.")
            self.ui_emit("status", "Apple USB services released (if any were active)")
        threading.Thread(target=do_release, daemon=True).start()

    def _restore_apple_services(self):
        if not plat.IS_MACOS:
            return
        def do_restore():
            state_file = os.path.join(
                plat.temp_dir(), "ipod_decrypt_apple_services.json")
            lines = plat.restore_apple_usb_services(state_file)
            for line in lines:
                self.ui_emit("log", line)
            if not lines:
                self.ui_emit("log", "No released services recorded; nothing to restore.")
            self.ui_emit("status", "Apple USB service restore step complete")
        threading.Thread(target=do_restore, daemon=True).start()

    def _scan_device(self):
        """Scan for an iPod in DFU mode via native USB enumeration."""
        self.device_label.config(text="🔍 Scanning...")
        self._autosize_window()

        def do_scan():
            expected_pid = None
            if self.detected_family_id in IPOD_MODELS:
                _, _, _, expected_pid = IPOD_MODELS[self.detected_family_id]
            pids = [p for p in DFU_PIDS if p != expected_pid]
            if expected_pid:
                pids = [expected_pid] + pids
            found_pid = None
            try:
                found_pid = plat.scan_dfu_pids(pids)
            except Exception:  # noqa: BLE001
                pass

            if found_pid:
                display_name = (self.detected_model or
                                DFU_PID_MODELS.get(
                                    found_pid, f"Unknown (PID 0x{found_pid})"))
                self.ui_emit("device_found", display_name, found_pid)
            else:
                ibugger_found, ibugger_detail = plat.find_ibugger_device()
                if ibugger_found:
                    self.ui_emit("device_found", "Unified iBugger (iPod Nano 2G)", "8642")
                    self.ui_emit("log", f"  {ibugger_detail}")
                else:
                    self.ui_emit("device_missing", "")
        threading.Thread(target=do_scan, daemon=True).start()

    def run(self):
        self.root.mainloop()


# ============================================================
# CLI backend (headless)
# ============================================================
class UniversalDecryptorCLI(DecryptController):
    """Headless console backend. Runs decrypt inline (no worker threads)."""

    def __init__(self, args):
        super().__init__(run_sync=True)
        self.args = args
        self._last_progress = -1.0
        self._failed = False

    # ----- UI surface -----
    def log(self, msg):
        print(msg, flush=True)

    def status(self, msg):
        print(f"  status: {msg}", flush=True)

    def progress(self, value):
        value = float(value)
        if int(value) != int(self._last_progress):
            bar_len = 30
            filled = int(bar_len * value / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"\r  progress: [{bar}] {value:5.1f}%", end="", flush=True)
        self._last_progress = value
        if value >= 100:
            print()

    def set_partition_options(self, options, hint=""):
        super().set_partition_options(options, hint)
        if hint:
            print(f"  members: {hint}")
        for name, label in options:
            sel = self.partition_selected.get(name, True)
            print(f"    [{'x' if sel else ' '}] {name}: {label}")
        if self.args.partitions:
            wanted = [p.strip() for p in self.args.partitions.split(",")
                      if p.strip()]
            for name in self.partition_selected:
                self.partition_selected[name] = name in wanted
            self.silverimagesdb_enabled = "silverimagesdb" in wanted
        else:
            self.silverimagesdb_enabled = True

    def show_dialog(self, kind, title, message):
        mark = {"info": "==", "error": "!! ERROR", "warning": "!! WARNING"}[kind]
        print(f"\n{mark} {title}\n{message}\n")
        if kind == "error":
            self._failed = True

    def confirm(self, title, message):
        if self.args.yes:
            return True
        try:
            answer = input(f"\n{title}: {message}\nContinue? [y/N] ").strip().lower()
            return answer in ("y", "yes")
        except EOFError:
            return True

    def model_state(self):
        if not self.ipsw_path:
            print("(no IPSW selected)")
            return
        if self.detected_family_id is None:
            print("⚠️  Could not detect model from filename")
            return
        print(f"  model: {self.detected_model} (FamilyID {self.detected_family_id}, "
              f"category {self.detected_category})")

    def mode_state(self):
        if self.detected_category == 2 and self.detected_family_id:
            supported, reason = self._device_aes_supported()
            if not supported:
                print(f"  ⚠️  device AES unavailable on {plat.PLATFORM_NAME}: {reason}")

    def nano2g_stage_status(self, text):
        print(f"  nano2g: {text}")

    # ----- run -----
    def run(self):
        print(f"{APP_NAME} v{APP_VERSION} (build {APP_BUILD}) — CLI mode")
        print(f"  platform: {plat.PLATFORM_NAME} ({plat.MACHINE})\n")

        self.on_ipsw_changed(self.args.ipsw)
        if self.detected_category is None:
            self.poperror("Error", "Could not detect iPod model from the IPSW filename.\n"
                                   "Expected format: iPod_XX.X.X.X.ipsw or "
                                   "iPod_X.X.X_XXYZZZZZ.ipsw")
            return 2

        self.output_path = self.args.output or self.output_path
        if not self.output_path:
            self.poperror("Error", "No output path given and none could be inferred.")
            return 2

        selected = self.get_selected_partitions()
        if self.detected_category in (2, 3, 4) and selected:
            print(f"  selected members: {', '.join(selected)}")

        print(f"  output: {self.output_path}\n")
        if not self.confirm("Decrypt",
                            f"About to process {os.path.basename(self.ipsw_path)} "
                            f"for {self.detected_model}:\n"
                            f"  output → {self.output_path}\n"):
            print("Aborted by user.")
            return 1

        self.start_decrypt()
        return 1 if self._failed else 0


# ============================================================
# Entry point
# ============================================================
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ipod_universal_decrypt_b",
        description=f"{APP_NAME} v{APP_VERSION} — {plat.PLATFORM_NAME}")
    parser.add_argument("--cli", action="store_true",
                        help="run headless (no GUI); implies --ipsw required")
    parser.add_argument("--ipsw", metavar="PATH", help="IPSW firmware file")
    parser.add_argument("--output", metavar="PATH",
                        help="output file (category 1) or directory (2/3/4)")
    parser.add_argument("--partitions", metavar="LIST",
                        help="comma-separated member list (default: all)")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="skip confirmation prompts")
    parser.add_argument("--check", action="store_true",
                        help="run preflight platform checks and exit")
    parser.add_argument("--release-apple-services", action="store_true",
                        help="(macOS) stop Apple USB services and exit")
    parser.add_argument("--restore-apple-services", action="store_true",
                        help="(macOS) restore previously released services and exit")
    args = parser.parse_args(argv)

    if args.check:
        print(f"{APP_NAME} v{APP_VERSION} — preflight check")
        for ok, label, detail in plat.preflight_report():
            mark = "OK " if ok else "-- "
            print(f"  [{mark}] {label}: {detail}")
        found, detail = plat.find_ibugger_device()
        print(f"\n  iBugger: {detail}")
        for vid, pid, product in plat.enumerate_usb_devices():
            if vid is None:
                continue
            print(f"  USB: {vid:04x}:{pid:04x}" +
                  (f"  {product}" if product else ""))
        return 0

    if args.release_apple_services:
        if not plat.IS_MACOS:
            print("Apple USB service management is macOS-only.")
            return 1
        state_file = os.path.join(
            plat.temp_dir(), "ipod_decrypt_apple_services.json")
        for line in plat.release_apple_usb_services(state_file):
            print(line)
        return 0

    if args.restore_apple_services:
        if not plat.IS_MACOS:
            print("Apple USB service management is macOS-only.")
            return 1
        state_file = os.path.join(
            plat.temp_dir(), "ipod_decrypt_apple_services.json")
        for line in plat.restore_apple_usb_services(state_file):
            print(line)
        return 0

    if args.cli:
        if not args.ipsw:
            parser.error("--cli requires --ipsw PATH")
        cli = UniversalDecryptorCLI(args)
        return cli.run()

    # GUI mode
    if not plat.auto_elevate():
        print("Administrator privileges are required (Windows).")
        return 1
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
