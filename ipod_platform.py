"""Cross-platform helpers for the Universal iPod Firmware Decryptor.

Centralizes every platform-specific behavior so the application code stays
portable:

- Windows: CREATE_NO_WINDOW subprocesses, pnputil device enumeration,
  pnputil driver management, net stop/start for Apple services, drive-letter
  detection for disk-mode iPods, UAC auto-elevation.
- macOS (Apple Silicon and Intel): ioreg/system_profiler USB enumeration,
  launchctl-based best-effort release/restore of Apple USB services,
  /Volumes mount detection, DYLD_LIBRARY_PATH wiring for the bundled
  libusb/wInd3x binaries. No elevation or driver installation is needed.
- Linux: /sys USB enumeration (kept for development/testing).
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

if IS_WINDOWS:
    PLATFORM_NAME = "Windows"
elif IS_MACOS:
    PLATFORM_NAME = "macOS"
else:
    PLATFORM_NAME = "Linux"

MACHINE = platform.machine().lower()
IS_ARM64 = MACHINE in ("arm64", "aarch64")

# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _windows_hidden_kwargs():
    """kwargs that run a subprocess with no console window (Windows only)."""
    if not IS_WINDOWS:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return {"creationflags": 0x08000000, "startupinfo": si}


def hidden_subprocess_kwargs():
    """Public alias for _windows_hidden_kwargs()."""
    return _windows_hidden_kwargs()


def run_cmd(cmd, timeout=30, *, sudo=False, env=None):
    """Run a command and return (success, stdout, stderr).

    No console window on Windows; plain subprocess on macOS/Linux. ``sudo``
    prepends sudo (password prompt goes to the terminal when invoked from
    one; GUI callers should avoid it or warn the user first).
    """
    if sudo and not IS_WINDOWS:
        cmd = ["sudo"] + list(cmd)
    try:
        result = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            **_windows_hidden_kwargs(),
        )
        return result.returncode == 0, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError as exc:
        return False, "", str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, "", str(exc)


def temp_dir():
    """A writable temporary directory (C:\\Temp on Windows, /tmp elsewhere)."""
    if IS_WINDOWS:
        return os.environ.get("TEMP", os.environ.get("TMP", r"C:\Temp"))
    import tempfile
    return tempfile.gettempdir()


def default_desktop():
    return os.path.join(os.path.expanduser("~"), "Desktop")


# ---------------------------------------------------------------------------
# Bundled file lookup (dev checkout, PyInstaller onefile/onedir, .app bundle)
# ---------------------------------------------------------------------------

def _search_dirs():
    dirs = []
    if getattr(sys, "_MEIPASS", None):
        dirs.append(sys._MEIPASS)
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    dirs.append(exe_dir)
    # macOS .app bundle: executable lives in Contents/MacOS, PyInstaller
    # onedir data lives in Contents/Resources.
    if os.path.basename(exe_dir) == "MacOS":
        bundle = os.path.dirname(os.path.dirname(exe_dir))  # Contents/
        dirs.append(os.path.join(bundle, "Resources"))
        dirs.append(exe_dir)
    repo_root = os.path.dirname(os.path.abspath(__file__))
    dirs.append(repo_root)
    dirs.append(os.path.join(repo_root, "vendor"))
    seen, ordered = set(), []
    for d in dirs:
        if d and d not in seen:
            seen.add(d)
            ordered.append(d)
    return ordered


def get_bundled_path(filename):
    """Absolute path to a bundled/auxiliary file, or None.

    Checks, in order: the PyInstaller temp dir, the executable directory,
    the .app Contents/Resources directory, the repository root and vendor/.
    """
    for directory in _search_dirs():
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def wind3x_candidates():
    """Candidate file names for the wInd3x binary, most specific first."""
    if IS_WINDOWS:
        return ["wInd3x-win.exe", "wInd3x.exe"]
    if IS_MACOS:
        return [
            f"wInd3x-darwin-{'arm64' if IS_ARM64 else 'x86_64'}",
            "wInd3x-darwin",
            "wInd3x",
        ]
    return ["wInd3x"]


def find_wind3x():
    """Locate the wInd3x binary (bundled, repo, or vendor dir)."""
    for name in wind3x_candidates():
        path = get_bundled_path(name)
        if path:
            return path
    return None


def find_libusb():
    """Locate libusb-1.0 for the iBugger (Nano 2G) libusb transport."""
    if IS_WINDOWS:
        # The Windows iBugger transport uses WinUSB directly; libusb is only
        # needed next to wInd3x-win.exe.
        return get_bundled_path("libusb-1.0.dll")
    for name in ("libusb-1.0.dylib", "libusb-1.0.so", "libusb.so.0",
                 "libusb-1.0.0.dylib", "libusb-1.0.so.0"):
        path = get_bundled_path(name)
        if path:
            return path
    # Homebrew standard location (macOS)
    if IS_MACOS:
        for prefix in ("/opt/homebrew", "/usr/local"):
            candidate = os.path.join(prefix, "opt", "libusb", "lib",
                                     "libusb-1.0.dylib")
            if os.path.isfile(candidate):
                return candidate
    return None


def child_env_for_wind3x(wind3x_path=None):
    """Environment for spawning wInd3x.

    On macOS, if a libusb dylib is bundled next to the binary, make sure
    dyld can find it (the Go build links libusb dynamically). DYLD_* env
    vars survive exec for regular (non-platform) binaries.
    """
    env = dict(os.environ)
    if not IS_MACOS:
        return env
    libusb = find_libusb()
    if libusb:
        dyld_dirs = [os.path.dirname(libusb)]
        if wind3x_path:
            dyld_dirs.append(os.path.dirname(wind3x_path))
        existing = env.get("DYLD_LIBRARY_PATH", "")
        parts = [p for p in dyld_dirs + ([existing] if existing else []) if p]
        env["DYLD_LIBRARY_PATH"] = os.pathsep.join(dict.fromkeys(parts))
    return env


def run_wind3x(args, timeout=30, cwd=None):
    """Run the wInd3x binary. Returns (success, stdout, stderr)."""
    wind3x = find_wind3x()
    if not wind3x:
        return False, "", (
            "wInd3x binary not found. On macOS, place a native build at "
            "vendor/wInd3x-darwin-arm64 (see BUILD.md)."
        )
    env = child_env_for_wind3x(wind3x)
    try:
        result = subprocess.run(
            [wind3x] + list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd or os.path.dirname(wind3x),
            **_windows_hidden_kwargs(),
        )
        return result.returncode == 0, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError as exc:
        return False, "", str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, "", str(exc)


# ---------------------------------------------------------------------------
# USB device enumeration
# ---------------------------------------------------------------------------

def _parse_hex(value):
    try:
        return int(str(value).strip().lstrip("0x"), 16) & 0xFFFF
    except (ValueError, AttributeError):
        return None


def _parse_ioreg_usb_devices(out):
    """Parse `ioreg -c IOUSBDevice -w 0 -l` output into [(vid, pid, name)].

    ioreg emits each device's dictionary keys in an unspecified order, so
    properties are accumulated per device block (a block starts at the
    node header line, which is the only line containing '<dictionary>')
    instead of relying on line order.
    """
    devices = []
    seen = set()
    vid = pid = None
    name = ""

    def flush():
        nonlocal vid, pid, name
        if vid is not None and pid is not None and (vid, pid) not in seen:
            seen.add((vid, pid))
            devices.append((vid, pid, name))
        vid = pid = None
        name = ""

    for line in out.splitlines():
        if "<dictionary>" in line:
            flush()  # new node block begins
            continue
        m = re.search(r'idVendor"\s*=\s*(\d+)', line)
        if m:
            vid = int(m.group(1)) & 0xFFFF
            continue
        m = re.search(r'idProduct"\s*=\s*(\d+)', line)
        if m:
            pid = int(m.group(1)) & 0xFFFF
            continue
        m = re.search(r'USB Product Name"\s*=\s*"([^"]+)"', line)
        if m:
            name = m.group(1)
    flush()
    return devices


def _parse_spusb(out):
    """Parse `system_profiler SPUSBDataType` output into [(vid, pid, name)].

    "Vendor ID: 0x...." and "ID: 0x...." appear on separate lines, so each
    product ID is paired with the most recently seen vendor ID.
    """
    devices = []
    vendor = None
    for line in out.splitlines():
        m = re.search(r"Vendor ID: (0x[0-9A-Fa-f]+)", line)
        if m:
            vendor = _parse_hex(m.group(1))
            continue
        m = re.search(r"^\s*ID: (0x[0-9A-Fa-f]+)", line)
        if m and vendor is not None:
            devices.append((vendor, _parse_hex(m.group(1)), ""))
            vendor = None
    return devices


def enumerate_usb_devices():
    """List (vid, pid, product) tuples for connected USB devices.

    Best-effort across platforms; returns an empty list on failure.
    """
    devices = []
    if IS_WINDOWS:
        ok, out, _ = run_cmd(["pnputil", "/enum-devices", "/connected"], timeout=15)
        if not ok:
            return devices
        vid = pid = None
        product = ""
        for line in out.splitlines():
            m = re.search(r"Instance ID:\s*(.+)", line)
            if m:
                if vid is not None and pid is not None:
                    devices.append((vid, pid, product))
                iid = m.group(1).strip()
                mm = re.search(r"VID_([0-9A-Fa-f]{4})", iid)
                vid = _parse_hex(mm.group(1)) if mm else None
                mp = re.search(r"PID_([0-9A-Fa-f]{4})", iid)
                pid = _parse_hex(mp.group(1)) if mp else None
                product = ""
            elif re.search(r"Device Description:", line, re.IGNORECASE):
                product = line.split(":", 1)[1].strip()
        if vid is not None and pid is not None:
            devices.append((vid, pid, product))
        return devices

    if IS_MACOS:
        # ioreg is fast and exposes idVendor/idProduct (decimal) per device.
        ok, out, _ = run_cmd(["ioreg", "-c", "IOUSBDevice", "-w", "0", "-l"],
                             timeout=20)
        if ok:
            devices = _parse_ioreg_usb_devices(out)
        if devices:
            return devices
        # Fallback: system_profiler (slower).
        ok, out, _ = run_cmd(["system_profiler", "SPUSBDataType"], timeout=30)
        if not ok:
            return devices
        return _parse_spusb(out)

    # Linux (development/testing)
    usb_root = "/sys/bus/usb/devices"
    if not os.path.isdir(usb_root):
        return devices
    try:
        for entry in os.listdir(usb_root):
            base = os.path.join(usb_root, entry)
            try:
                with open(os.path.join(base, "idVendor")) as f:
                    vid = int(f.read().strip(), 16)
                with open(os.path.join(base, "idProduct")) as f:
                    pid = int(f.read().strip(), 16)
                product = ""
                try:
                    with open(os.path.join(base, "product"), "r",
                              errors="replace") as f:
                        product = f.read().strip()
                except OSError:
                    pass
                devices.append((vid, pid, product))
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return devices


def scan_dfu_pids(pids):
    """Return the first DFU PID (from the given list of '05ac'-style PIDs)
    found among connected devices, or None."""
    wanted = {int(p, 16) for p in pids}
    for vid, pid, _product in enumerate_usb_devices():
        if vid == 0x05AC and pid in wanted:
            return "%04x" % pid
    return None


def find_ibugger_device():
    """Look for the Unified iBugger interface (FFFF:8642).

    Returns (found: bool, detail: str).
    """
    for vid, pid, product in enumerate_usb_devices():
        if vid == 0xFFFF and pid == 0x8642:
            return True, f"Unified iBugger (FFFF:8642) connected{': ' + product if product else ''}"
    return False, "No Unified iBugger (FFFF:8642) device connected"


# ---------------------------------------------------------------------------
# Disk-mode iPod mount detection (Nano 2G loader.htm staging)
# ---------------------------------------------------------------------------

def find_ipod_notes_mount():
    """Find a removable volume that looks like a disk-mode iPod (has a
    Notes folder). Returns the volume root path or None."""
    if IS_WINDOWS:
        import string
        for letter in string.ascii_uppercase:
            notes_path = f"{letter}:\\Notes"
            if os.path.isdir(notes_path):
                return f"{letter}:\\"
        return None

    volumes_root = "/Volumes"
    try:
        entries = sorted(os.listdir(volumes_root))
    except OSError:
        return None
    for entry in entries:
        if entry.startswith(".") or entry in ("Macintosh HD",):
            continue
        volume = os.path.join(volumes_root, entry)
        if os.path.isdir(os.path.join(volume, "Notes")):
            return volume
    return None


# ---------------------------------------------------------------------------
# Apple USB service management (macOS only; best-effort, requires sudo)
# ---------------------------------------------------------------------------

# Labels of launchd jobs that are known (or suspected) to be able to hold
# Apple USB devices (iPod DFU) open. We only touch jobs that actually exist
# and match these patterns — never anything else.
_APPLE_USB_LABEL_RE = re.compile(
    r"^com\.apple\..*(dfu|ipod|iosd|usbd).*", re.IGNORECASE
)


def _run_admin_mac(cmd_list, timeout=30):
    """Run a command with administrator privileges on macOS.

    Uses the standard GUI authorization dialog (osascript) so it works
    from both GUI apps (no TTY available for sudo) and terminals.
    """
    import shlex
    inner = " ".join(shlex.quote(a) for a in cmd_list)
    # Escape for AppleScript string literal context.
    inner = inner.replace("\\", "\\\\").replace('"', '\"')
    script = (f'do shell script "{inner}" with administrator privileges '
              f"and with hidden results")
    return run_cmd(["osascript", "-e", script], timeout=timeout)


def list_apple_usb_services():
    """Return [(label, plist_path)] for Apple USB-related launchd jobs.

    Best-effort and read-only (no elevation): returns [] when launchctl is
    unavailable or nothing matches (normal on most Macs — nothing holds
    the DFU interface).
    """
    if not IS_MACOS:
        return []
    ok, out, _ = run_cmd(["launchctl", "list"], timeout=20)
    if not ok:
        return []
    services = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        label = parts[2].strip()
        if _APPLE_USB_LABEL_RE.match(label):
            # Discover the plist path (needed later to bootstrap it back).
            plist_path = ""
            okp, outp, _ = run_cmd(
                ["launchctl", "print", f"system/{label}"], timeout=10)
            if not okp:
                okp, outp, _ = run_cmd(
                    ["launchctl", "print", f"gui/{os.getuid()}/{label}"],
                    timeout=10,
                )
            if okp:
                m = re.search(r"^\s*path\s*=\s*(\S+)", outp, re.MULTILINE)
                if m:
                    plist_path = m.group(1)
            services.append((label, plist_path))
    return services


def release_apple_usb_services(state_path):
    """Stop Apple USB-related launchd jobs so raw USB tools can open the
    device. Persists released jobs to state_path so they can be restored.

    Elevation uses the standard macOS admin dialog (osascript). Returns a
    list of human-readable log lines.
    """
    lines = []
    if not IS_MACOS:
        return lines
    services = list_apple_usb_services()
    released = []
    for label, plist_path in services:
        ok, _out, err = _run_admin_mac(
            ["launchctl", "bootout", "system", label], timeout=30)
        if not ok:
            ok, _out, err = _run_admin_mac(
                ["launchctl", "remove", label], timeout=30)
        if ok:
            released.append({"label": label, "plist": plist_path})
            lines.append(f"  released system service: {label}")
        else:
            lines.append(f"  could not release {label}: {err.strip() or 'unknown'}")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"released": released}, f)
    if not released:
        lines.append("  no Apple USB services needed releasing (good)")
    return lines


def restore_apple_usb_services(state_path):
    """Re-bootstrap any Apple USB services previously released (admin
    dialog)."""
    lines = []
    if not IS_MACOS or not os.path.isfile(state_path):
        return lines
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        return lines
    for job in state.get("released", []):
        label, plist = job.get("label", ""), job.get("plist", "")
        if plist and os.path.isfile(plist):
            ok, _out, err = _run_admin_mac(
                ["launchctl", "bootstrap", "system", plist], timeout=30)
            lines.append(f"  restored {label}" if ok
                         else f"  could not restore {label}: {err.strip() or 'unknown'}")
        else:
            lines.append(f"  no plist recorded for {label}; it will reload on next boot")
    try:
        os.remove(state_path)
    except OSError:
        pass
    return lines


# ---------------------------------------------------------------------------
# Driver management (Windows only; no-op elsewhere)
# ---------------------------------------------------------------------------

def check_winusb_installed(pid):
    """Check if a WinUSB (libwdi/Zadig) driver is installed for a PID."""
    if not IS_WINDOWS:
        return False
    ok, out, _ = run_cmd(["pnputil", "/enum-drivers"], timeout=10)
    if not ok:
        return False
    return f"PID_{pid}" in out.upper() and "libwdi" in out.lower()


def remove_winusb_driver(pid):
    """Remove a libwdi WinUSB driver for a specific PID (Windows)."""
    if not IS_WINDOWS:
        return False
    ok, out, _ = run_cmd(["pnputil", "/enum-drivers"], timeout=10)
    if not ok:
        return False
    lines = out.splitlines()
    oem_inf = None
    for i, line in enumerate(lines):
        if f"PID_{pid}" in line.upper() and "libwdi" in line.lower():
            for j in range(max(0, i - 5), i):
                if "Published Name:" in lines[j]:
                    oem_inf = lines[j].split(":", 1)[1].strip()
                    break
            if oem_inf:
                break
    if oem_inf:
        run_cmd(["pnputil", "/delete-driver", oem_inf, "/uninstall"],
                timeout=15)
        return True
    return False


# ---------------------------------------------------------------------------
# Elevation (Windows only)
# ---------------------------------------------------------------------------

def needs_elevation():
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return not ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:  # noqa: BLE001
        return False


def auto_elevate():
    """Re-launch as administrator (Windows). No-op on macOS/Linux.

    Returns True when the current process may continue.
    """
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
    except Exception:  # noqa: BLE001
        return True
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
    except Exception:  # noqa: BLE001
        return False
    if ret > 32:
        sys.exit(0)
    return False


# ---------------------------------------------------------------------------
# Device access preparation (platform-specific service juggling)
# ---------------------------------------------------------------------------

def prepare_device_access(log=None):
    """Do whatever this platform needs before raw USB device access.

    Windows: stop Apple Mobile Device Service / iPodService and unbind
    usbipd. macOS: nothing is stopped automatically (raw USB usually works
    out of the box; use release_apple_usb_services() if a service is
    holding the device).
    """
    log = log or (lambda _msg: None)
    if IS_WINDOWS:
        for svc in ("Apple Mobile Device Service", "iPodService"):
            run_cmd(["net", "stop", svc], timeout=10)
        run_cmd(["usbipd", "unbind", "--all"], timeout=5)
    return True


def restore_device_access(log=None):
    log = log or (lambda _msg: None)
    if IS_WINDOWS:
        for svc in ("Apple Mobile Device Service", "iPodService"):
            run_cmd(["net", "start", svc], timeout=10)
    return True


# ---------------------------------------------------------------------------
# Preflight / diagnostics
# ---------------------------------------------------------------------------

def check_libusb_loadable():
    """Try loading libusb-1.0 (needed by the Nano 2G iBugger transport on
    macOS/Linux). Returns (ok, detail)."""
    if IS_WINDOWS:
        return True, "WinUSB transport (no libusb needed)"
    import ctypes
    candidates = []
    env_path = os.environ.get("IPOD_LIBUSB_PATH")
    if env_path:
        candidates.append(env_path)
    bundled = find_libusb()
    if bundled:
        candidates.append(bundled)
    candidates += [
        "libusb-1.0.dylib", "libusb-1.0.so",
        "libusb-1.0.0.dylib", "libusb-1.0.so.0", "libusb.so.0",
    ]
    last_error = ""
    for candidate in candidates:
        try:
            ctypes.CDLL(candidate)
            return True, f"libusb loaded: {candidate}"
        except OSError as exc:
            last_error = str(exc)
    return False, (
        f"libusb-1.0 not found ({last_error}). "
        "On macOS install it with: brew install libusb "
        "(only needed for the Nano 2G iBugger path; Classic/Nano 3G/5G "
        "device AES uses wInd3x directly)."
    )


def check_openssl():
    ok, _out, err = run_cmd(["openssl", "version"], timeout=10)
    if ok:
        return True, "openssl available"
    return False, f"openssl not available: {err.strip() or 'not found'}"


def check_tkinter():
    try:
        import tkinter  # noqa: F401
        return True, "tkinter available"
    except Exception as exc:  # noqa: BLE001
        return False, f"tkinter unavailable: {exc} (use --cli mode instead)"


def preflight_report():
    """Return a list of (ok, label, detail) tuples for a full check."""
    reports = []
    reports.append((True, "Platform",
                    f"{PLATFORM_NAME} ({MACHINE or 'unknown arch'})"))
    reports.append((True, "Python", platform.python_version()))
    ok, detail = check_tkinter()
    reports.append((ok, "Tkinter GUI", detail))
    ok, detail = check_openssl()
    reports.append((ok, "OpenSSL (software AES fallback)", detail))
    ok, detail = check_libusb_loadable()
    reports.append((ok, "libusb (Nano 2G iBugger path)", detail))
    wind3x = find_wind3x()
    reports.append((bool(wind3x), "wInd3x binary",
                    wind3x or "not found (needed for device-AES decrypt)"))
    return reports


if __name__ == "__main__":
    print(f"Universal iPod Firmware Decryptor — platform check ({PLATFORM_NAME})")
    for ok, label, detail in preflight_report():
        mark = "OK " if ok else "-- "
        print(f"  [{mark}] {label}: {detail}")
    print("\nConnected USB devices (VID:PID):")
    for vid, pid, product in enumerate_usb_devices():
        if vid is None:
            continue
        extra = f"  {product}" if product else ""
        print(f"  {vid:04x}:{pid:04x}{extra}")
    found, detail = find_ibugger_device()
    print(f"\niBugger check: {detail}")
