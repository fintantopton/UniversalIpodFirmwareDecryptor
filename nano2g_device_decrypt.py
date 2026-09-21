"""Self-contained, hardware-verified Nano 2G (S5L8701) device-side decryptor.

Background (see C:\\KIRO\\iPodKnowledgeDB\\RESEARCH_DOCS\\
NANO2G_S5L8701_USB_TRANSPORT_AND_DECRYPTION.md for the full technical record):

The Nano 2G's OSOS/AUPD partitions are encrypted with a hardware-fused AES key
that is NOT the public "0x837" key (that key belongs to a different SoC
generation's IMG2/ramdisk format). The only way to decrypt them correctly is
to run the device's own AES engine, via a Notes-app buffer overflow exploit
(historically "iBugger" by TheSeven) that loads a RAM-resident Loader, then a
RAM-resident Core, then a small AES driver payload.

That exploit chain was blocked on modern PCs because the Loader/Core configure
USB bulk endpoints at an out-of-spec 528-byte packet size (USB 2.0 Hi-Speed
caps bulk endpoints at 512 bytes). Legacy EHCI (USB 2.0) hosts tolerated it;
all modern xHCI (USB 3.x) hosts silently drop every response. This module
embeds 512-byte-patched Loader/Core builds (patched at exactly 6 bytes each,
zero other behavior changes) plus the historical AES driver payload, and
drives them with native WinUSB (no extra runtime DLL) so the whole pipeline
works standalone in this app.

Every operation here is RAM-resident on the iPod. Nothing is written to
iPod NAND/NOR/flash storage at any point.
"""

from __future__ import annotations

import base64
import ctypes
import re
import struct
import subprocess
import time
import uuid
import zlib
from ctypes import wintypes


# ============================================================
# Embedded device-side binaries (patched to 512-byte USB packets)
# ============================================================
# Each blob is: zlib-compressed, then base64-encoded, to keep this source
# file compact. Decompressed sizes and SHA-256 hashes are recorded in
# NANO2G_S5L8701_USB_TRANSPORT_AND_DECRYPTION.md.

def _blob(compressed_b64: str) -> bytes:
    return zlib.decompress(base64.b64decode(compressed_b64))


# loader_512.htm (4096 bytes) - patched Notes-exploit loader, 512-byte USB
# packets. Deploy verbatim as <iPod>/Notes/loader.htm.
# core-2_512.bin (6237 bytes) - patched Core image, 512-byte USB packets.
# logo-2_original.bin (46464 bytes) - unmodified boot-splash image shown by
# the Loader while Core is uploaded. Contains no packet-size fields.
# decryptfirmware.bin (768 bytes) - historical device-side AES driver
# payload (TheSeven, ipodcrypto/decryptfirmware). Unmodified; it contains no
# USB code, only the AES engine driving logic.
from nano2g_payloads import (  # noqa: E402
    _LOADER_HTM_B64,
    _CORE_BIN_B64,
    _LOGO_BIN_B64,
    _DECRYPTFW_BIN_B64,
)


IBUGGER_VID = 0xFFFF
IBUGGER_PID = 0x8642
IBUGGER_OUT_ENDPOINT = 0x04
IBUGGER_IN_ENDPOINT = 0x83
IBUGGER_INTERFACE = 0
IBUGGER_WIRE_PACKET_SIZE = 512
IBUGGER_INTERFACE_GUID = uuid.UUID("8bcdb266-e477-4545-b94c-8ee8fbe21bd8")

IBUGGER_LOGO_ADDRESS = 0x22000020
IBUGGER_CORE_ADDRESS = 0x22000000
IBUGGER_CORE_ENTRY = 0x22000020
IBUGGER_CORE_STACK = 0x0A000000

IBUGGER_RAM_CODE = 0x08000000
IBUGGER_RAM_ENTRY = IBUGGER_RAM_CODE + 0x20
IBUGGER_RAM_DATA = 0x08010000
IBUGGER_RAM_STACK = IBUGGER_RAM_DATA

# ============================================================
# Win32 / WinUSB ctypes plumbing (self-contained, no external DLL)
# ============================================================
DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010
DIGCF_ALLCLASSES = 0x00000004
ERROR_NO_MORE_ITEMS = 259
ERROR_IO_PENDING = 997
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_ATTRIBUTE_NORMAL = 0x00000080
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
BULK_TIMEOUT_MS = 5000


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wintypes.DWORD),
        ("Reserved", ctypes.c_void_p),
    ]


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("ClassGuid", GUID),
        ("DevInst", wintypes.DWORD),
        ("Reserved", ctypes.c_void_p),
    ]


class USB_INTERFACE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_ubyte),
        ("bDescriptorType", ctypes.c_ubyte),
        ("bInterfaceNumber", ctypes.c_ubyte),
        ("bAlternateSetting", ctypes.c_ubyte),
        ("bNumEndpoints", ctypes.c_ubyte),
        ("bInterfaceClass", ctypes.c_ubyte),
        ("bInterfaceSubClass", ctypes.c_ubyte),
        ("bInterfaceProtocol", ctypes.c_ubyte),
        ("iInterface", ctypes.c_ubyte),
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def _guid_from_uuid(value: uuid.UUID) -> GUID:
    raw = value.bytes_le
    result = GUID()
    ctypes.memmove(ctypes.byref(result), raw, len(raw))
    return result


def _last_error_text() -> str:
    error = ctypes.get_last_error()
    return f"Win32 error {error}: {ctypes.FormatError(error)}"


class DeviceNotFoundError(RuntimeError):
    pass


class TransportError(RuntimeError):
    pass


# Windows' official, stable WinUSB device setup class GUID. This is a
# fixed value assigned by Microsoft (see winusb.inf / the WinUSB driver
# installation docs) and does NOT change between Zadig/libwdi installs.
# It is deliberately NOT the same thing as IBUGGER_INTERFACE_GUID above,
# which is a per-install *device interface* GUID that libwdi's generated
# driver package registers — that one genuinely can differ between Zadig
# runs on different PCs (or even re-installs on the same PC), which is
# exactly what caused _find_interface() to report "not found" on a PC
# where WinUSB was, in fact, correctly bound to the device.
_WINUSB_CLASS_GUID = "{88BAE032-5A81-49F0-BC3D-A4FF138216D6}"


def _ibugger_pnp_presence() -> str:
    """Check whether a PID_8642 device exists in Windows PnP, and whether
    WinUSB (Microsoft's winusb.sys, any install) is actually bound to it —
    independent of this app's own hardcoded IBUGGER_INTERFACE_GUID.

    _find_interface() only succeeds if WinUSB happens to have registered
    exactly that one device interface GUID. libwdi (which Zadig uses to
    generate its driver packages) mints a fresh interface GUID per install
    unless the exact same driver package is reused, so a PC where Zadig
    was run separately can have WinUSB genuinely, correctly bound to the
    device, while still using a different interface GUID than the one
    hardcoded here. In that case _find_interface() finding nothing does
    NOT mean WinUSB isn't installed - it means this app doesn't yet know
    that PC's specific interface GUID.

    This function checks the device's PnP *class GUID* instead, which for
    any WinUSB-bound device is always the same well-known Microsoft value
    (_WINUSB_CLASS_GUID), regardless of which libwdi/Zadig run installed
    it. That distinguishes "WinUSB is genuinely not installed for this
    device" from "WinUSB is installed, but under an interface GUID this
    app doesn't recognize yet".

    Returns one of:
      "present_winusb_unrecognized_guid" - WinUSB IS bound (class GUID
          matches), but not under the interface GUID this app expects.
          This is a bug in this app's assumptions, not a driver problem.
      "present_no_winusb" - device present, but bound to some other
          (non-WinUSB) driver.
      "not_present" - no PID_8642 device found in PnP at all.
      "unknown" - pnputil unavailable/failed; caller should fall back to
          a generic message rather than assert either way.
    """
    try:
        result = subprocess.run(
            ['pnputil', '/enum-devices', '/connected', '/drivers'],
            capture_output=True, text=True, timeout=10,
            creationflags=0x08000000,
        )
    except Exception:
        return "unknown"
    if result.returncode != 0 and not result.stdout:
        return "unknown"

    vid_tag = f'VID_{IBUGGER_VID:04X}'
    pid_tag = f'PID_{IBUGGER_PID:04X}'
    lines = result.stdout.splitlines()

    # pnputil prints one record per "Instance ID:" line, followed by that
    # device's own fields (Class GUID, Status, Driver Name, ...) until the
    # next "Instance ID:" line. Find our device's record and inspect only
    # the fields that belong to it, not the whole (possibly huge) output.
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith('Instance ID:'):
            continue
        upper = stripped.upper()
        if vid_tag not in upper or pid_tag not in upper:
            continue
        # Found our device's record. Scan forward until the next
        # "Instance ID:" (or end of output) for its Class GUID.
        for record_line in lines[i + 1:]:
            record_stripped = record_line.strip()
            if record_stripped.startswith('Instance ID:'):
                break
            if record_stripped.upper().startswith('CLASS GUID:'):
                class_guid = record_stripped.split(':', 1)[1].strip().upper()
                if class_guid == _WINUSB_CLASS_GUID:
                    return "present_winusb_unrecognized_guid"
                return "present_no_winusb"
        # Record found but no Class GUID field seen before the next device
        # (shouldn't normally happen) - fall back to "present, unknown
        # driver" rather than silently returning not_present.
        return "present_no_winusb"

    return "not_present"


def _load_apis():
    setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    winusb = ctypes.WinDLL("winusb", use_last_error=True)

    setupapi.SetupDiGetClassDevsW.argtypes = [
        ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD
    ]
    setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD,
        ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)
    ]
    setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
    ]
    setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    setupapi.SetupDiEnumDeviceInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)
    ]
    setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
    setupapi.SetupDiOpenDevRegKey.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(SP_DEVINFO_DATA), wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ]
    setupapi.SetupDiOpenDevRegKey.restype = wintypes.HKEY

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR
    ]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    ]
    kernel32.GetOverlappedResult.restype = wintypes.BOOL

    winusb.WinUsb_Initialize.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE)]
    winusb.WinUsb_Initialize.restype = wintypes.BOOL
    winusb.WinUsb_Free.argtypes = [wintypes.HANDLE]
    winusb.WinUsb_Free.restype = wintypes.BOOL
    winusb.WinUsb_QueryInterfaceSettings.argtypes = [
        wintypes.HANDLE, ctypes.c_ubyte, ctypes.POINTER(USB_INTERFACE_DESCRIPTOR)
    ]
    winusb.WinUsb_QueryInterfaceSettings.restype = wintypes.BOOL
    winusb.WinUsb_WritePipe.argtypes = [
        wintypes.HANDLE, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), ctypes.POINTER(OVERLAPPED),
    ]
    winusb.WinUsb_WritePipe.restype = wintypes.BOOL
    winusb.WinUsb_ReadPipe.argtypes = [
        wintypes.HANDLE, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), ctypes.POINTER(OVERLAPPED),
    ]
    winusb.WinUsb_ReadPipe.restype = wintypes.BOOL
    return setupapi, kernel32, winusb


def _enum_interface_paths(setupapi, vid, pid, interface_guid):
    """Yield every device interface path under interface_guid whose device
    path contains the given VID/PID, regardless of instance ordering."""
    guid = _guid_from_uuid(interface_guid)
    info_set = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    )
    if info_set == INVALID_HANDLE_VALUE:
        raise TransportError(_last_error_text())
    try:
        for index in range(256):
            interface = SP_DEVICE_INTERFACE_DATA()
            interface.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            if not setupapi.SetupDiEnumDeviceInterfaces(
                info_set, None, ctypes.byref(guid), index, ctypes.byref(interface)
            ):
                if ctypes.get_last_error() == ERROR_NO_MORE_ITEMS:
                    break
                continue
            required = wintypes.DWORD()
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                info_set, ctypes.byref(interface), None, 0, ctypes.byref(required), None
            )
            if required.value == 0:
                continue
            detail = (ctypes.c_ubyte * required.value)()
            cb_size = wintypes.DWORD(8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 5)
            ctypes.memmove(detail, ctypes.byref(cb_size), ctypes.sizeof(cb_size))
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                info_set, ctypes.byref(interface), detail, required.value,
                ctypes.byref(required), None,
            ):
                continue
            path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
            if re.search(rf"vid_{vid:04x}&pid_{pid:04x}", path, re.IGNORECASE):
                yield path
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)


_REG_DEVICE_INTERFACE_GUIDS_VALUE = "DeviceInterfaceGUIDs"
_REG_DEVICE_INTERFACE_GUID_VALUE = "DeviceInterfaceGUID"
DICS_FLAG_GLOBAL = 0x00000001
DIREG_DEV = 0x00000001
KEY_READ = 0x20019
REG_MULTI_SZ = 7
REG_SZ = 1
ERROR_SUCCESS = 0


def _discover_device_interface_guids(setupapi, vid, pid):
    """Read the actual DeviceInterfaceGUID(s) registry value that libwdi's
    generated .inf wrote for this specific VID/PID device on this specific
    PC, by opening the device's own hardware registry key directly.

    This is the authoritative source: whatever GUID(s) appear here are
    exactly what SetupDiEnumDeviceInterfaces can enumerate against for this
    device, regardless of which install/version of Zadig wrote them. The
    well-known WinUSB *class* GUID cannot be used for this purpose - class
    GUIDs group devices for driver-install purposes, but WinUSB always
    registers its actual runtime device interface under a GUID declared in
    the device-specific INF's [Dev_AddReg] section (DeviceInterfaceGUIDs),
    not under the class GUID itself.

    Returns a list of uuid.UUID (usually 0 or 1 entries; DeviceInterfaceGUIDs
    is a REG_MULTI_SZ and can technically hold more than one).
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RegQueryValueExW.argtypes = [
        wintypes.HKEY, wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.RegQueryValueExW.restype = wintypes.LONG
    advapi32.RegCloseKey.argtypes = [wintypes.HKEY]
    advapi32.RegCloseKey.restype = wintypes.LONG

    info_set = setupapi.SetupDiGetClassDevsW(
        None, None, None, DIGCF_PRESENT | DIGCF_ALLCLASSES
    )
    if info_set == INVALID_HANDLE_VALUE:
        return []

    found: list[uuid.UUID] = []
    try:
        index = 0
        while True:
            devinfo = SP_DEVINFO_DATA()
            devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            if not setupapi.SetupDiEnumDeviceInfo(info_set, index, ctypes.byref(devinfo)):
                if ctypes.get_last_error() == ERROR_NO_MORE_ITEMS:
                    break
                index += 1
                continue
            index += 1

            required = wintypes.DWORD()
            setupapi.SetupDiGetDeviceInstanceIdW(
                info_set, ctypes.byref(devinfo), None, 0, ctypes.byref(required)
            )
            if required.value == 0:
                continue
            buf = ctypes.create_unicode_buffer(required.value)
            if not setupapi.SetupDiGetDeviceInstanceIdW(
                info_set, ctypes.byref(devinfo), buf, required.value, ctypes.byref(required)
            ):
                continue
            instance_id = buf.value
            if not re.search(rf"vid_{vid:04x}&pid_{pid:04x}", instance_id, re.IGNORECASE):
                continue

            hkey = setupapi.SetupDiOpenDevRegKey(
                info_set, ctypes.byref(devinfo), DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ
            )
            if not hkey or hkey == INVALID_HANDLE_VALUE:
                continue
            try:
                for value_name in (_REG_DEVICE_INTERFACE_GUIDS_VALUE,
                                   _REG_DEVICE_INTERFACE_GUID_VALUE):
                    value_type = wintypes.DWORD()
                    value_size = wintypes.DWORD()
                    rc = advapi32.RegQueryValueExW(
                        hkey, value_name, None, ctypes.byref(value_type),
                        None, ctypes.byref(value_size),
                    )
                    if rc != ERROR_SUCCESS or value_size.value == 0:
                        continue
                    raw = ctypes.create_unicode_buffer(value_size.value // 2 + 1)
                    rc = advapi32.RegQueryValueExW(
                        hkey, value_name, None, ctypes.byref(value_type),
                        ctypes.cast(raw, ctypes.c_void_p), ctypes.byref(value_size),
                    )
                    if rc != ERROR_SUCCESS:
                        continue
                    raw_bytes = ctypes.string_at(raw, value_size.value)
                    text = raw_bytes.decode("utf-16-le", errors="ignore")
                    for candidate in text.split("\x00"):
                        candidate = candidate.strip().strip("{}")
                        if not candidate:
                            continue
                        try:
                            found.append(uuid.UUID(candidate))
                        except ValueError:
                            continue
                    if found:
                        break
            finally:
                advapi32.RegCloseKey(hkey)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)
    return found


def _find_interface(setupapi, vid, pid, interface_guid):
    """Find a WinUSB device interface path for the given VID/PID.

    Tries this app's known interface_guid first (fast path — matches when
    the current PC's Zadig/libwdi install happens to use the same GUID as
    whatever install this app's constant was recorded from). If that finds
    nothing, discovers the actual DeviceInterfaceGUID(s) this specific PC's
    driver install registered for this VID/PID directly from the device's
    own registry key, and retries with each of those. libwdi mints a fresh
    interface GUID per install, so a different PC (or a fresh Zadig
    re-install on the same PC) can have WinUSB genuinely, correctly bound
    while using an interface GUID this app has never seen before; reading
    it directly from the device's own registration is the only way to
    reliably find it (the WinUSB device *class* GUID is a different thing
    entirely and cannot be enumerated as a device interface).
    """
    for path in _enum_interface_paths(setupapi, vid, pid, interface_guid):
        return path
    for discovered_guid in _discover_device_interface_guids(setupapi, vid, pid):
        if discovered_guid == interface_guid:
            continue
        for path in _enum_interface_paths(setupapi, vid, pid, discovered_guid):
            return path
    return None


class IBuggerTransport:
    """Native WinUSB transport for the patched Nano 2G iBugger Loader/Core.

    Every bulk transfer is capped at 512 bytes, matching the patched
    device-side endpoint configuration. RAM-only: does not touch iPod
    storage.
    """

    def __init__(self, log=None):
        self._log = log or (lambda _msg: None)
        self.setupapi, self.kernel32, self.winusb = _load_apis()
        self.handle = None
        self.usb_handle = wintypes.HANDLE()
        self.version = None
        self.core_type = None  # 1 = Loader, 2 = Core
        self.device_type = None
        self._open()

    def _open(self):
        path = _find_interface(
            self.setupapi, IBUGGER_VID, IBUGGER_PID, IBUGGER_INTERFACE_GUID
        )
        if not path:
            presence = _ibugger_pnp_presence()
            if presence == "present_winusb_unrecognized_guid":
                raise DeviceNotFoundError(
                    "iPod is enumerating as Unified iBugger (VID_FFFF&PID_8642) "
                    "and WinUSB IS correctly bound to it on this PC, but its "
                    "registered device interface could not be opened just now. "
                    "Try unplugging and reconnecting the iPod once, then retry. "
                    "If this keeps happening, re-run Zadig's Install/Replace "
                    "Driver step for this device."
                )
            elif presence == "present_no_winusb":
                raise DeviceNotFoundError(
                    "iPod is enumerating as Unified iBugger (VID_FFFF&PID_8642), "
                    "but no WinUSB driver is bound to it on this PC. This is a "
                    "one-time, per-PC driver setup step, not a problem with the "
                    "iPod or the loader.htm staging.\n\n"
                    "Fix: open Zadig, select the 'Unified iBugger' / VID_FFFF "
                    "PID_8642 device (enable Options > List All Devices if it "
                    "isn't shown), choose WinUSB as the target driver, and "
                    "click Install Driver/Replace Driver. Then try again "
                    "without re-staging loader.htm or resetting the iPod."
                )
            elif presence == "not_present":
                raise DeviceNotFoundError(
                    "Unified iBugger (VID_FFFF&PID_8642) not found on this PC "
                    "at all (checked both WinUSB and raw PnP device presence). "
                    "Stage loader.htm in Notes and eject/reconnect the iPod so "
                    "it boots into iBugger, then try again."
                )
            else:
                raise DeviceNotFoundError(
                    "Unified iBugger (VID_FFFF&PID_8642) not found. "
                    "Stage loader.htm in Notes and eject/reconnect the iPod. "
                    "If the iPod is confirmed booted into iBugger but this "
                    "keeps failing, check Zadig for a WinUSB driver bound to "
                    "VID_FFFF&PID_8642 on this PC."
                )
        handle = self.kernel32.CreateFileW(
            path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            handle = self.kernel32.CreateFileW(
                path, 0, 0, None, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None,
            )
        if handle == INVALID_HANDLE_VALUE:
            raise TransportError(f"CreateFile failed: {_last_error_text()}")
        self.handle = handle
        usb_handle = wintypes.HANDLE()
        if not self.winusb.WinUsb_Initialize(handle, ctypes.byref(usb_handle)):
            self.kernel32.CloseHandle(handle)
            self.handle = None
            raise TransportError(f"WinUsb_Initialize failed: {_last_error_text()}")
        self.usb_handle = usb_handle
        self._read_identity()

    def close(self):
        if self.usb_handle:
            self.winusb.WinUsb_Free(self.usb_handle)
            self.usb_handle = wintypes.HANDLE()
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # ---- low-level bulk transfer -----------------------------------
    def _bulk_transfer(self, endpoint, buffer, size):
        event = self.kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise TransportError(_last_error_text())
        overlapped = OVERLAPPED()
        overlapped.hEvent = event
        transferred = wintypes.ULONG()
        try:
            if endpoint & 0x80:
                ok = self.winusb.WinUsb_ReadPipe(
                    self.usb_handle, endpoint, buffer, size,
                    ctypes.byref(transferred), ctypes.byref(overlapped),
                )
            else:
                ok = self.winusb.WinUsb_WritePipe(
                    self.usb_handle, endpoint, buffer, size,
                    ctypes.byref(transferred), ctypes.byref(overlapped),
                )
            if not ok and ctypes.get_last_error() != ERROR_IO_PENDING:
                raise TransportError(_last_error_text())
            if not ok:
                wait_result = self.kernel32.WaitForSingleObject(event, BULK_TIMEOUT_MS)
                if wait_result == WAIT_TIMEOUT:
                    raise TransportError(
                        f"USB endpoint 0x{endpoint:02x} timed out. If this "
                        "device previously worked, it may have re-enumerated; "
                        "retry the operation."
                    )
                if wait_result != WAIT_OBJECT_0:
                    raise TransportError(_last_error_text())
                if not self.kernel32.GetOverlappedResult(
                    self.handle, ctypes.byref(overlapped), ctypes.byref(transferred), False
                ):
                    raise TransportError(_last_error_text())
            return transferred.value
        finally:
            self.kernel32.CloseHandle(event)

    def _bulk_write(self, data: bytes):
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        transferred = self._bulk_transfer(IBUGGER_OUT_ENDPOINT, buffer, len(data))
        if transferred != len(data):
            raise TransportError(f"short write: {transferred} of {len(data)} bytes")

    def _bulk_read(self, size: int) -> bytes:
        buffer = (ctypes.c_ubyte * size)()
        transferred = self._bulk_transfer(IBUGGER_IN_ENDPOINT, buffer, size)
        return bytes(buffer[:transferred])

    def _read_status(self):
        return self._bulk_read(0x10)

    @staticmethod
    def _check_status(data: bytes):
        if len(data) < 4:
            raise TransportError(f"short iBugger status response: {data.hex()}")
        error_code = struct.unpack_from("<I", data)[0]
        if error_code != 1:
            raise TransportError(f"iBugger operation failed with status {error_code}")

    # ---- protocol ----------------------------------------------------
    def _read_identity(self):
        """Opcode 1 (GET INFO) returns direct metadata, not a status packet.

        The 4th word (reserved) has been observed non-zero on real hardware
        (e.g. 0x00005ac0) even though every other field decodes correctly;
        the historical libibugger.py never validated it either, so it is
        not enforced here.
        """
        self._bulk_write(struct.pack("<IIII", 1, 0, 0, 0))
        data = self._bulk_read(16)
        if len(data) != 16:
            raise TransportError(f"unexpected identity response length: {len(data)}")
        major, minor, revision, core_type, device_type, _max_out, _max_in, _reserved = (
            struct.unpack("<BBBBIHHI", data)
        )
        self.version = (major, minor, revision)
        self.core_type = core_type + 1
        self.device_type = device_type
        self._log(
            f"iBugger identity: v{major}.{minor}.{revision}, "
            f"stage={'Core' if self.core_type == 2 else 'Loader'}, "
            f"device_type={device_type}"
        )

    def get_state(self, new_state: int):
        """GETSTATE (opcode 0xA) is Core-only; the Loader replies with a
        16-byte 'unsupported function' status instead of the 92-byte block."""
        self._bulk_write(struct.pack("<IiII", 0xA, new_state, 0, 0))
        data = self._bulk_read(0x5C)
        self._check_status(data)
        if len(data) != 0x5C:
            raise TransportError(f"unexpected state response length: {len(data)}")
        return struct.unpack("<19I", data[0x10:])

    def write_memory(self, offset: int, data: bytes):
        if offset & 3:
            opcode, divisor = 7, 1
        else:
            opcode, divisor = 6, 4
        block_size = IBUGGER_WIRE_PACKET_SIZE - 0x10
        position = 0
        while position < len(data):
            block = data[position:position + block_size]
            block_opcode, block_divisor = opcode, divisor
            if len(block) & 3:
                block_opcode, block_divisor = 7, 1
            command = struct.pack(
                "<IIII", block_opcode, offset + position, len(block) // block_divisor, 0
            ) + block
            self._bulk_write(command)
            self._check_status(self._read_status())
            position += len(block)

    def read_memory(self, offset: int, size: int) -> bytes:
        if offset & 3:
            opcode, divisor = 5, 1
        else:
            opcode, divisor = 4, 4
        block_size = IBUGGER_WIRE_PACKET_SIZE - 0x10
        output = bytearray()
        position = 0
        while position < size:
            block_len = min(block_size, size - position)
            block_opcode, block_divisor = opcode, divisor
            if block_len & 3:
                block_opcode, block_divisor = 5, 1
            self._bulk_write(struct.pack(
                "<IIII", block_opcode, offset + position, block_len // block_divisor, 0
            ))
            response = self._bulk_read(0x10 + block_len)
            self._check_status(response)
            output.extend(response[0x10:0x10 + block_len])
            position += block_len
        return bytes(output)

    def execute(self, address: int, stack: int):
        self._bulk_write(struct.pack("<IIII", 8, address, stack, 0))

    def startup_core(self, logo: bytes, core: bytes, reconnect_timeout=15) -> None:
        """Upload logo+Core from the Loader stage, execute, and wait for the
        device to re-enumerate as Core. Re-opens the USB handle in place."""
        if self.core_type != 1:
            raise TransportError(
                f"startup_core() requires the Loader stage, got core_type={self.core_type}"
            )
        self._log(f"Uploading Core logo ({len(logo):,} bytes)...")
        self.write_memory(IBUGGER_LOGO_ADDRESS, logo)
        self._log(f"Uploading Core image ({len(core):,} bytes)...")
        self.write_memory(IBUGGER_CORE_ADDRESS, core)
        self._log("Executing Core...")
        self.execute(IBUGGER_CORE_ENTRY, IBUGGER_CORE_STACK)

        # Tear down this handle; the device is about to re-enumerate.
        self.winusb.WinUsb_Free(self.usb_handle)
        self.usb_handle = wintypes.HANDLE()
        self.kernel32.CloseHandle(self.handle)
        self.handle = None

        self._log("Waiting for device to re-enumerate as Core...")
        deadline = time.monotonic() + reconnect_timeout
        last_error = None
        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                self._open()
            except (DeviceNotFoundError, TransportError) as error:
                last_error = error
                continue
            if self.core_type == 2:
                self._log("Core is now running.")
                return
            last_error = TransportError(
                f"re-opened device reports core_type={self.core_type}, expected 2"
            )
            self.close()
        raise TransportError(f"Timed out waiting for Core to load: {last_error}")

    def run_crypto_payload(self, payload: bytes, input_data: bytes, timeout=180) -> bytes:
        """Upload the AES driver payload + data, execute, poll, download.

        This runs entirely in iPod RAM (0x08000000/0x08010000). Nothing is
        written to iPod NAND/NOR/flash storage.
        """
        if self.core_type != 2:
            raise TransportError(
                f"run_crypto_payload() requires Core, got core_type={self.core_type}"
            )
        if len(input_data) > 0x1FE0000:
            raise ValueError("iBugger crypto payload supports inputs up to 31 MiB")
        padded_size = (len(input_data) + 0x3F) & ~0x3F
        padded_input = input_data.ljust(padded_size, b"\0")

        self.get_state(2)  # STARTUP
        self._log(f"Uploading crypto payload ({len(payload):,} bytes)...")
        self.write_memory(IBUGGER_RAM_CODE, payload)
        self._log(f"Uploading input data ({len(padded_input):,} bytes)...")
        self.write_memory(IBUGGER_RAM_DATA, padded_input)
        self._log("Executing device-side AES operation...")
        self.execute(IBUGGER_RAM_ENTRY, IBUGGER_RAM_STACK)

        deadline = time.monotonic() + timeout
        while True:
            state = self.get_state(-1)
            if state[18] != 0:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting for device AES operation")
            time.sleep(0.25)

        self._log(f"Downloading result ({padded_size:,} bytes)...")
        return self.read_memory(IBUGGER_RAM_DATA, padded_size)[:len(input_data)]


# ============================================================
# Public helpers for embedding the patched binaries
# ============================================================
def get_loader_htm() -> bytes:
    """Return the 512-byte-patched loader.htm ready to stage in Notes."""
    return _blob(_LOADER_HTM_B64)


def get_core_bin() -> bytes:
    """Return the 512-byte-patched Core image."""
    return _blob(_CORE_BIN_B64)


def get_logo_bin() -> bytes:
    """Return the unmodified Core boot-splash image."""
    return _blob(_LOGO_BIN_B64)


def get_decryptfirmware_bin() -> bytes:
    """Return the historical device-side AES driver payload."""
    return _blob(_DECRYPTFW_BIN_B64)


def find_device() -> str | None:
    """Read-only check: return 'loader', 'core', or None.

    Deprecated in favor of find_device_status(), which distinguishes "not
    present at all" from "present, but WinUSB isn't bound to it" — the two
    have completely different fixes and this function's callers previously
    could not tell them apart. Kept for any other existing callers; new
    code should use find_device_status().
    """
    status, stage, _detail = find_device_status()
    return stage if status == "ok" else None


def find_device_status() -> tuple[str, str | None, str]:
    """Read-only check with a specific, actionable status.

    Returns (status, stage, detail):
      status="ok"                stage is "loader" or "core"
      status="not_present"       device not found at all (WinUSB or raw PnP)
      status="present_no_winusb" device enumerates, but WinUSB isn't bound
      status="error"             device/transport error after WinUSB opened
    """
    setupapi, _kernel32, _winusb = _load_apis()
    # _find_interface() itself now falls back to the well-known WinUSB
    # class GUID if this app's hardcoded per-install interface GUID isn't
    # found, so this already recovers on PCs where Zadig registered a
    # different (but equally valid) interface GUID.
    path = _find_interface(setupapi, IBUGGER_VID, IBUGGER_PID, IBUGGER_INTERFACE_GUID)
    if not path:
        presence = _ibugger_pnp_presence()
        if presence == "present_winusb_unrecognized_guid":
            return (
                "present_winusb_unrecognized_guid", None,
                "iPod is enumerating as Unified iBugger (VID_FFFF&PID_8642) "
                "and WinUSB IS correctly bound to it on this PC, but the "
                "device interface could not be opened. Try unplugging and "
                "reconnecting the iPod once, then check status again. If "
                "this persists, re-run Zadig's Install/Replace Driver step "
                "for this device."
            )
        if presence == "present_no_winusb":
            return (
                "present_no_winusb", None,
                "iPod is enumerating as Unified iBugger (VID_FFFF&PID_8642), "
                "but no WinUSB driver is bound to it on this PC. Open Zadig "
                "(enable Options > List All Devices if needed), select the "
                "VID_FFFF PID_8642 device, choose WinUSB, and click Install "
                "Driver/Replace Driver. This is a one-time per-PC step."
            )
        return (
            "not_present", None,
            "Unified iBugger (VID_FFFF&PID_8642) not found on this PC at "
            "all. Stage loader.htm in Notes, then eject/reconnect the iPod "
            "so it boots into iBugger, and try again."
        )
    try:
        with IBuggerTransport() as transport:
            stage = "core" if transport.core_type == 2 else "loader"
            return ("ok", stage, "")
    except (DeviceNotFoundError, TransportError) as exc:
        return ("error", None, str(exc))


def decrypt_partition(payload: bytes, raw_partition: bytes, log=None) -> bytes:
    """Full pipeline: connect to Core (loading it from Loader if needed),
    run the AES driver against raw_partition (header + encrypted body),
    return the decrypted header + body. Caller supplies the already-extracted
    exact partition range (0x800-byte header + directory-length body)."""
    log = log or (lambda _msg: None)
    with IBuggerTransport(log=log) as transport:
        if transport.core_type == 1:
            log("Device is Loader stage; loading Core...")
            transport.startup_core(get_logo_bin(), get_core_bin())
        elif transport.core_type != 2:
            raise TransportError(f"Unexpected core_type={transport.core_type}")
        return transport.run_crypto_payload(payload, raw_partition)
