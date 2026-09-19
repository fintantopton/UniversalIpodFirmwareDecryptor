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


def _find_interface(setupapi, vid, pid, interface_guid):
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
                return path
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)
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
            raise DeviceNotFoundError(
                "Unified iBugger (VID_FFFF&PID_8642) not found. "
                "Stage loader.htm in Notes and eject/reconnect the iPod."
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
    """Read-only check: return 'loader', 'core', or None."""
    setupapi, _kernel32, _winusb = _load_apis()
    path = _find_interface(setupapi, IBUGGER_VID, IBUGGER_PID, IBUGGER_INTERFACE_GUID)
    if not path:
        return None
    try:
        with IBuggerTransport() as transport:
            return "core" if transport.core_type == 2 else "loader"
    except (DeviceNotFoundError, TransportError):
        return None


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
