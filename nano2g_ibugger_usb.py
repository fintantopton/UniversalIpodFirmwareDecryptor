"""Cross-platform (macOS/Linux) libusb transport for the Nano 2G iBugger.

Implements the exact same USB protocol as the Windows WinUSB transport in
``nano2g_device_decrypt.py`` (see the research doc referenced there), but
over libusb-1.0 via ctypes — so the Nano 2G hardware-AES decrypt path works
on macOS (Apple Silicon and Intel) and Linux with no extra Python
dependencies.

Device: Unified iBugger, VID 0xFFFF, PID 0x8642, interface 0,
OUT endpoint 0x04, IN endpoint 0x83, 512-byte wire packets.

Everything stays RAM-resident on the iPod: nothing is written to NAND,
NOR or flash storage.

libusb is located (in order):
  1. $IPOD_LIBUSB_PATH
  2. a bundled libusb-1.0.dylib / libusb-1.0.so (next to the app, in the
     .app Resources dir, or in vendor/)
  3. the system default (Homebrew's keg or /usr/lib)
"""

from __future__ import annotations

import ctypes
import os
import struct
import time
import ipod_platform as plat
import nano2g_device_decrypt as _wintransport  # for get_*_bin() helpers

IBUGGER_VID = 0xFFFF
IBUGGER_PID = 0x8642
IBUGGER_OUT_ENDPOINT = 0x04
IBUGGER_IN_ENDPOINT = 0x83
IBUGGER_INTERFACE = 0
IBUGGER_WIRE_PACKET_SIZE = 512
IBUGGER_BULK_TIMEOUT_MS = 5000

IBUGGER_LOGO_ADDRESS = 0x22000020
IBUGGER_CORE_ADDRESS = 0x22000000
IBUGGER_CORE_ENTRY = 0x22000020
IBUGGER_CORE_STACK = 0x0A000000

IBUGGER_RAM_CODE = 0x08000000
IBUGGER_RAM_ENTRY = IBUGGER_RAM_CODE + 0x20
IBUGGER_RAM_DATA = 0x08010000
IBUGGER_RAM_STACK = IBUGGER_RAM_DATA


class DeviceNotFoundError(RuntimeError):
    pass


class TransportError(RuntimeError):
    pass


class LibusbError(TransportError):
    pass


# ============================================================
# libusb-1.0 ctypes bindings (only what we use)
# ============================================================

def _load_libusb() -> ctypes.CDLL:
    candidates = []
    env_path = os.environ.get("IPOD_LIBUSB_PATH")
    if env_path:
        candidates.append(env_path)
    bundled = plat.find_libusb()
    if bundled:
        candidates.append(bundled)
    candidates.append("libusb-1.0.dylib")
    candidates.append("libusb-1.0.so")
    candidates.append("libusb-1.0.0.dylib")
    candidates.append("libusb-1.0.so.0")
    candidates.append("libusb.so.0")
    last_error = ""
    for candidate in candidates:
        try:
            return ctypes.CDLL(candidate)
        except OSError as exc:
            last_error = str(exc)
    raise TransportError(
        "Could not load libusb-1.0 (" + last_error + ").\n"
        "On macOS install it with: brew install libusb\n"
        "Or set IPOD_LIBUSB_PATH=/path/to/libusb-1.0.dylib"
    )


class _Libusb:
    """Thin wrapper around the handful of libusb-1.0 calls we need."""

    def __init__(self):
        self.lib = _load_libusb()
        lib = self.lib

        lib.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.libusb_init.restype = ctypes.c_int
        lib.libusb_exit.argtypes = [ctypes.c_void_p]
        lib.libusb_open_device_with_vid_pid.argtypes = [
            ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16
        ]
        lib.libusb_open_device_with_vid_pid.restype = ctypes.c_void_p
        lib.libusb_kernel_driver_active.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_kernel_driver_active.restype = ctypes.c_int
        lib.libusb_detach_kernel_driver.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_detach_kernel_driver.restype = ctypes.c_int
        lib.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_claim_interface.restype = ctypes.c_int
        lib.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.libusb_release_interface.restype = ctypes.c_int
        lib.libusb_close.argtypes = [ctypes.c_void_p]
        lib.libusb_bulk_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_ubyte,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
        ]
        lib.libusb_bulk_transfer.restype = ctypes.c_int
        lib.libusb_strerror.argtypes = [ctypes.c_int]
        lib.libusb_strerror.restype = ctypes.c_char_p

        self.ctx = ctypes.c_void_p()
        rc = lib.libusb_init(ctypes.byref(self.ctx))
        if rc != 0:
            raise TransportError(self._err(rc, "libusb_init"))

    def _err(self, rc, context):
        try:
            text = self.lib.libusb_strerror(rc).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = "unknown"
        return f"{context} failed ({rc}): {text}"

    def close(self):
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = None

    def open(self, vid, pid):
        handle = self.lib.libusb_open_device_with_vid_pid(
            self.ctx, vid, pid)
        if not handle:
            raise DeviceNotFoundError(
                "Unified iBugger (VID_FFFF&PID_8642) not found. Stage "
                "loader.htm in Notes, then eject/reconnect the iPod so it "
                "boots into iBugger, and try again."
            )
        return handle

    def claim(self, handle):
        active = self.lib.libusb_kernel_driver_active(
            handle, IBUGGER_INTERFACE)
        if active == 1:
            self.lib.libusb_detach_kernel_driver(handle, IBUGGER_INTERFACE)
        rc = self.lib.libusb_claim_interface(handle, IBUGGER_INTERFACE)
        if rc != 0:
            self.lib.libusb_close(handle)
            raise TransportError(
                self._err(rc, "claim_interface") +
                ". If the iPod DFU/iPod interface is held by Apple's "
                "software, release it (Prerequisites panel) or try a "
                "different USB port."
            )

    def release(self, handle):
        if not handle:
            return
        self.lib.libusb_release_interface(handle, IBUGGER_INTERFACE)
        self.lib.libusb_close(handle)

    def bulk(self, handle, endpoint, data, size, timeout_ms):
        if endpoint & 0x80:  # IN
            buffer = (ctypes.c_ubyte * size)()
        else:
            buffer = (ctypes.c_ubyte * size).from_buffer_copy(data)
        transferred = ctypes.c_int(0)
        rc = self.lib.libusb_bulk_transfer(
            handle, endpoint & 0xFF, buffer, size,
            ctypes.byref(transferred), timeout_ms,
        )
        if rc != 0:
            raise TransportError(self._err(rc, "bulk_transfer"))
        if endpoint & 0x80:
            return bytes(buffer[:transferred.value])
        return transferred.value


# ============================================================
# iBugger transport (same protocol as the WinUSB transport)
# ============================================================

class IBuggerUSBTransport:
    """libusb transport for the patched Nano 2G iBugger Loader/Core."""

    def __init__(self, log=None):
        self._log = log or (lambda _msg: None)
        self._usb = _Libusb()
        self.handle = None
        self.version = None
        self.core_type = None  # 1 = Loader, 2 = Core
        self.device_type = None
        self._open()

    # ---- lifecycle -------------------------------------------------
    def _open(self):
        handle = self._usb.open(IBUGGER_VID, IBUGGER_PID)
        try:
            self._usb.claim(handle)
        except TransportError:
            self._usb.release(handle)
            raise
        self.handle = handle
        self._read_identity()

    def close(self):
        if self.handle:
            self._usb.release(self.handle)
            self.handle = None
        self._usb.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # ---- low-level --------------------------------------------------
    def _bulk_write(self, data: bytes):
        transferred = self._usb.bulk(
            self.handle, IBUGGER_OUT_ENDPOINT, data, len(data),
            IBUGGER_BULK_TIMEOUT_MS)
        if transferred != len(data):
            raise TransportError(f"short write: {transferred} of {len(data)} bytes")

    def _bulk_read(self, size: int) -> bytes:
        data = self._usb.bulk(
            self.handle, IBUGGER_IN_ENDPOINT, b"", size,
            IBUGGER_BULK_TIMEOUT_MS)
        if len(data) < size:
            raise TransportError(
                f"short read: {len(data)} of {size} bytes (endpoint 0x83). "
                "The device may have re-enumerated; retry the operation."
            )
        return data

    def _read_status(self):
        return self._bulk_read(0x10)

    @staticmethod
    def _check_status(data: bytes):
        if len(data) < 4:
            raise TransportError(f"short iBugger status response: {data.hex()}")
        error_code = struct.unpack_from("<I", data)[0]
        if error_code != 1:
            raise TransportError(f"iBugger operation failed with status {error_code}")

    # ---- protocol (identical to the WinUSB transport) ---------------
    def _read_identity(self):
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

        self._usb.release(self.handle)
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
            # close() tore down the libusb context too; recreate it.
            self._usb = _Libusb()
        raise TransportError(f"Timed out waiting for Core to load: {last_error}")

    def run_crypto_payload(self, payload: bytes, input_data: bytes, timeout=180) -> bytes:
        """Upload the AES driver payload + data, execute, poll, download.

        Runs entirely in iPod RAM (0x08000000/0x08010000). Nothing is
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
# Public helpers (same surface as nano2g_device_decrypt for the app)
# ============================================================

def get_loader_htm() -> bytes:
    return _wintransport.get_loader_htm()


def get_core_bin() -> bytes:
    return _wintransport.get_core_bin()


def get_logo_bin() -> bytes:
    return _wintransport.get_logo_bin()


def get_decryptfirmware_bin() -> bytes:
    return _wintransport.get_decryptfirmware_bin()


def find_device_status() -> tuple[str, str | None, str]:
    """Read-only check. Returns (status, stage, detail) with the same
    status values as the WinUSB transport (status values that only make
    sense on Windows are not produced here)."""
    if not plat.find_ibugger_device()[0]:
        return (
            "not_present", None,
            "Unified iBugger (VID_FFFF&PID_8642) not found. Stage "
            "loader.htm in Notes, then eject/reconnect the iPod so it "
            "boots into iBugger, and try again."
        )
    try:
        transport = IBuggerUSBTransport()
    except DeviceNotFoundError as exc:
        return ("not_present", None, str(exc))
    except TransportError as exc:
        return ("error", None, str(exc))
    except Exception as exc:  # noqa: BLE001
        return ("error", None, f"libusb transport failed: {exc}")
    try:
        stage = "core" if transport.core_type == 2 else "loader"
        return ("ok", stage, "")
    finally:
        transport.close()
