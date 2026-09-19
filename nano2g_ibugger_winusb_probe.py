"""Read-only native WinUSB probe for an already-loaded Nano 2G iBugger.

This probe sends only the historical identity request and passive state query.
It does not upload, execute, reset, restart, or access iPod storage.  It uses
WinUSB directly to avoid libusb backends returning stale host-buffer contents
for the loader's nonstandard endpoint configuration.
"""

from __future__ import annotations

import ctypes
import re
import struct
import sys
import uuid
from ctypes import wintypes

from nano2g_dfu_probe import (
    DIGCF_DEVICEINTERFACE,
    DIGCF_PRESENT,
    ERROR_NO_MORE_ITEMS,
    FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_OVERLAPPED,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    GENERIC_READ,
    GENERIC_WRITE,
    GUID,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
    SP_DEVICE_INTERFACE_DATA,
    USB_DEVICE_INTERFACE_GUID,
    guid_from_uuid,
    last_error_text,
    load_apis,
)


VID = 0xFFFF
PID = 0x8642
IBUGGER_OUT_ENDPOINT = 0x04
IBUGGER_IN_ENDPOINT = 0x83
IBUGGER_INTERFACE = 0
IBUGGER_INTERFACE_GUID = uuid.UUID("8bcdb266-e477-4545-b94c-8ee8fbe21bd8")
IBUGGER_WIRE_PACKET_SIZE = 528
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
BULK_TIMEOUT_MS = 5000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
BULK_TIMEOUT_MS = 5000


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


class WINUSB_PIPE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PipeType", wintypes.ULONG),
        ("PipeId", ctypes.c_ubyte),
        ("MaximumPacketSize", wintypes.USHORT),
        ("Interval", ctypes.c_ubyte),
        ("_padding", ctypes.c_ubyte * 3),
        ("MaximumBytesPerInterval", wintypes.ULONG),
    ]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def find_interface(setupapi):
    guid = guid_from_uuid(IBUGGER_INTERFACE_GUID)
    info_set = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    )
    if info_set == INVALID_HANDLE_VALUE:
        raise OSError(last_error_text())
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
                info_set,
                ctypes.byref(interface),
                detail,
                required.value,
                ctypes.byref(required),
                None,
            ):
                continue
            path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
            if re.search(rf"vid_{VID:04x}&pid_{PID:04x}", path, re.IGNORECASE):
                return path
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)
    return None


def configure_bulk_apis(winusb, kernel32):
    winusb.WinUsb_Initialize.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    winusb.WinUsb_Initialize.restype = wintypes.BOOL
    winusb.WinUsb_Free.argtypes = [wintypes.HANDLE]
    winusb.WinUsb_Free.restype = wintypes.BOOL
    winusb.WinUsb_QueryInterfaceSettings.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ubyte,
        ctypes.POINTER(USB_INTERFACE_DESCRIPTOR),
    ]
    winusb.WinUsb_QueryInterfaceSettings.restype = wintypes.BOOL
    winusb.WinUsb_QueryPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ubyte,
        ctypes.c_ubyte,
        ctypes.POINTER(WINUSB_PIPE_INFORMATION),
    ]
    winusb.WinUsb_QueryPipe.restype = wintypes.BOOL
    winusb.WinUsb_WritePipe.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ubyte,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(OVERLAPPED),
    ]
    winusb.WinUsb_WritePipe.restype = wintypes.BOOL
    winusb.WinUsb_ReadPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ubyte,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(OVERLAPPED),
    ]
    winusb.WinUsb_ReadPipe.restype = wintypes.BOOL

    kernel32.CreateEventW.argtypes = [
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
    ]
    kernel32.GetOverlappedResult.restype = wintypes.BOOL


def _bulk_transfer(kernel32, winusb, file_handle, usb_handle, endpoint, buffer, size):
    event = kernel32.CreateEventW(None, True, False, None)
    if not event:
        raise OSError(last_error_text())
    overlapped = OVERLAPPED()
    overlapped.hEvent = event
    transferred = wintypes.ULONG()
    try:
        if endpoint & 0x80:
            ok = winusb.WinUsb_ReadPipe(
                usb_handle,
                endpoint,
                buffer,
                size,
                ctypes.byref(transferred),
                ctypes.byref(overlapped),
            )
        else:
            ok = winusb.WinUsb_WritePipe(
                usb_handle,
                endpoint,
                buffer,
                size,
                ctypes.byref(transferred),
                ctypes.byref(overlapped),
            )
        if not ok and ctypes.get_last_error() != ERROR_IO_PENDING:
            raise OSError(last_error_text())
        if not ok:
            wait_result = kernel32.WaitForSingleObject(event, BULK_TIMEOUT_MS)
            if wait_result == WAIT_TIMEOUT:
                raise TimeoutError(
                    f"WinUSB endpoint 0x{endpoint:02x} timed out after "
                    f"{BULK_TIMEOUT_MS} ms"
                )
            if wait_result != WAIT_OBJECT_0:
                raise OSError(last_error_text())
            if not kernel32.GetOverlappedResult(
                file_handle, ctypes.byref(overlapped), ctypes.byref(transferred), False
            ):
                raise OSError(last_error_text())
        return transferred.value
    finally:
        kernel32.CloseHandle(event)


def pad_command(command):
    if len(command) > IBUGGER_WIRE_PACKET_SIZE:
        raise ValueError("iBugger command exceeds the 528-byte wire packet")
    return command.ljust(IBUGGER_WIRE_PACKET_SIZE, b"\0")


def bulk_write(kernel32, winusb, file_handle, usb_handle, endpoint, data):
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    transferred = _bulk_transfer(
        kernel32, winusb, file_handle, usb_handle, endpoint, buffer, len(data)
    )
    if transferred != len(data):
        raise RuntimeError(f"Short WinUSB write: {transferred} of {len(data)} bytes")


def bulk_read(kernel32, winusb, file_handle, usb_handle, endpoint, size):
    buffer = (ctypes.c_ubyte * size)()
    transferred = _bulk_transfer(
        kernel32, winusb, file_handle, usb_handle, endpoint, buffer, size
    )
    return bytes(buffer[:transferred])


def main():
    setupapi, kernel32, winusb = load_apis()
    configure_bulk_apis(winusb, kernel32)
    path = find_interface(setupapi)
    if not path:
        print(f"No present WinUSB interface found for VID_{VID:04X}&PID_{PID:04X}")
        return 2
    print("device_interface_path=", path)

    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        handle = kernel32.CreateFileW(
            path,
            0,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
    if handle == INVALID_HANDLE_VALUE:
        print("CreateFile failed:", last_error_text())
        return 3

    usb_handle = wintypes.HANDLE()
    try:
        if not winusb.WinUsb_Initialize(handle, ctypes.byref(usb_handle)):
            print("WinUsb_Initialize failed:", last_error_text())
            return 4

        descriptor = USB_INTERFACE_DESCRIPTOR()
        if not winusb.WinUsb_QueryInterfaceSettings(
            usb_handle, IBUGGER_INTERFACE, ctypes.byref(descriptor)
        ):
            print("WinUsb_QueryInterfaceSettings failed:", last_error_text())
            return 5
        print(
            "interface=", descriptor.bInterfaceNumber,
            "endpoints=", descriptor.bNumEndpoints,
        )

        for pipe_index in range(descriptor.bNumEndpoints):
            pipe = WINUSB_PIPE_INFORMATION()
            if not winusb.WinUsb_QueryPipe(
                usb_handle, IBUGGER_INTERFACE, pipe_index, ctypes.byref(pipe)
            ):
                print(f"pipe_index_{pipe_index}_query_error=", last_error_text())
            else:
                print(
                    f"pipe_index_{pipe_index}=endpoint:0x{pipe.PipeId:02x} "
                    f"type:{pipe.PipeType} max_packet:{pipe.MaximumPacketSize}"
                )

        # Identity is a direct 16-byte metadata response, not a status packet.
        bulk_write(
            kernel32,
            winusb,
            handle,
            usb_handle,
            IBUGGER_OUT_ENDPOINT,
            pad_command(struct.pack("<IIII", 1, 0, 0, 0)),
        )
        identity = bulk_read(
            kernel32, winusb, handle, usb_handle, IBUGGER_IN_ENDPOINT, 16
        )
        if len(identity) != 16:
            raise RuntimeError(f"Unexpected identity length: {len(identity)}")
        major, minor, revision, core_type, device_type, max_out, max_in, reserved = struct.unpack(
            "<BBBBIHHI", identity
        )
        print(
            f"identity=v{major}.{minor}.{revision} core_type={core_type + 1} "
            f"device_type={device_type} advertised_out={max_out} "
            f"advertised_in={max_in} reserved=0x{reserved:08x}"
        )

        # PING (opcode 0) is supported by both Loader and Core and replies
        # with a 16-byte success status (error code 1, then zeros).
        bulk_write(
            kernel32,
            winusb,
            handle,
            usb_handle,
            IBUGGER_OUT_ENDPOINT,
            pad_command(struct.pack("<IIII", 0, 0, 0, 0)),
        )
        ping_response = bulk_read(
            kernel32, winusb, handle, usb_handle, IBUGGER_IN_ENDPOINT, 16
        )
        if len(ping_response) != 16:
            raise RuntimeError(f"Unexpected PING response length: {len(ping_response)}")
        ping_status = struct.unpack_from("<I", ping_response)[0]
        print(f"ping_response={ping_response.hex()} status={ping_status}")
        if ping_status != 1:
            raise RuntimeError(f"PING returned non-success status {ping_status}")

        if core_type + 1 != 2:
            # GETSTATE (opcode 0xA) is a Core-only command. The Loader stage
            # replies to it with a 16-byte "unsupported function" status
            # (error code 2), not a 92-byte state block. Skip it here rather
            # than reporting a false transport failure.
            print(
                "skipping passive GETSTATE: device is the Loader stage "
                "(Core-only opcode)"
            )
            return 0

        # -1 is the passive state query; 2 would request STARTUP and is not used.
        bulk_write(
            kernel32,
            winusb,
            handle,
            usb_handle,
            IBUGGER_OUT_ENDPOINT,
            pad_command(struct.pack("<IiII", 0xA, -1, 0, 0)),
        )
        state_response = bulk_read(
            kernel32, winusb, handle, usb_handle, IBUGGER_IN_ENDPOINT, 0x5C
        )
        if len(state_response) != 0x5C:
            raise RuntimeError(
                f"Unexpected state response length: {len(state_response)}"
            )
        status = struct.unpack_from("<I", state_response)[0]
        state = struct.unpack_from("<19I", state_response, 0x10)
        print(f"state_status={status}")
        print("state_words=" + ",".join(f"0x{word:08x}" for word in state))
        print(f"passive_target_state=0x{state[18]:08x}")
        return 0
    except (OSError, RuntimeError) as error:
        print("probe_error=", error)
        return 6
    finally:
        if usb_handle:
            winusb.WinUsb_Free(usb_handle)
        kernel32.CloseHandle(handle)


if __name__ == "__main__":
    sys.exit(main())
