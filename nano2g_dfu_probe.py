"""Read-only WinUSB probe for an iPod Nano 2G software-DFU device.

This tool deliberately issues only USB descriptor reads and standard DFU
GETSTATUS/GETSTATE class requests. It does not upload, download, erase,
execute, exploit, or restore firmware.
"""

from __future__ import annotations

import ctypes
import re
import sys
import uuid
from ctypes import wintypes


VID = 0x05AC
PID = 0x1240
DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010
ERROR_NO_MORE_ITEMS = 259
ERROR_INSUFFICIENT_BUFFER = 122
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_ATTRIBUTE_NORMAL = 0x00000080

# GUID_DEVINTERFACE_USB_DEVICE
USB_DEVICE_INTERFACE_GUID = uuid.UUID("a5dcbf10-6530-11d2-901f-00c04fb951ed")


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


class WINUSB_SETUP_PACKET(ctypes.Structure):
    _fields_ = [
        ("RequestType", ctypes.c_ubyte),
        ("Request", ctypes.c_ubyte),
        ("Value", wintypes.WORD),
        ("Index", wintypes.WORD),
        ("Length", wintypes.WORD),
    ]


class USB_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_ubyte),
        ("bDescriptorType", ctypes.c_ubyte),
        ("bcdUSB", wintypes.WORD),
        ("bDeviceClass", ctypes.c_ubyte),
        ("bDeviceSubClass", ctypes.c_ubyte),
        ("bDeviceProtocol", ctypes.c_ubyte),
        ("bMaxPacketSize0", ctypes.c_ubyte),
        ("idVendor", wintypes.WORD),
        ("idProduct", wintypes.WORD),
        ("bcdDevice", wintypes.WORD),
        ("iManufacturer", ctypes.c_ubyte),
        ("iProduct", ctypes.c_ubyte),
        ("iSerialNumber", ctypes.c_ubyte),
        ("bNumConfigurations", ctypes.c_ubyte),
    ]


def guid_from_uuid(value: uuid.UUID) -> GUID:
    raw = value.bytes_le
    result = GUID()
    ctypes.memmove(ctypes.byref(result), raw, len(raw))
    return result


def last_error_text():
    error = ctypes.get_last_error()
    return f"Win32 error {error}: {ctypes.FormatError(error)}"


def load_apis():
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

    winusb.WinUsb_Initialize.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE)]
    winusb.WinUsb_Initialize.restype = wintypes.BOOL
    winusb.WinUsb_Free.argtypes = [wintypes.HANDLE]
    winusb.WinUsb_Free.restype = wintypes.BOOL
    winusb.WinUsb_QueryInterfaceSettings.argtypes = [
        wintypes.HANDLE, ctypes.c_ubyte, ctypes.POINTER(USB_INTERFACE_DESCRIPTOR)
    ]
    winusb.WinUsb_QueryInterfaceSettings.restype = wintypes.BOOL
    winusb.WinUsb_ControlTransfer.argtypes = [
        wintypes.HANDLE, WINUSB_SETUP_PACKET, ctypes.POINTER(ctypes.c_ubyte),
        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), ctypes.c_void_p
    ]
    winusb.WinUsb_ControlTransfer.restype = wintypes.BOOL
    return setupapi, kernel32, winusb


def find_interface(setupapi):
    guid = guid_from_uuid(USB_DEVICE_INTERFACE_GUID)
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
                info_set, ctypes.byref(interface), detail, required.value,
                ctypes.byref(required), None
            ):
                continue
            path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
            if re.search(rf"vid_{VID:04x}&pid_{PID:04x}", path, re.IGNORECASE):
                return path
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info_set)
    return None


def control_transfer(winusb, handle, request_type, request, value, index, length):
    setup = WINUSB_SETUP_PACKET(request_type, request, value, index, length)
    buffer = (ctypes.c_ubyte * length)()
    transferred = wintypes.ULONG()
    ok = winusb.WinUsb_ControlTransfer(
        handle, setup, buffer, length, ctypes.byref(transferred), None
    )
    if not ok:
        return None, last_error_text()
    return bytes(buffer[:transferred.value]), None


def main():
    setupapi, kernel32, winusb = load_apis()
    path = find_interface(setupapi)
    if not path:
        print(f"No present USB interface found for VID_{VID:04X}&PID_{PID:04X}")
        return 2
    print("device_interface_path=", path)

    handle = kernel32.CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None
    )
    if handle == INVALID_HANDLE_VALUE:
        handle = kernel32.CreateFileW(
            path, 0, 0, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None
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
        if winusb.WinUsb_QueryInterfaceSettings(usb_handle, 0, ctypes.byref(descriptor)):
            print(
                "interface=", descriptor.bInterfaceNumber,
                "alt=", descriptor.bAlternateSetting,
                "class=0x%02x" % descriptor.bInterfaceClass,
                "subclass=0x%02x" % descriptor.bInterfaceSubClass,
                "protocol=0x%02x" % descriptor.bInterfaceProtocol,
                "endpoints=", descriptor.bNumEndpoints,
            )
        else:
            print("WinUsb_QueryInterfaceSettings failed:", last_error_text())
            return 5

        # Standard USB device descriptor read. This is read-only.
        device_bytes, error = control_transfer(
            winusb, usb_handle, 0x80, 0x06, 0x0100, 0, ctypes.sizeof(USB_DEVICE_DESCRIPTOR)
        )
        if device_bytes is not None and len(device_bytes) >= ctypes.sizeof(USB_DEVICE_DESCRIPTOR):
            device = USB_DEVICE_DESCRIPTOR.from_buffer_copy(device_bytes)
            print(
                "device_descriptor=vendor:0x%04x product:0x%04x bcdDevice:0x%04x "
                "class:0x%02x subclass:0x%02x protocol:0x%02x maxPacket0:%d" % (
                    device.idVendor, device.idProduct, device.bcdDevice,
                    device.bDeviceClass, device.bDeviceSubClass, device.bDeviceProtocol,
                    device.bMaxPacketSize0,
                )
            )
            print(
                "string_indexes=manufacturer:%d product:%d serial:%d configurations:%d" % (
                    device.iManufacturer, device.iProduct, device.iSerialNumber,
                    device.bNumConfigurations,
                )
            )
        else:
            print("device_descriptor_error=", error)

        # USB DFU class requests: GETSTATUS and GETSTATE. Both are read-only.
        interface_number = descriptor.bInterfaceNumber
        status, error = control_transfer(
            winusb, usb_handle, 0xA1, 0x03, 0, interface_number, 6
        )
        if status is not None:
            print("dfu_getstatus=", status.hex(), "length=", len(status))
        else:
            print("dfu_getstatus_error=", error)

        state, error = control_transfer(
            winusb, usb_handle, 0xA1, 0x05, 0, interface_number, 1
        )
        if state is not None:
            print("dfu_getstate=", state.hex(), "length=", len(state))
        else:
            print("dfu_getstate_error=", error)
        return 0
    finally:
        if usb_handle:
            winusb.WinUsb_Free(usb_handle)
        kernel32.CloseHandle(handle)


if __name__ == "__main__":
    sys.exit(main())
