"""Read-only Linux/libusb probe for the Nano 2G iBugger over WSL USB/IP.

Only GET INFO (opcode 1) and, after a valid identity, passive GET STATE
(opcode 0xA with -1) are sent. No upload, execute, restart, reset, memory,
storage, NAND, or NOR operation is present in this program.
"""

from __future__ import annotations

import argparse
import ctypes
import struct
import sys
from ctypes import POINTER, byref, c_int, c_ssize_t, c_ubyte, c_uint, c_void_p


VID = 0xFFFF
PID = 0x8642
OUT_ENDPOINT = 0x04
IN_ENDPOINT = 0x83
INTERFACE = 0
DEFAULT_TIMEOUT_MS = 5000


class USB_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("bLength", c_ubyte),
        ("bDescriptorType", c_ubyte),
        ("bcdUSB", ctypes.c_ushort),
        ("bDeviceClass", c_ubyte),
        ("bDeviceSubClass", c_ubyte),
        ("bDeviceProtocol", c_ubyte),
        ("bMaxPacketSize0", c_ubyte),
        ("idVendor", ctypes.c_ushort),
        ("idProduct", ctypes.c_ushort),
        ("bcdDevice", ctypes.c_ushort),
        ("iManufacturer", c_ubyte),
        ("iProduct", c_ubyte),
        ("iSerialNumber", c_ubyte),
        ("bNumConfigurations", c_ubyte),
    ]


class LibUSB:
    def __init__(self):
        self.lib = ctypes.CDLL("libusb-1.0.so.0")
        lib = self.lib
        lib.libusb_init.argtypes = [POINTER(c_void_p)]
        lib.libusb_init.restype = c_int
        lib.libusb_exit.argtypes = [c_void_p]
        lib.libusb_exit.restype = None
        lib.libusb_get_device_list.argtypes = [c_void_p, POINTER(POINTER(c_void_p))]
        lib.libusb_get_device_list.restype = c_ssize_t
        lib.libusb_free_device_list.argtypes = [POINTER(c_void_p), c_int]
        lib.libusb_free_device_list.restype = None
        lib.libusb_get_device_descriptor.argtypes = [
            c_void_p,
            POINTER(USB_DEVICE_DESCRIPTOR),
        ]
        lib.libusb_get_device_descriptor.restype = c_int
        lib.libusb_get_device_speed.argtypes = [c_void_p]
        lib.libusb_get_device_speed.restype = c_int
        lib.libusb_open.argtypes = [c_void_p, POINTER(c_void_p)]
        lib.libusb_open.restype = c_int
        lib.libusb_set_configuration.argtypes = [c_void_p, c_int]
        lib.libusb_set_configuration.restype = c_int
        lib.libusb_close.argtypes = [c_void_p]
        lib.libusb_close.restype = None
        lib.libusb_set_auto_detach_kernel_driver.argtypes = [c_void_p, c_int]
        lib.libusb_set_auto_detach_kernel_driver.restype = c_int
        lib.libusb_claim_interface.argtypes = [c_void_p, c_int]
        lib.libusb_claim_interface.restype = c_int
        lib.libusb_release_interface.argtypes = [c_void_p, c_int]
        lib.libusb_release_interface.restype = c_int
        lib.libusb_bulk_transfer.argtypes = [
            c_void_p,
            c_ubyte,
            POINTER(c_ubyte),
            c_int,
            POINTER(c_int),
            c_uint,
        ]
        lib.libusb_bulk_transfer.restype = c_int
        lib.libusb_error_name.argtypes = [c_int]
        lib.libusb_error_name.restype = ctypes.c_char_p

    def error(self, code):
        name = self.lib.libusb_error_name(code)
        return f"{code} ({name.decode() if name else 'unknown'})"


def command_packet(opcode, second=0, third=0, fourth=0, wire_size=16):
    command = struct.pack("<IiII", opcode, second, third, fourth)
    if wire_size < len(command):
        raise ValueError("wire size must be at least 16 bytes")
    return command.ljust(wire_size, b"\0")


def bulk_transfer(api, handle, endpoint, payload, timeout_ms):
    if isinstance(payload, int):
        length = payload
        buffer = (c_ubyte * length)()
    else:
        length = len(payload)
        buffer = (c_ubyte * length).from_buffer_copy(payload)
    transferred = c_int()
    rc = api.lib.libusb_bulk_transfer(
        handle,
        endpoint,
        buffer,
        length,
        byref(transferred),
        timeout_ms,
    )
    if rc != 0:
        raise RuntimeError(
            f"bulk endpoint 0x{endpoint:02x} length {length} failed: "
            f"{api.error(rc)}"
        )
    return bytes(buffer[: transferred.value])


def find_device(api, context):
    devices = POINTER(c_void_p)()
    count = api.lib.libusb_get_device_list(context, byref(devices))
    if count < 0:
        raise RuntimeError(f"libusb_get_device_list failed: {api.error(count)}")
    try:
        for index in range(count):
            device = devices[index]
            descriptor = USB_DEVICE_DESCRIPTOR()
            rc = api.lib.libusb_get_device_descriptor(device, byref(descriptor))
            if rc != 0:
                continue
            if descriptor.idVendor == VID and descriptor.idProduct == PID:
                return device, descriptor, api.lib.libusb_get_device_speed(device)
    finally:
        # The opened handle retains the device reference after this list is freed.
        api.lib.libusb_free_device_list(devices, 0)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wire-size",
        type=int,
        choices=(16, 512, 528),
        default=528,
        help="OUT command size to test (default: 528)",
    )
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    args = parser.parse_args()

    api = LibUSB()
    context = c_void_p()
    rc = api.lib.libusb_init(byref(context))
    if rc != 0:
        raise RuntimeError(f"libusb_init failed: {api.error(rc)}")

    handle = c_void_p()
    claimed = False
    try:
        found = find_device(api, context)
        if found is None:
            print(f"No Linux USB device {VID:04x}:{PID:04x} found")
            return 2
        device, descriptor, speed = found
        print(
            f"device={descriptor.idVendor:04x}:{descriptor.idProduct:04x} "
            f"usb_bcd=0x{descriptor.bcdUSB:04x} ep0_max={descriptor.bMaxPacketSize0} "
            f"speed_code={speed}"
        )

        rc = api.lib.libusb_open(device, byref(handle))
        if rc != 0:
            raise RuntimeError(f"libusb_open failed: {api.error(rc)}")
        rc = api.lib.libusb_set_configuration(handle, 1)
        if rc not in (0, -6):  # -6 means the kernel already owns configuration 1.
            raise RuntimeError(f"libusb_set_configuration failed: {api.error(rc)}")
        # WSL's vhci device normally has no competing kernel interface.  A
        # positive return here is informational; claim is the required step.
        api.lib.libusb_set_auto_detach_kernel_driver(handle, 1)
        rc = api.lib.libusb_claim_interface(handle, INTERFACE)
        if rc != 0:
            raise RuntimeError(f"libusb_claim_interface failed: {api.error(rc)}")
        claimed = True

        identity_request = command_packet(1, wire_size=args.wire_size)
        print(f"identity_out_length={len(identity_request)}")
        bulk_transfer(api, handle, OUT_ENDPOINT, identity_request, args.timeout_ms)
        identity = bulk_transfer(api, handle, IN_ENDPOINT, 16, args.timeout_ms)
        print(f"identity_in_length={len(identity)} data={identity.hex()}")
        if len(identity) != 16:
            raise RuntimeError("identity response was not exactly 16 bytes")

        major, minor, revision, core_type, device_type, max_out, max_in, reserved = struct.unpack(
            "<BBBBIHHI", identity
        )
        print(
            f"identity=v{major}.{minor}.{revision} core_type={core_type + 1} "
            f"device_type={device_type} advertised_out={max_out} "
            f"advertised_in={max_in} reserved=0x{reserved:08x}"
        )
        # Real Nano 2G hardware has been observed returning a non-zero value
        # in this word (e.g. 0x00005ac0). The historical libibugger.py never
        # validates it either, so it is treated as informational only.

        state_request = command_packet(0xA, second=-1, wire_size=args.wire_size)
        bulk_transfer(api, handle, OUT_ENDPOINT, state_request, args.timeout_ms)
        state_response = bulk_transfer(api, handle, IN_ENDPOINT, 0x5C, args.timeout_ms)
        if len(state_response) != 0x5C:
            raise RuntimeError("state response was not exactly 92 bytes")
        status = struct.unpack_from("<I", state_response)[0]
        state = struct.unpack_from("<19I", state_response, 0x10)
        print(f"state_status={status}")
        print("state_words=" + ",".join(f"0x{word:08x}" for word in state))
        print(f"passive_target_state=0x{state[18]:08x}")
        return 0
    finally:
        if handle:
            if claimed:
                api.lib.libusb_release_interface(handle, INTERFACE)
            api.lib.libusb_close(handle)
        api.lib.libusb_exit(context)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"probe_error={error}")
        sys.exit(1)
