"""Python 3 host for the historical Nano 2G iBugger crypto service.

This tool does not write iPod storage. It communicates with an already-loaded
*iBugger Core* (VID 0xffff, PID 0x8642), uploads a bundled device-side crypto
payload into RAM, executes it, and downloads the result. Loading iBugger Core
itself still requires the historical Notes loader and is intentionally a
separate, user-visible step.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from pathlib import Path

import usb.core
import usb.util
import usb.backend.libusb1


IBUGGER_VID = 0xFFFF
IBUGGER_PID = 0x8642
IBUGGER_OUT_ENDPOINT = 0x04
IBUGGER_IN_ENDPOINT = 0x83
IBUGGER_INTERFACE = 0
IBUGGER_MAX_TRANSFER = 512
IBUGGER_RAM_CODE = 0x08000000
IBUGGER_RAM_ENTRY = IBUGGER_RAM_CODE + 0x20
IBUGGER_RAM_DATA = 0x08010000
IBUGGER_RAM_STACK = IBUGGER_RAM_DATA

# Core-loading sequence, mirrors libibugger.py's startup() for device_type=2
# (Nano 2G). The logo is uploaded first purely for on-screen feedback, then
# the Core image is uploaded starting 0x20 bytes earlier, overwriting the
# logo in RAM. Core's entry point is base+0x20 (past its vector table).
IBUGGER_LOGO_ADDRESS = 0x22000020
IBUGGER_CORE_ADDRESS = 0x22000000
IBUGGER_CORE_ENTRY = 0x22000020
IBUGGER_CORE_STACK = 0x0A000000


def find_libusb():
    candidates = [
        os.environ.get("LIBUSB_1_0_DLL"),
        r"C:\KIRO\libusb\VS2022\MS64\dll\libusb-1.0.dll",
        r"C:\KIRO\AppPatcher\wInd3x-src\libusb-1.0.dll",
        r"C:\KIRO\iPodUniversalDecrypt\libusb-1.0.dll",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            backend = usb.backend.libusb1.get_backend(
                find_library=lambda _name, path=candidate: path
            )
            if backend is not None:
                return backend, candidate
    backend = usb.backend.libusb1.get_backend()
    if backend is None:
        raise RuntimeError("No usable libusb-1.0 backend was found")
    return backend, "system default"


class IbuggerCore:
    def __init__(self, timeout=5000):
        self.timeout = timeout
        backend, backend_name = find_libusb()
        self.backend_name = backend_name
        self.device = usb.core.find(
            idVendor=IBUGGER_VID, idProduct=IBUGGER_PID, backend=backend
        )
        if self.device is None:
            raise RuntimeError(
                "iBugger Core not found (expected USB VID 0xffff PID 0x8642)"
            )
        self.device.set_configuration()
        usb.util.claim_interface(self.device, IBUGGER_INTERFACE)
        self.device.default_timeout = timeout
        self.max_out = IBUGGER_MAX_TRANSFER
        self.max_in = IBUGGER_MAX_TRANSFER
        self.device_type = None
        self.core_type = None
        self.version = None
        self._read_identity()

    def close(self):
        if self.device is not None:
            try:
                usb.util.release_interface(self.device, IBUGGER_INTERFACE)
            except usb.core.USBError:
                pass
            usb.util.dispose_resources(self.device)
            self.device = None

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()

    def _bulk_write(self, data):
        return self.device.write(IBUGGER_OUT_ENDPOINT, data)

    def _bulk_read(self, size):
        return bytes(self.device.read(IBUGGER_IN_ENDPOINT, size))

    def _read_status(self):
        return self._bulk_read(0x10)

    @staticmethod
    def _check_status(data):
        if len(data) < 4:
            raise RuntimeError(f"Short iBugger status response: {data.hex()}")
        error_code = struct.unpack_from("<I", data)[0]
        if error_code != 1:
            raise RuntimeError(f"iBugger operation failed with status {error_code}")

    def _read_identity(self):
        """Read the loader/Core identity packet, which is not a status packet.

        Opcode 1 returns version/device metadata directly.  In particular, the
        first word is the packed version, not the normal status value 1.
        """
        self._bulk_write(struct.pack("<IIII", 1, 0, 0, 0))
        data = self._bulk_read(0x10)
        if len(data) != 0x10:
            raise RuntimeError(f"Unexpected identity response length: {len(data)}")
        major, minor, revision, core_type, device_type, max_out, max_in, reserved = struct.unpack(
            "<BBBBIHHI", data
        )
        # The 4th word is loaded from a register the loader treats as a
        # constant zero, but real Nano 2G hardware has been observed to
        # return a non-zero value here (e.g. 0x00005ac0) while every other
        # field decodes correctly. The historical libibugger.py never
        # validates this field either, so it is not enforced here.
        self.version = (major, minor, revision)
        self.core_type = core_type + 1
        self.device_type = device_type
        # The historical host overrides Nano 2G transfer sizes to 512 bytes.
        # The loader advertises 528 internally, but padding host transfers to
        # that out-of-spec size is not part of the working host protocol.
        self.max_out = 512 if device_type == 2 else max_out
        self.max_in = 512 if device_type == 2 else max_in
        print(
            f"iBugger identity v{major}.{minor}.{revision}, core_type={self.core_type}, "
            f"device_type={device_type}, advertised_out={max_out}, "
            f"advertised_in={max_in}, max_out={self.max_out}, max_in={self.max_in}, "
            f"backend={self.backend_name}"
        )

    def get_state(self, new_state):
        self._bulk_write(struct.pack("<IiII", 0xA, new_state, 0, 0))
        data = self._bulk_read(0x5C)
        self._check_status(data)
        if len(data) != 0x5C:
            raise RuntimeError(f"Unexpected state response length: {len(data)}")
        return struct.unpack("<19I", data[0x10:])

    def write_memory(self, offset, data):
        if offset & 3:
            opcode, divisor = 7, 1
        else:
            opcode, divisor = 6, 4
        block_size = self.max_out - 0x10
        position = 0
        while position < len(data):
            block = data[position:position + block_size]
            block_opcode = opcode
            block_divisor = divisor
            if len(block) & 3:
                block_opcode, block_divisor = 7, 1
            command = struct.pack(
                "<IIII", block_opcode, offset + position, len(block) // block_divisor, 0
            ) + block
            self._bulk_write(command)
            self._check_status(self._read_status())
            position += len(block)

    def read_memory(self, offset, size):
        if offset & 3:
            opcode, divisor = 5, 1
        else:
            opcode, divisor = 4, 4
        block_size = self.max_in - 0x10
        output = bytearray()
        position = 0
        while position < size:
            block_len = min(block_size, size - position)
            block_opcode = opcode
            block_divisor = divisor
            if block_len & 3:
                block_opcode, block_divisor = 5, 1
            self._bulk_write(
                struct.pack(
                    "<IIII", block_opcode, offset + position,
                    block_len // block_divisor, 0
                )
            )
            response = self._bulk_read(0x10 + block_len)
            self._check_status(response)
            output.extend(response[0x10:0x10 + block_len])
            position += block_len
        return bytes(output)

    def execute(self, address, stack):
        self._bulk_write(struct.pack("<IIII", 8, address, stack, 0))

    def startup(self, logo_path, core_path, reconnect_timeout=15):
        """Upload and execute the Core image from the Loader stage.

        Mirrors libibugger.py's startup(): upload the logo, upload Core,
        execute at IBUGGER_CORE_ENTRY, then wait for the device to
        re-enumerate as Core and re-open it. The caller must discard this
        object and use the returned IbuggerCore afterward; the original
        handle is no longer valid once Core resets the USB link.
        """
        if self.core_type != 1:
            raise RuntimeError(
                f"startup() requires the Loader stage (core_type=1), got {self.core_type}"
            )
        logo = Path(logo_path).read_bytes()
        core = Path(core_path).read_bytes()

        print(f"Uploading logo ({len(logo):,} bytes) to 0x{IBUGGER_LOGO_ADDRESS:08x}...")
        self.write_memory(IBUGGER_LOGO_ADDRESS, logo)
        print(f"Uploading Core ({len(core):,} bytes) to 0x{IBUGGER_CORE_ADDRESS:08x}...")
        self.write_memory(IBUGGER_CORE_ADDRESS, core)
        print(
            f"Executing Core at 0x{IBUGGER_CORE_ENTRY:08x}, "
            f"stack 0x{IBUGGER_CORE_STACK:08x}..."
        )
        self.execute(IBUGGER_CORE_ENTRY, IBUGGER_CORE_STACK)
        self.close()

        print("Waiting for device to re-enumerate as Core...")
        deadline = time.monotonic() + reconnect_timeout
        last_error = None
        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                new_core = IbuggerCore(timeout=self.timeout)
            except RuntimeError as error:
                last_error = error
                continue
            if new_core.core_type == 2:
                print("Core is now running.")
                return new_core
            new_core.close()
            last_error = RuntimeError(
                f"re-opened device reports core_type={new_core.core_type}, expected 2"
            )
        raise TimeoutError(
            f"Timed out waiting for Core to re-enumerate: {last_error}"
        )

    def run_crypto_payload(self, payload_path, input_data, timeout=120):
        if len(input_data) > 0x1FE0000:
            raise ValueError("iBugger crypto payload supports inputs up to 31 MiB")
        padded_size = (len(input_data) + 0x3F) & ~0x3F
        payload = Path(payload_path).read_bytes()
        padded_input = input_data.ljust(padded_size, b"\0")

        self.get_state(2)
        print(f"Uploading device crypto payload ({len(payload):,} bytes)...")
        self.write_memory(IBUGGER_RAM_CODE, payload)
        print(f"Uploading input ({len(padded_input):,} bytes)...")
        self.write_memory(IBUGGER_RAM_DATA, padded_input)
        print("Executing device-side crypto operation...")
        self.execute(IBUGGER_RAM_ENTRY, IBUGGER_RAM_STACK)

        deadline = time.monotonic() + timeout
        while True:
            state = self.get_state(-1)
            if state[18] != 0:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting for device crypto operation")
            time.sleep(0.25)

        print(f"Downloading device result ({padded_size:,} bytes)...")
        return self.read_memory(IBUGGER_RAM_DATA, padded_size)[:len(input_data)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input", type=Path, nargs="?", help="Raw Nano 2G partition image"
    )
    parser.add_argument(
        "output", type=Path, nargs="?", help="Output path for device-processed image"
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Read identity and passive target state only; do not upload, execute, or download",
    )
    parser.add_argument(
        "--startup",
        action="store_true",
        help=(
            "Load Core from the Loader stage (uploads logo+Core, executes, "
            "waits for re-enumeration), then probe Core identity/state and stop"
        ),
    )
    parser.add_argument(
        "--logo",
        type=Path,
        default=Path(__file__).parent.parent / "nano2g_loader_512" / "logo-2_original.bin",
        help="Device-side logo image for --startup (unmodified, no packet-size bug)",
    )
    parser.add_argument(
        "--core",
        type=Path,
        default=Path(__file__).parent.parent / "nano2g_loader_512" / "core-2_512.bin",
        help="Device-side Core image for --startup (512-byte patched)",
    )
    parser.add_argument(
        "--payload",
        type=Path,
        default=Path(__file__).parents[1] / "ibugger" / "ipodcrypto" / "decryptfirmware" / "decryptfirmware.bin",
        help="Device-side decryptfirmware.bin payload",
    )
    args = parser.parse_args()

    if args.startup:
        if args.input is not None or args.output is not None:
            parser.error("--startup does not accept input/output paths")
        with IbuggerCore() as loader:
            core = loader.startup(args.logo, args.core)
        try:
            state = core.get_state(-1)
            print("core_state_words=" + ",".join(f"0x{word:08x}" for word in state))
            print(f"core_target_state=0x{state[18]:08x}")
        finally:
            core.close()
        return

    if args.probe:
        if args.input is not None or args.output is not None:
            parser.error("--probe does not accept input/output paths")
        with IbuggerCore() as core:
            if core.core_type != 2:
                print(
                    "device is the Loader stage; GETSTATE is Core-only, "
                    "skipping passive state query"
                )
                return
            state = core.get_state(-1)
            print("passive_state_words=" + ",".join(f"0x{word:08x}" for word in state))
            print(f"passive_target_state=0x{state[18]:08x}")
        return

    if args.input is None or args.output is None:
        parser.error("input and output are required unless --probe is used")
    input_data = args.input.read_bytes()
    with IbuggerCore() as core:
        result = core.run_crypto_payload(args.payload, input_data)
    args.output.write_bytes(result)
    print(f"Wrote {len(result):,} bytes to {args.output}")


if __name__ == "__main__":
    main()
