"""Platform-neutral access to the Nano 2G iBugger transport.

- Windows: native WinUSB transport (``nano2g_device_decrypt``).
- macOS/Linux: libusb transport (``nano2g_ibugger_usb``).

The application imports *this* module only, so the rest of the codebase is
identical across platforms.
"""

from __future__ import annotations

import ipod_platform as plat

# Device payload helpers are identical on every platform (the embedded
# RAM-resident binaries never change with the host OS).
# Re-exported here so callers can import one module on every platform.
from nano2g_device_decrypt import (  # noqa: F401
    DeviceNotFoundError,
    TransportError,
    get_core_bin,
    get_decryptfirmware_bin,
    get_loader_htm,
    get_logo_bin,
)

if plat.IS_WINDOWS:
    IBuggerTransport = None  # type: ignore[assignment]

    def _get_transport_class():
        import nano2g_device_decrypt as mod
        return mod.IBuggerTransport, mod.find_device_status
else:
    def _get_transport_class():
        import nano2g_ibugger_usb as mod
        return mod.IBuggerUSBTransport, mod.find_device_status


def get_transport_class():
    """Return (IBuggerTransportClass, find_device_status_func) for this OS."""
    return _get_transport_class()


def connect(log=None):
    """Open the platform transport (raises DeviceNotFoundError /
    TransportError with platform-appropriate guidance)."""
    transport_class, _status = get_transport_class()
    return transport_class(log=log)


def find_device_status():
    """Read-only iBugger status check. Same (status, stage, detail) shape
    as the Windows implementation."""
    _transport, status_fn = get_transport_class()
    return status_fn()
