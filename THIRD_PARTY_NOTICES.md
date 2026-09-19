# Third-Party Notices

This repository contains original application code plus integrations with external tools and historical device artifacts.

## wInd3x

The native hardware-AES workflow invokes the open-source [freemyipod/wInd3x](https://github.com/freemyipod/wInd3x) project. wInd3x is distributed under its own license; consult its upstream repository and included license before redistribution or modification.

The repository does not include the wInd3x executable or libusb runtime DLL. Obtain those dependencies separately and use only versions appropriate for the target device and host.

## WinUSB/Zadig

WinUSB is provided by Windows. Zadig is an external driver-installation utility and is not included in this source repository.

## Historical device payloads

`nano2g_payloads.py` contains embedded historical device-side binary payloads required by the legacy RAM-resident device-AES path. These payloads are not ordinary newly authored Python source and may retain original copyright/licensing terms. Preserve their attribution and do not assume the project MIT license relicenses them.

## Firmware and user data

Firmware images, decrypted outputs, device dumps, recovery files, and user data are intentionally excluded from this repository. Do not commit them without confirming redistribution rights.
