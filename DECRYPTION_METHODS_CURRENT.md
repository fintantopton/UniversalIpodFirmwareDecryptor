# Current Decryption Methods

This file summarizes the methods implemented by the active v3.2 application. Detailed handover documents are in `NANO5G_IMPLEMENTATION_HANDOVER.md` and `NANO5G_STRINGS_FONTS_FINDINGS.md`.

## Methods

- **Plaintext extraction:** IPSW/MSE extraction with an IMG1-header fallback for unencrypted firmware families. No device required.
- **Native hardware AES:** Native Windows `wInd3x-win.exe` haxdfu plus on-device AES for supported Classic/Nano 3G/4G/5G paths. Requires DFU, WinUSB, and direct native USB.
- **Legacy hardware AES:** Separate Notes/Loader/Core WinUSB transport in `nano2g_device_decrypt.py` and `nano2g_payloads.py`. Device-side work is RAM-resident.
- **Nano 5G resource export:** Plaintext RSRC/FAT16 parsing in `nano5g_resources.py`, including `Resources/UI/SilverImagesDB.LE.bin`. No device required for resource-only export.
- **Historical software reconstruction:** Retained only for comparison; it is not a valid source of ground-truth decrypted firmware.

## Current native wInd3x coverage

| Device group | SoC | DFU PID | Path |
|---|---|---:|---|
| Classic revisions | S5L8702 | `0x1223` / `0x1250` | DFUProtoVersion1 |
| Nano 3G | S5L8702 | `0x1223` | DFUProtoVersion1 |
| Nano 4G | S5L8720 | `0x1225` | epNano4G trampoline (`0x3b0`) |
| Nano 5G | S5L8730 | `0x1231` | epNano5G trampoline (`0x37c`) |
| S5Late-era models | S5L8723/S5L8740 | `0x1232`/`0x1234` | Not current decrypt support |

## Safety and limitations

- Native trampoline paths require direct Windows USB; USB/IP is unreliable for their intentional timeout/re-enumeration sequence.
- Hardware-AES paths require the correct physical device state and WinUSB binding.
- RSRC resource export is plaintext and read-only.
- Category 2 output validation should be strengthened beyond file-size checks before treating every output as cryptographic proof.
- The executable is distributed through GitHub Releases and is not committed to the source repository.
