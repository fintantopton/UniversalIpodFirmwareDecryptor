# Current Decryption Methods

This file summarizes the methods implemented by the active v3.2 application. Per-model details are in `DECRYPTION_METHODS.md`; build instructions are in `BUILD.md`.

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
| Nano 5G | S5L8730 | `0x1231` | epNano5G trampoline (`0x37c`) — successfully decrypted and locally verified for OSOS 1.0.1 and 1.0.2 |
| S5Late-era models | S5L8723/S5L8740 | `0x1232`/`0x1234` | Not current decrypt support |

## Safety and limitations

- Native trampoline paths require direct Windows USB; USB/IP is unreliable for their intentional timeout/re-enumeration sequence.
- Hardware-AES paths require the correct physical device state and WinUSB binding.
- RSRC resource export is plaintext and read-only.
- Category 2 output validation should be strengthened beyond file-size checks before treating every output as cryptographic proof.
- The executable is distributed through GitHub Releases and is not committed to the source repository.

## Verified Nano 5G decryption results

The workspace contains two successfully decrypted and locally verified S5L8730 OSOS outputs:

```text
OSOS 1.0.1
size:   7,276,688 bytes
SHA256: EA4BAD8DC8C8C57EA3144F9615B92D6865AB34BEC267229B41E7B12CF6B491F4

OSOS 1.0.2
size:   7,286,720 bytes
SHA256: 3269D9EDA2E7E7C406D7BFD6895BD83F27603F03A2C9F52C6CF415924E41AF81
```

Both outputs validate as S5L8730 IMG1 images with magic `8730`, version `2.0`, format 4, internally consistent length fields, 16-byte-aligned bodies, valid unsigned-image signature/certificate placeholders, and expected RetailOS anchors including `RTXC`, `MeCCA`, `SQLite`, `DiskMode`, `TCCamera`, and `N33FirmwareWin`.

This establishes that the Nano 5G decryption process has successfully produced coherent decrypted OSOS firmware. A new hardware run on a different host/device should still be recorded separately when reproducing the process.
