# iPod Universal Decryptor — Knowledge Base

> **Current implementation authority (v3.2.0/build 30):** Use `C:\KIRO\iPodKnowledgeDB\RESEARCH_DOCS\DECRYPTION_METHODS_CURRENT.md` for the active app's decryption categories, model coverage, device requirements, resource-export behavior, and known limitations. The older sections below are historical and may contain superseded model/PID descriptions.


## Architecture Overview

The Universal iPod Firmware Decryptor extracts and decrypts RetailOS (OSOS) from iPod IPSW files.

### Two Categories of iPod Firmware

| Category | Devices | Encryption | Decrypt Method |
|----------|---------|-----------|----------------|
| 1 | iPod 1G-5.5G, Nano 1G, Mini 1G/2G | None | Extract from IPSW ZIP, strip IMG1 header |
| 2 | Nano 2G-7G, Classic 6G/6.5G/7G | Hardware AES (GID key) | Device in DFU mode + wInd3x exploit |

### Category 2 Exploit Paths (wInd3x)

| SoC | Devices | DFU PID | Exploit | Trampoline |
|-----|---------|---------|---------|------------|
| S5L8701 | Nano 2G | 1223 | DFUProtoVersion1 | No |
| S5L8702 | Nano 3G, Classic | 1223, 1250 | DFUProtoVersion1 (epNano3G) | No |
| S5L8720 | Nano 4G | 1225 | epNano4G (epNano45G base) | Yes (0x3b0) |
| S5L8730 | Nano 5G | 1231 | epNano5G (epNano45G base) | Yes (0x37c) |
| S5L8723 | Nano 6G | 1232 | S5Late | Different |
| S5L8740 | Nano 7G | 1234 | S5Late | Different |

---

## Critical Discovery: USB Transport Incompatibility

### Problem
The Nano 4G/5G exploit uses a "trampoline" mechanism in EVERY RCE call:
1. Upload payload to DFU buffer
2. Send USB control upload of `TrampolineAddr + 0x40` bytes — **intentionally causes USB timeout**
3. Send setup packet (bug trigger) — device executes payload and returns 0x40 bytes of data

**usbipd (USB/IP bridge) cannot handle step 2 + 3 reliably.** The intentional USB timeout at step 2 corrupts the USB/IP protocol state, causing step 3's response data to be lost.

### Evidence
- Classic/Nano 3G (`TrampolineAddr = 0`): works perfectly over usbipd — no trampoline needed
- Nano 5G (`TrampolineAddr = 0x37c`): haxdfu and decrypt both fail over usbipd
- Tested timeouts: 50ms, 500ms, 5000ms — all fail (not a timeout issue, it's protocol-level)
- Direct USB on Windows (via WinUSB + libusb): works perfectly

### Solution
**Native Windows execution via WinUSB driver + libusb-1.0.dll**

No WSL, no usbipd. The `wInd3x-win.exe` binary runs directly on Windows and communicates with the iPod over native USB through the WinUSB driver.

---

## Working Solutions

### Solution A: Native Windows (ALL Category 2 devices) ✅ RECOMMENDED

**Requirements:**
- `wInd3x-win.exe` (Go binary, compiled with CGO + libusb for Windows)
- `libusb-1.0.dll` (from libusb 1.0.27 MinGW64 release)
- WinUSB driver installed for the iPod DFU PID (one-time via Zadig)
- Apple Mobile Device Service stopped during decrypt

**Build wInd3x-win.exe:**
```
```powershell
# Prerequisites: Go 1.26+, MSYS2 MinGW64 GCC, libusb-1.0.27 (MinGW64 package)
$env:Path = "C:\Program Files\Go\bin;C:\msys64\mingw64\bin;" + $env:Path
$env:CGO_ENABLED = "1"
$env:CC = "gcc"
$env:PKG_CONFIG_PATH = "C:\KIRO\libusb\pkgconfig"
cd C:\KIRO\AppPatcher\wInd3x-src
go build -buildvcs=false -o wInd3x-win.exe ./cmd/wInd3x/
```

**libusb pkgconfig file** (`C:\KIRO\libusb\pkgconfig\libusb-1.0.pc`):
```
prefix=C:/KIRO/libusb
includedir=${prefix}/include
libdir=${prefix}/MinGW64/static

Name: libusb-1.0
Description: libusb-1.0
Version: 1.0.27
Cflags: -I${includedir}
Libs: -L${libdir} -lusb-1.0
```

**Runtime requirement:** `libusb-1.0.dll` must be next to `wInd3x-win.exe`

**Driver installation:**
- Zadig (5.1MB, bundled) installs WinUSB for a specific VID/PID
- User opens Zadig → selects iPod DFU device → installs WinUSB
- One-time per PID — persists across reboots

**Driver removal:**
```powershell
pnputil /enum-drivers  # Find the oem###.inf for the target PID
pnputil /delete-driver oem###.inf /uninstall
```

**Critical: Stop Apple services before USB access:**
```powershell
net stop "Apple Mobile Device Service"
net stop "iPodService"
```

**Decrypt flow:**
```powershell
# 1. Extract OSOS from IPSW
wInd3x-win.exe mse extract Firmware.MSE -o .\mse_out\

# 2. Exploit (device must be in DFU mode)
wInd3x-win.exe haxdfu -v

# 3. Decrypt (takes ~2 hours for 7MB, ~30 min for Classic 10MB)
wInd3x-win.exe decrypt .\mse_out\osos output.bin -v -r recovery.dat
```

---

### Solution B: WSL2 + usbipd (Classic/Nano 3G ONLY)

**Works for:** S5L8702 devices (TrampolineAddr = 0)
**Does NOT work for:** Nano 4G/5G/6G/7G

**Requirements:**
- WSL2 with Ubuntu or iPodPatcher (Alpine) distro
- usbipd-win installed
- wInd3x Linux binary (glibc for Ubuntu, musl for Alpine)
- `modprobe vhci-hcd` in WSL before attaching USB

**Key findings:**
- iPodPatcher Alpine distro is 0.4MB compressed — very small
- musl binary (`wInd3x-write-musl`) needed for Alpine, glibc for Ubuntu
- `stdbuf` not available in Alpine — don't wrap commands with it
- WSL keepalive needed (`sleep 14400`) to prevent distro shutdown during long decrypt
- usbipd `bind` + `attach --wsl` workflow; `modprobe vhci-hcd` must run first

---

## wInd3x Source Patches (for usbipd compatibility)

Location: `c:\KIRO\AppPatcher\wInd3x-src\`

### Patch 1: Timeout increase
File: `pkg/exploit/exploit.go` line 115
```go
// Original: 50ms (too short for usbipd)
usb.SetControlTimeout(time.Millisecond * 5000)
```

### Patch 2: Trampoline timeout handling
File: `pkg/exploit/exploit.go` — RCE function
```go
if ep.TrampolineAddr() != 0 {
    // Use short timeout for trampoline (expected to timeout)
    usb.SetControlTimeout(time.Millisecond * 100)
    // ... trampoline step ...
    // Restore longer timeout for bug trigger
    usb.SetControlTimeout(time.Millisecond * 5000)
}
```

### Patch 3: haxdfu accepts timeout as success for Nano 4G/5G
File: `pkg/exploit/haxeddfu/haxeddfu.go`
```go
// After RCE, if error AND device uses trampoline, treat as success
// (device re-enumerates after exploit, USB response is lost)
if err != nil {
    if ep.TrampolineAddr() != 0 {
        slog.Info("Haxed DFU triggered (device re-enumerated)")
        return nil
    }
    return fmt.Errorf("failed: %w", err)
}
```

### Patch 4: GetStringDescriptor failure tolerance
File: `pkg/exploit/haxeddfu/haxeddfu.go`
```go
// First descriptor check may fail if device already re-enumerated
p, err := usb.GetStringDescriptor(2)
if err == nil {
    // Check if already in haxed DFU...
}
// If err != nil, proceed with exploit (device is in normal DFU)
```

---

## DFU Mode Entry

**iPod Classic / Nano 3G:** Hold Menu + Center (Select) for ~8 seconds until screen stays completely black (backlight may be on).

**iPod Nano 4G/5G:** Same procedure — Menu + Center until black screen.

**Important:** Device must be running stock Apple firmware. Custom bootloaders (Rockbox, emCORE) intercept the boot and enter WTF mode instead of DFU.

**DFU PID 1242:** This is Nano 3G recovery mode (not DFU). If you see this, the device is in recovery, not DFU. Re-enter DFU mode.

---

## IPSW Filename Parsing

Two formats exist:

| Format | Example | FamilyID |
|--------|---------|----------|
| Standard | `iPod_26.1.1.3.ipsw` | First number (26) |
| Build code | `iPod_1.0.2_34A20020.ipsw` | First 2 digits of build code (34) |

**Critical:** Format 2 must be checked FIRST. Otherwise `iPod_1.0.2_34A20020.ipsw` matches Format 1 as FamilyID 1 (iPod 1st Gen) instead of FamilyID 34 (Nano 5G).

---

## File Locations

```
c:\KIRO\iPodUniversalDecrypt\
  ipod_universal_decrypt_b.py    — Main app source
  iPodUniversalDecrypt_b.spec    — PyInstaller spec
  build_b.bat                    — Build script
  zadig.exe                      — Bundled Zadig (5.1MB)
  KNOWLEDGE_BASE.md              — This file

c:\KIRO\AppPatcher\wInd3x-src\
  wInd3x-win.exe                 — Native Windows binary (21MB)
  libusb-1.0.dll                 — Windows libusb runtime
  wInd3x                         — Linux glibc binary
  wInd3x-write-musl              — Linux musl binary (Alpine)
  pkg/exploit/exploit.go         — RCE + timeout patches
  pkg/exploit/haxeddfu/          — haxdfu trigger patches
  pkg/exploit/wind3x_n45g.go     — Nano 4G/5G exploit params
  pkg/exploit/wind3x_n3g.go      — Nano 3G/Classic exploit params

c:\KIRO\libusb\
  include\libusb.h               — Header for CGO build
  MinGW64\static\libusb-1.0.a   — Static lib for linking
  MinGW64\dll\libusb-1.0.dll    — Runtime DLL
  pkgconfig\libusb-1.0.pc       — pkg-config file

c:\KIRO\AppPatcher\iPodCFGPatcher\
  installer.nsi                  — Reference: how Alpine rootfs is bundled
  release\installers\ipodpatcher-rootfs.tar.gz  — Alpine WSL distro (0.4MB)
```

---

## Known Issues & Workarounds

1. **Apple Mobile Device Service** holds USB exclusively. Must be stopped before native Windows USB access.

2. **usbipd "Shared" state** blocks native access. Run `usbipd unbind --busid X-Y` (elevated) to release.

3. **iPodService** also grabs the device on Windows. Stop before decrypt.

4. **Nano 5G haxdfu "USB timeout error"**: Expected behavior — the exploit causes USB re-enumeration. The patched wInd3x treats this as success.

5. **glibc vs musl**: The standard wInd3x Linux binary is glibc-linked. iPodPatcher (Alpine) needs the musl variant. Error message: `sh: /usr/local/bin/wInd3x: not found` (misleading — it means the dynamic linker can't load it).

6. **DeviceInterfaceGUIDs registry**: Even with WinUSB driver installed via Apple's INF, libusb may fail with `ERROR_NOT_SUPPORTED (50)` if the GUID doesn't match. Zadig creates the correct GUID entry. Apple's INF uses a custom GUID that libusb can't open.

7. **Decrypt speed**: ~48 bytes per USB transaction. Classic 10MB ≈ 2 hours. Nano 3G ≈ 2 hours. Nano 4G/5G ≈ 4-5 hours (trampoline overhead doubles time per block).

### Decrypt Time Estimates (Native Windows)

| Device | OSOS Size | RCE Type | Trampoline | Approx Time |
|--------|-----------|----------|------------|-------------|
| iPod Classic (S5L8702) | ~10 MB | DFUProtoVersion1 | No | ~2 hours |
| iPod Nano 3G (S5L8702) | ~7 MB | DFUProtoVersion1 | No | ~2 hours |
| iPod Nano 4G (S5L8720) | varies | epNano4G | Yes (0x3b0) | ~4 hours (estimate) |
| iPod Nano 5G (S5L8730) | ~7 MB | epNano5G | Yes (0x37c) | ~4-5 hours |
| iPod Nano 6G (S5L8723) | varies | S5Late | Different | Unknown |
| iPod Nano 7G (S5L8740) | varies | S5Late | Different | Unknown |

**Note:** Times are for native Windows (wInd3x-win.exe + WinUSB). The Nano 3G/Classic previously showed ~30 min in the TESTED_OUTPUT.md, but that was measured over a direct Linux USB connection. Over native Windows with WinUSB, real-world times for Classic/Nano 3G are approximately 2 hours due to Windows USB stack overhead and the WinUSB layer adding latency to each 48-byte control transfer.

8. **Recovery file**: Must be on a persistent filesystem. Do NOT use `/tmp/` in WSL (cleared on restart). Use Windows path (e.g., Desktop).


---

## Nano 6G/7G Decrypt — Unsolved (S5Late Limitation)

### Problem
After S5Late's haxdfu exploit, the DFU state machine is corrupted:
- `dfu.Clean()` (ClearStatus + GetState) hangs — never returns
- `dfu.SendChunk()` (DFU DNLOAD) also hangs — state not in dfuIDLE
- Without these, wInd3x's standard RCE → decrypt cycle cannot work

### What Works
- S5Late haxdfu: ✅ (consistently succeeds)
- The first RCE call (for haxdfu payload): ✅
- String descriptor check confirming haxed DFU: ✅

### What Doesn't Work  
- Any subsequent dfu.Clean() call: ❌ hangs
- Any subsequent dfu.SendChunk() call: ❌ hangs
- Therefore: wInd3x `decrypt` command: ❌ cannot do repeated RCE

### Root Cause
S5Late works by overflowing the DFU buffer to overwrite `g_State` at 0x2202fff8.
It crafts a new state structure that patches the vendor handler. After the first
payload executes, it restores the original state pointer — but the DFU state
machine's internal state (transferred bytes counter, status registers) is NOT
properly reset. The BootROM's DFU handler never returns to dfuIDLE.

### Tested Approaches
1. **Skip dfu.Clean()**: SendChunk also hangs (needs dfuIDLE state)
2. **Various timeouts (50ms, 200ms, 1000ms, 5000ms)**: No difference, Clean never responds
3. **Removing Clean from RCE**: SendChunk then fails

### Possible Future Solutions
1. **Single-shot ARM payload**: Write a payload that loops AES decrypt internally
   (all blocks in one execution), stores results in SRAM, signals completion.
   Challenge: 256KB SRAM can't hold 9MB OSOS.

2. **Chunked payload with USB data channel**: After exploit, use the vendor handler
   (`blx r0`) directly — send data+code via USB control transfers without DFU DNLOAD.
   Requires understanding what R0 points to after haxdfu.

3. **Reset DFU state from payload**: The haxdfu payload could be modified to also
   reset DFU state fields (state=dfuIDLE, transferred=0, ready=0) so subsequent
   Clean/SendChunk work. Needs modification to S5Late's first-stage payload in
   `s5late_n7g.go`.

4. **ipod_sun userspace approach**: Boot modified firmware via disk-mode swap,
   dump AES key from running memory. Completely different path, no DFU needed
   after initial flash.

### Online Resources
- `github.com/m-gsch/S5Late` — Original exploit (Rust, Nano 7G only)
- `github.com/CUB3D/ipod_sun` — Userspace exploit (firmware swap trick)  
- `github.com/760ceb3b9c0ba4872cadf3ce35a7a494/ipodhax` — N6G/7G research
- `github.com/IAmDazen/Pixosn0w` — Nano 7G jailbreak attempt using ipod_sun
- `theapplewiki.com/wiki/S5Late` — Exploit documentation
- `theapplewiki.com/wiki/ByteFau1t` — Another N7G bug (rsrc partition)

### Current Status
**Nano 6G/7G decrypt is NOT supported.** The app should inform the user that these
models require research-level work to decrypt. haxdfu works, but the decrypt data
path is blocked by the S5Late state corruption issue.
