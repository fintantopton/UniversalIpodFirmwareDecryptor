# vendor/ — External Native Dependencies

This directory holds external native binaries that are intentionally **not committed** to Git (see `.gitignore`). Only files that are present get bundled by the build specifications.

## Windows

| File | Purpose | Source |
|---|---|---|
| `wInd3x-win.exe` | Native Windows wInd3x build (haxdfu + device AES) | [freemyipod/wInd3x](https://github.com/freemyipod/wInd3x) |
| `libusb-1.0.dll` | libusb for the native Windows wInd3x build | [libusb/libusb](https://github.com/libusb/libusb) |
| `wInd3x` | Musl Linux wInd3x (compatibility) | freemyipod/wInd3x |
| `wInd3x-write-musl` | Optional compatibility binary | freemyipod/wInd3x |
| `zadig.exe` | WinUSB driver installer (optional) | [zadig](https://zadig.akeo.ie/) |

## macOS (Apple Silicon / Intel)

| File | Purpose | Source |
|---|---|---|
| `wInd3x-darwin-arm64` | Native darwin wInd3x build (haxdfu + device AES), Apple Silicon | Build: `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o wInd3x-darwin-arm64 ./cmd/wInd3x` from [freemyipod/wInd3x](https://github.com/freemyipod/wInd3x) — `build_macos.sh` does this automatically when Go is installed |
| `wInd3x-darwin-x86_64` | Same, for Intel Macs | Same, with `GOARCH=x86_64` |
| `libusb-1.0.dylib` | libusb for the Nano 2G iBugger transport (ctypes) and for the Go wInd3x binary | `brew install libusb` → `/opt/homebrew/opt/libusb/lib/libusb-1.0.dylib` (or `/usr/local/opt/...` on Intel) |

Notes:

- A generic name `wInd3x` in `vendor/` is also accepted on macOS (any of the
  candidates in `ipod_platform.wind3x_candidates()` is tried, most specific first).
- The darwin wInd3x build links libusb dynamically; when `libusb-1.0.dylib`
  is bundled next to the binary, the app sets `DYLD_LIBRARY_PATH` for the
  child process so the dylib is found without installation.
- Without a wInd3x binary the app still performs: unencrypted extraction
  (Category 1), Nano 2G software/device paths (Category 3/4 — libusb needed
  for 4), and raw/plaintext MSE member export (including Nano 5G RSRC and
  SilverImagesDB). Device-AES (Category 2) requires the wInd3x binary.

## License notice

The bundled third-party binaries are covered by their upstream licenses; see `THIRD_PARTY_NOTICES.md`.
