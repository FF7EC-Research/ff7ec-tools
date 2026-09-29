# AndApp preservation loader (`winmm.dll`)

A single drop-in `winmm.dll`, placed next to `FF_EXVIUS.exe`, that lets the
FFBE AndApp client run for **preservation** without the discontinued AndApp
desktop client — no extra programs to launch. It:

1. **Proxies `winmm.dll`** transparently to the real system winmm (audio/timers
   keep working), and uses `DllMain` as an injection point.
2. **Hosts the AndApp helper** on loopback TCP and writes
   `%LOCALAPPDATA%\AndApp\AndAppHelper.cfg` so the SDK finds it — with
   **payments disabled** (never fakes a purchase).
3. **Redirects game-server hostnames** to your preservation server, via a
   `[dns]` table in `andapp_loader.ini` (hooks `getaddrinfo`/`GetAddrInfoW`).
4. **Accepts any TLS certificate** so a self-signed preservation server works
   (in-memory OpenSSL/libcurl patch; only this local client is affected).
5. **Neutralizes the single-instance mutex** so the game launches standalone.

Everything is gated by `andapp_loader.ini`; delete or disable a section to turn
a feature off.

## Build (must be 32-bit — the game is x86)

**MSVC** — from an *x86 Native Tools Command Prompt*:
```
build.bat
```
**MinGW** (`i686-w64-mingw32-g++` on PATH):
```
build.bat mingw
```
**CMake**:
```
cmake -B build -A Win32           REM MSVC
cmake --build build --config Release
```
The MinGW target links the runtime statically, so the result imports only
`KERNEL32` / `msvcrt` / `WS2_32` — a clean drop-in.

## Install

Copy next to `FF_EXVIUS.exe`:
```
FF_EXVIUS.exe
winmm.dll            <- this loader
andapp_loader.ini    <- edit ports + [dns] redirects
```
Run the game normally. Check `andapp_loader.log` (same folder) for what the
loader did: real-winmm load, hooks installed, helper listening, DNS redirects,
SSL patches, and raw command bytes.

## Files
| File | Role |
|---|---|
| `winmm.cpp`, `winmm_exports.inc`, `winmm.def` | winmm proxy + DllMain |
| `util.cpp` | logging, `.ini` parsing, config |
| `hooks.cpp` | IAT hook, prologue patch, DNS / mutex / SSL hooks |
| `helper_server.cpp` | AndAppHelper TCP replacement (payments stubbed) |
| `andapp_loader.ini` | configuration |

## Status / limitation
The SDK↔helper **session handshake crypto** is isolated in one `SessionCrypto`
seam in `helper_server.cpp`. The default build speaks plaintext newline-framed
JSON and logs raw bytes. If the SDK requires the encrypted handshake, capture
one real session with the packet-logging helper and complete that seam — see
[`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) §5. All JSON
verbs, the payment stub, DNS, mutex, and SSL pieces are complete.
