# FF7 Ever Crisis traffic-inspection loader (`winmm.dll`)

A drop-in `winmm.dll` for a **preservation copy of a game you own**, used to
record and understand its own network traffic before the servers shut down
(FF7 Ever Crisis ends service October 5, 2026). It never touches any other
copy of the game, any other player, or any host besides the one the game
itself was already going to talk to.

It does three things:

1. **Redirects the game's own DNS lookups to `127.0.0.1`** (`[dns]`), so its
   connections land on a local proxy instead of going straight to the real
   server.
2. **Terminates that connection with one local, self-signed certificate**
   (`certs.cpp`, `tls_schannel.cpp`) and opens its own ordinary, validated
   TLS connection to the real server, relaying HTTP messages between the two
   (`proxy.cpp`). Nothing is altered or fabricated in transit.
3. **Logs a decrypted copy of every message** (`decode.cpp`) using the
   request/response body cipher documented by the sibling
   [`ff7ecapi`](../../ff7ecapi) research repository (AES-256-CBC over an LZ4
   frame, protobuf payload), to `ff7ec_traffic.log`.

`ssl_bypass.cpp` makes the game's own TLS stack (SChannel, and OpenSSL/libcurl
if present) accept the local proxy's otherwise-untrusted certificate - the
only reason that certificate needs to exist at all is to let the game's
*existing* HTTPS client complete a handshake with our proxy; it is not a CA
and nothing installs it system-wide unless you explicitly set
`[mitm] install_ca = 1`.

## Files

| File | Role |
|---|---|
| `winmm.cpp`, `winmm_exports.inc`, `winmm.def` | winmm proxy + `DllMain` entry point |
| `util.cpp` | logging, `.ini` parsing, config, path helpers |
| `hooks.cpp` | IAT hooking + the DNS redirect |
| `ssl_bypass.cpp` | makes the game accept the local proxy's certificate |
| `certs.cpp` | generates/caches the proxy's one self-signed certificate |
| `tls_schannel.h/.cpp` | minimal blocking TLS stream over Windows SChannel |
| `proxy.cpp` | the loopback listener, upstream connection, HTTP relay + logging |
| `decode.h/.cpp` | portable (no Win32) AES/LZ4/protobuf decoder, unit-tested in `../tests` |
| `api_fields.inc` | generated field-name table for the protobuf dump (see below) |
| `ff7ec_loader.ini` | configuration |

`decode.cpp`/`decode.h` have no Windows dependency, so `../tests` builds and
runs them natively (see `../tests/README.md`) without needing Wine or a
Windows box.

`api_fields.inc` is generated from the sibling `ff7ecapi` repo's
`ff7ecpb/proto/api/api.proto` (the `ApiRequest`/`ApiResponse` top-level field
list), so the traffic log can show `201 (get_check)` instead of a bare field
number. Regenerate it if that proto changes.

## Build (match the game's bitness - Unity Windows builds are normally x64)

**MSVC** - from an *x64 Native Tools Command Prompt*:
```
build.bat
```
**MinGW** (`x86_64-w64-mingw32-g++` on PATH):
```
build.bat mingw
```
**CMake**:
```
cmake -B build -A x64             REM MSVC
cmake --build build --config Release
```

## Install

Copy next to the game's `.exe`:
```
<game>.exe
winmm.dll            <- this loader
ff7ec_loader.ini     <- edit if you need non-default ports/hosts
```
Run the game normally. `ff7ec_loader.log` records what the loader did
(real-winmm load, hooks installed, listener bound); `ff7ec_traffic.log`
records the decrypted traffic itself.

## Scope and limits

- Everything here only affects this local game process on this machine.
- The proxy speaks HTTP/1.1 framed messages (`Content-Length` or chunked)
  over TLS 1.2; it does not implement HTTP/2 or WebSockets.
- `upstream_verify` (default on) means the proxy's own connection - to
  whatever host the game's TLS ClientHello named, resolved normally - is
  validated like any other HTTPS client. Turn it off only once the real
  server has been replaced by a community preservation server (e.g. via your
  hosts file or a DNS override outside this loader) whose certificate
  wouldn't otherwise validate.
