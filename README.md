# ffbe-JP-andapp — preservation toolkit

Interoperability / preservation tooling for the AndApp (DMM/DeNA) build of
*Final Fantasy Brave Exvius* JP (`FF_EXVIUS.exe`, build **10.0.0**). The goal is
to keep a client you own runnable after the AndApp platform's end of service:
launch the game without the official AndApp desktop client, decrypt its own
assets, and point it at a community preservation server.

This is not a piracy project. Purchases are **disabled**, not spoofed — the
helper never fabricates a successful payment or entitlement.

## Layout

| Path | What |
|---|---|
| [`tools/cocos_ccz.py`](tools/cocos_ccz.py) | Decrypt/re-pack cocos2d-x CCZp assets (XXTEA key recovered) |
| [`tools/patch_ssl.py`](tools/patch_ssl.py) | Disable TLS cert verification for a self-signed preservation server |
| [`loader/`](loader/) | Drop-in `winmm.dll` loader: hosts the AndApp helper, DNS redirect, SSL bypass, mutex fix — no extra program to run |
| [`docs/REVERSE_ENGINEERING.md`](docs/REVERSE_ENGINEERING.md) | Full findings: assets, helper IPC, payment surface, handshake |
| [`docs/VersionAndApp.decrypted.xml`](docs/VersionAndApp.decrypted.xml) | Decrypted sample (proof the key works) |

## Quick start

1. **Decrypt assets**
   ```
   python tools/cocos_ccz.py decrypt VersionAndApp.xml
   ```
2. **Build the loader** (32-bit) and drop it next to the game
   ```
   cd loader && build.bat          REM or: build.bat mingw
   copy winmm.dll andapp_loader.ini  <game folder>
   ```
3. **Edit `andapp_loader.ini`** — set the `[dns]` redirects to your preservation
   server; leave `[helper]`, `[ssl]`, `[mutex]` enabled.
4. **Run `FF_EXVIUS.exe`.** Read `andapp_loader.log` to see what happened.

## Known open item
The SDK↔helper **session handshake crypto** (RSA-wrapped AES) is isolated in one
seam in `loader/helper_server.cpp`; complete it from a capture taken with the
packet-logging helper (see `docs/REVERSE_ENGINEERING.md` §5). Everything else —
CCZ decryption, the JSON command layer, payment stub, DNS redirect, SSL bypass,
mutex fix, and the winmm proxy — is implemented and, for the loader, compiles to
a clean 32-bit drop-in DLL.
