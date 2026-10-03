# ff7ec-tools — preservation toolkit

Interoperability / preservation tooling for *Final Fantasy VII Ever Crisis*
(Square Enix / Applibot), built ahead of its announced end of service on
**October 5, 2026**. This repository exists under the Stop Killing Games
banner: once the servers go down, nothing here can reach them anymore, so the
only window for recording how the client and server actually talk to each
other is now.

## Layout

| Path | What |
|---|---|
| [`loader/`](loader/) | Drop-in `winmm.dll`: redirects the game's own traffic to a local proxy, decrypts it with the sibling [`ff7ecapi`](../ff7ecapi) research repo's documented key material, and logs it |
| [`tests/`](tests/) | Native (no Windows/Wine needed) unit tests for the decoder |

## Quick start

1. Build the loader (64-bit - see [`loader/README.md`](loader/README.md)):
   ```
   cd loader && build.bat          REM or: build.bat mingw
   ```
2. Copy `winmm.dll` + `ff7ec_loader.ini` next to the game's `.exe`.
3. Run the game. `ff7ec_loader.log` records what the loader did;
   `ff7ec_traffic.log` records the decrypted request/response traffic.

## Scope

This only affects the local game client you run it against, on your own
machine, against the host its own client was already configured to talk to.
It does not spoof purchases, fabricate server responses, or send anything
anywhere beyond that one connection.
