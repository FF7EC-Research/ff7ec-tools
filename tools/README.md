# tools

Reverse-engineering / preservation utilities for the FFBE AndApp client.

## `cocos_ccz.py`
Decrypt, inspect, and re-pack cocos2d-x **CCZp** encrypted assets using the
XXTEA key recovered from `FF_EXVIUS.exe` (build 10.0.0).

```
python cocos_ccz.py info    VersionAndApp.xml      # header + preview
python cocos_ccz.py decrypt  in.ccz  out.xml       # decrypt + inflate
python cocos_ccz.py encrypt  in.xml  out.ccz       # re-pack (round-trippable)
python cocos_ccz.py keystream                       # show key parts / keystream
```
Key parts: `0x10872fa8, 0x12eb74c3, 0x4ada7aa3, 0xf4783fd9`. See
[`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) §2.

## `patch_ssl.py`
Disable TLS certificate verification so the client accepts a self-signed /
renamed **preservation server** cert. Patches the OpenSSL/libcurl DLLs that ship
next to the game (`X509_verify_cert`→1, `SSL_get_verify_result`→0), with `.bak`
backups. Requires `pip install pefile`.

```
python patch_ssl.py  <game_dir>            # patch all OpenSSL/curl DLLs found
python patch_ssl.py  --restore <game_dir>  # revert from .bak
```
Prefer the **no-files-modified** alternative built into the loader
(`loader/ssl_hook` via `[ssl] bypass = true`) if you don't want to touch the
game's DLLs. Both do the same two no-ops.

> These only affect the local client you own; they are not for intercepting
> anyone else's traffic.
