# FFBE (AndApp) — reverse-engineering notes for preservation

Target: `FF_EXVIUS.exe`, the AndApp (DMM/DeNA PC platform) build of *Final
Fantasy Brave Exvius* JP. Everything here is for **interoperability and
preservation** of a client you own: running the game without the discontinued
AndApp desktop client, and pointing it at a community preservation server.

Reference binaries examined:
`FF_EXVIUS.exe`, `AndAppNextHelper.exe` (+ `.bak`), `AndAppNextBootHelper.exe`,
`AndAppNext.exe` (launcher), `roots.pem`, `VersionAndApp.xml`.

---

## 1. Executable overview

| Property | Value |
|---|---|
| Format | PE32 (x86, 32-bit), GUI |
| Engine | cocos2d-x (`libcocos2d.dll`), OpenGL/GLEW |
| Net/TLS | `libcurl.dll` → OpenSSL (`libcrypto-1_1.dll`, and libssl at runtime) |
| Crypto | OpenSSL EVP AES-128 CBC/ECB, MD5; Win32 CryptoAPI (RSA+AES) |
| AndApp SDK | DeNA "AndApp SDK End User Edition" v1.0.4 (`clientId ab6198d`) |

The AndApp integration is the statically-linked DeNA SDK, not game-specific
code. Relevant SDK source tags in the binary: `src/SDKImpl.cpp`,
`src/SessionManager.cpp`, `src/PaymentImpl.cpp`, `src/UserSessionImpl.cpp`,
`platform/win/ipc/src/DeNATCPClientImpl.cpp`, `DeNASessionImpl.cpp`.

---

## 2. cocos2d-x asset encryption (CCZp) — SOLVED

Encrypted assets use the cocos2d-x "CCZp" container. The XXTEA key is installed
by four calls near RVA `0x00750d2c`:

```
setPvrEncryptionKeyPart(0, 0x10872fa8)
setPvrEncryptionKeyPart(1, 0x12eb74c3)
setPvrEncryptionKeyPart(2, 0x4ada7aa3)
setPvrEncryptionKeyPart(3, 0xf4783fd9)
```

The same function immediately decrypts `VersionAndApp.xml`, confirming the key.

**Container layout** (16-byte big-endian header):

```
0  "CCZp"                 signature
4  uint16 compression      (0 = zlib)
6  uint16 version
8  uint32 reserved
12 uint32 len (BE)         uncompressed size   -- ENCRYPTED
16 zlib stream ...                              -- ENCRYPTED
```

**Algorithm**: a 1024-word keystream is expanded in place (from all-zeros) with
an XXTEA schedule (`DELTA = 0x9E3779B9`, 6 rounds) driven by the four key parts;
then payload words from offset 12 are XORed word-for-word with `keystream[i]`
(index-aligned). After decrypt, inflate the zlib stream at offset 16.

Implemented in [`tools/cocos_ccz.py`](../tools/cocos_ccz.py) (decrypt/encrypt/
info, round-trip verified). Result of decrypting the sample:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<application>
    <version name="10.0.0" build="10.0.0" />
</application>
```

(see [`docs/VersionAndApp.decrypted.xml`](VersionAndApp.decrypted.xml)) — this
is game build **10.0.0**.

---

## 3. AndApp helper IPC

### Roles of the three helper executables
* **AndAppNext.exe** — the launcher (Tauri/Rust). Reads a game `manifest.json`
  (`entryPointBaseName`, `versionCode`, `architecture`), writes AppData state
  (`andapp_config`, `andapphelper.pid`, `id_cache.json`, `roots.pem`,
  `boot_settings.json`), and launches the game with `--andapp-payload-id=<id>`.
* **AndAppNextHelper.exe** — the resident helper the SDK talks to. Envoy/gRPC-
  based local proxy; classes `SDKCommand@andapp`, `PortalAppCommand@andapp`,
  transports `PipeServer@dena` and `SocketImpl`/`TCPHandler`.
* **AndAppNextBootHelper.exe** — installer only
  (`AndApp-Portal-Next-win-installer`, `InstallerHelper.log`). **Not needed** to
  launch an already-installed game.

### Transport
The SDK is a TCP client to **127.0.0.1**. It discovers the ports from:

```
%LOCALAPPDATA%\AndApp\AndAppHelper.cfg      (or \AndAppDev\AndAppDevHelper.cfg)
    standard.tcp.command.ipv4.port      = <cmd>
    standard.tcp.notification.ipv4.port = <ntf>
    standard.tcp.command.ipv6.port      = ...
    standard.tcp.notification.ipv6.port = ...
```

Two channels: a **command** socket (request/response) and a **notification**
socket (server push). On failure the SDK logs `Could not connect to
AndAppHelper` / `Send TCP handshake request failed`.

> Note: the `\\.\pipe\crashpad_*` named pipe belongs to the bundled Crashpad
> crash handler, **not** the AndApp IPC.

### Message layer (JSON)
Commands carry an `action` and use DeNA's JSON. Verbs seen in both the SDK and
the helper:

| Verb | Purpose |
|---|---|
| `initialize` | handshake/init; carries `clientId`, `sdk_version`, `payload_id`, `app_version_*` |
| `get_id_token` | returns `id_token` / `public_user_id_token` / `player_id` |
| `is_billing_supported` | boolean |
| `get_products` | store catalog (`items`, `missingIds`) |
| `request_purchase` / `request_purchase_completion` / `get_request_purchase_info` | purchase flow |
| `consume_purchase` | consume |
| `get_purchases` | owned items |
| `send_analytics_event`, `open_app_page` | misc |

Notifications: `paymentSucceed`, `paymentFailed`, `application`/`active`,
`resume`.

### Session crypto (the one open item)
`DeNASessionImpl.cpp` wraps the raw TCP (`DeNATCPClientImpl.cpp`) with a crypto
session: Win32 CryptoAPI "Microsoft Enhanced RSA and AES Cryptographic
Provider", `CryptGenKey`/`CryptExportKey`/`CryptImportKey`, plus OpenSSL
AES-128-CBC. The SDK generates an AES session key and RSA-wraps it during the
handshake. **No RSA public key is embedded in the game**, which means the
helper's key is exchanged at handshake time — so a clean-room helper can present
its own RSA key rather than needing DeNA's private key.

The exact handshake framing could not be fully recovered from the 8 MB Envoy-
based official helper by static analysis alone. The replacement helper isolates
this in a single `SessionCrypto` seam
([`loader/helper_server.cpp`](../loader/helper_server.cpp)); confirm it against
one captured handshake (§5).

---

## 4. Payment stub (no piracy)

The replacement helper answers the billing verbs **safely**:
* `is_billing_supported` → `false` (store UI stays disabled)
* `get_products` / `get_purchases` → empty
* `request_purchase*` / `consume_purchase` → **decline** with an error

It **never** emits `paymentSucceed` and never fabricates entitlements or
receipts.

## 4a. TLS validation & pinning bypass (loader)

FFBE's HTTPS runs through libcurl → OpenSSL. Verification is neutralized in
memory at both layers so a recreated server's self-signed / mismatched cert is
accepted and any certificate pinning is defeated:

* OpenSSL: `X509_verify_cert`→1, `SSL_get_verify_result`→X509_V_OK, and
  `SSL_CTX_set_verify` / `SSL_set_verify` / `SSL_CTX_set_cert_verify_callback`
  made no-ops (leaves the default client `VERIFY_NONE`, and prevents a pinning
  callback from replacing the neutralized default check).
* libcurl (its own hostname match + pin live here, not in OpenSSL):
  `curl_easy_setopt` is filtered — `SSL_VERIFYPEER`/`VERIFYHOST`/`VERIFYSTATUS`
  forced to 0, `PINNEDPUBLICKEY` and `SSL_CTX_FUNCTION` dropped.

libcurl is imported by `libcocos2d.dll`, not by the exe, so the `curl_easy_setopt`
hook is installed across every loaded module (`hooks.cpp:iat_hook_all_modules`),
with a ~10 s retry for lazily-loaded OpenSSL/curl. See `loader/hooks.cpp`
`install_ssl_bypass()`.

### CEF (embedded Chromium) — separate network stack

The game bundles CEF (`libcef.dll`, `chrome_elf.dll`, `cef*.pak`, v8 snapshots,
`icudtl.dat`, `widevinecdmadapter.dll`, `locales/`), so login / portal / store
screens are almost certainly Chromium webviews. **CEF has its own network stack
and TLS (BoringSSL inside `libcef.dll`)** — the libcurl/OpenSSL bypass does not
touch it, and CEF runs networking in child processes that may not load our DLL.

CEF is instead relaxed with Chromium command-line switches
(`loader/cef_hook.cpp`), which must be present before `cef_initialize`:

* The loader inline-patches `GetCommandLineW` (synchronously in `DllMain`, before
  the exe entrypoint) to append:
  `--ignore-certificate-errors`, `--ignore-urlfetcher-cert-requests`,
  `--allow-running-insecure-content`, `--test-type`, optionally
  `--disable-web-security`, and
  `--host-resolver-rules="MAP <host> <ip>,…,EXCLUDE localhost"` built from the
  `[dns]` table. Because CEF reuses `FF_EXVIUS.exe` as its subprocess (no
  separate CEF helper exe ships), every CEF process loads our winmm.dll and gets
  the switches; a `CreateProcessW` hook re-appends them to any `--type=` child as
  a safeguard (dedup-guarded).
* Governed by the ini `[cef]` section; `[dns]` feeds both the winsock redirect
  and the Chromium host-resolver rules.

### Known FFBE JP (AndApp) endpoints

The client's server hostnames, to point at a preservation server via `[dns]`:

| Host | Role |
|---|---|
| `v53-ios.game.exvius.com` | game API / session |
| `v53.notice.exvius.com`   | notices / news |
| `cdn.resource.exvius.com` | asset CDN (masters, images, …) |

(`v53` is the API version prefix; it advances with major game versions.) The game also has server-side reverify flags (`ForcePurchaseReverify`,
`BUY_COIN_REVERIFY_*`), so spoofing a local success would fail reverification
anyway — declining is both the honest and the robust choice.

---

## 5. Confirming the handshake with the packet-logging helper

The patched `AndAppNextHelper.exe` (accepts any cert, logs packets) can capture
one real SDK↔helper session:

1. Run the patched helper + game once; collect its packet log next to the game.
2. Look at the very first bytes on the **command** socket after connect — that is
   the handshake. Identify: any length prefix, the RSA-wrapped AES key blob, and
   where JSON begins.
3. Fill in `SessionCrypto::negotiate()/decode()/encode()` in
   `loader/helper_server.cpp` to match (framing + AES-128-CBC with the negotiated
   key). The JSON verb handlers above it are already complete.

Until then the helper runs in pass-through (newline-framed plaintext JSON) mode
and logs raw byte counts so its framing can be diffed against the capture.

---

## 6. `manifest.json` + `signature` file — AndApp integrity (not the game's)

`manifest.json` (v11 sample: `versionCode 124`, `versionName 11.0.0`,
`clientId 5701868182306816`, `entryPointBaseName FF_EXVIUS.exe`) is AndApp's file
inventory. Its `signature[]` array holds one entry per shipped file
(`bin/*.exe`, the root DLLs, and the exe): `{path, signature}`. The sibling
`signature` file is a single value covering `manifest.json` itself.

**Format.** Every signature (per-file and the top-level one) decodes to exactly
**64 bytes** — an **asymmetric signature** (ECDSA-P256 `r‖s`, or Ed25519), made
with DeNA's private key. Ruled out by testing against `zlib1.dll`: it is **not**
SHA-512/384/SHA3-512/BLAKE2b, and **not** HMAC-SHA512 over the file, path+file,
or the file's hash, across the obvious embedded keys (clientId, versionName,
"andapp", …). Being asymmetric, these **cannot be regenerated** without DeNA's
private key.

**Who verifies it.** Only the AndApp launcher / BootHelper (install + launch
integrity). The **game does not**:
* `FF_EXVIUS.exe` imports from `libcrypto-1_1.dll` are symmetric-only
  (AES-128 CBC/ECB, MD5) — **no** `ECDSA_verify` / `EVP_DigestVerify` / `EC_KEY`
  / `d2i_PUBKEY`, and no `CryptVerifySignature` from advapi32.
* The only game reference to `manifest.json` is in `SdkUtils.cpp`, which parses
  `versionCode` / `versionName` / `platform` / `architecture` /
  `entryPointBaseName` to populate the SDK's `initialize` payload — it never
  reads the `signature` array.

**Consequence for preservation.** Launched directly (our winmm loader replacing
AndApp), **nothing verifies these signatures**, so patched files — a modified
exe, patched OpenSSL DLLs, our `winmm.dll` — run fine. **No in-game
"ignore-signature" hook is needed.** (An integrity bypass would only matter if
you launched *through* AndApp, which this project avoids.)

**Tooling.** None is shipped: because the signatures are asymmetric and can't be
regenerated without DeNA's private key, and because the game never verifies them,
there is nothing to generate. If you ever need a manifest for your own tooling,
copy the shipped one and edit the version fields — the `signature` array is inert
for a direct (non-AndApp) launch.

> Versions: the CCZ key is **unchanged across v10 and v11** — the same four key
> parts decrypt both `VersionAndApp.xml` files (v10 → 10.0.0, v11 → 11.0.0), and
> the v11 `FF_EXVIUS.exe` sets them at RVA `0x00759022`. The `manifest.json`
> sample is v11 (`versionCode 124`). `clientId 5701868182306816` there is the
> AndApp *application* id, distinct from the SDK build id `ab6198d`.
