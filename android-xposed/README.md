# FF7EC traffic logger (Xposed/LSPosed module)

A new approach after `../android-patches` hit a wall: that patch bytecode-
patches and resigns the game's APK, and the resigned APK crashes
deterministically with a silent, unresolvable native `SIGABRT` - confirmed
(by a diagnostic build where the patch's native entry point does nothing
at all and the game *still* crashed the same way) to be happening
somewhere in the game's own original code, not anything the patch itself
runs. See `../android-patches/README.md`'s "Bisecting the silent
SIGABRT" for the full investigation. Leading theory: the game's own
anti-tamper/signature verification reacting to the APK being resigned,
which patching inherently requires.

This module sidesteps that entirely: it never touches the game's APK.
Xposed/LSPosed loads it into the game's **stock, unmodified, originally-
signed** process at startup instead, and hooks
`EntryApplication.attachBaseContext(Context)` the same way the Morphe
patch did - same effect, no repackaging, no resigning, no anti-tamper
surface to trip.

## What it does

Hooks the game, loads the same native shim `../android-patches/shim`
builds (reused as source, not copied - see
`app/src/main/cpp/CMakeLists.txt`), and logs decrypted gRPC/MagicOnion
request and response bodies to **`/sdcard/ff7ec-logs/`** (shared storage,
not an app-private directory this time - see "Storage permission"
below). TLS bypass and DNS redirect are off; this is passive logging
only. See `../android-patches/README.md`'s "Architecture" section for
how the shim itself works (dlsym interposition into YAHA, gRPC frame
splitting, protobuf dumping) - all of that is unchanged, just loaded a
different way.

## Requirements

- A rooted device (or one with a systemless root method) running
  **LSPosed** (or another active Xposed implementation - EdXposed,
  etc.). This cannot work without one; Xposed hooking requires a
  framework already running with elevated privileges on the device.
- Android 8.1+ (`minSdk 27`, matching LSPosed's own floor).

## Building

```sh
export ANDROID_SDK_ROOT=/path/to/android-sdk   # needs platform 36, NDK r26+, cmake 3.22+
cd android-xposed
./gradlew :app:assembleRelease
```

Output: `app/build/outputs/apk/release/app-release-unsigned.apk`. Sign it
(any key - LSPosed doesn't care, unlike the game's own anti-tamper check
this approach is specifically avoiding) and install normally
(`adb install`), then enable it for FF7 Ever Crisis in LSPosed's manager
app and reboot/force-stop the game.

No private registry credentials needed (unlike `../android-patches`) -
this is a plain Android app module plus the public XposedBridge API jar
(`de.robv.android.xposed:api:82`, from `https://api.xposed.info/`).

## Storage permission

Logs go to `/sdcard/ff7ec-logs/`, not `getExternalFilesDir()` - deliberate
(the explicit ask was "root of sdcard"), but it means the write happens
from **inside FF7EC's own process**, under FF7EC's own UID, not this
module's. On Android 10 and below that only needs
`WRITE_EXTERNAL_STORAGE`, which this module's manifest declares - but
since the write is attributed to the *game's* UID, the game needs that
permission, not just this module. On Android 11+, shared storage writes
outside an app's own sandbox need `MANAGE_EXTERNAL_STORAGE` granted to
that UID instead, which **cannot be requested via a normal runtime
permission dialog** - it has to be granted manually: Settings → Apps →
Final Fantasy VII Ever Crisis → Permissions → Files and media → Allow
management of all files (wording varies by OEM/Android version), or via
`adb shell appops set com.square_enix.android_googleplay.ff7ecww
MANAGE_EXTERNAL_STORAGE allow`.

If logs aren't appearing, check this first - `shim::log_directory()`
(`../android-patches/shim/android_bridge.cpp`) silently returns an empty
path and skips logging if the directory can't be created, rather than
crashing.

## Files

- `app/src/main/java/dev/ff7ecpreservation/xposed/Ff7ecXposedModule.java`
  - the `IXposedHookLoadPackage` entry point (named in
    `app/src/main/assets/xposed_init`), hooks
    `EntryApplication.attachBaseContext`.
- `app/src/main/java/dev/ff7ecpreservation/extension/Ff7ecShimBridge.java`
  - same shape as `../android-patches/extensions/ff7ec`'s class of the
    same name (own declaration, not shared - see its own comment for
    why), loads the native library and calls into it.
- `app/src/main/cpp/CMakeLists.txt` - builds `libff7ec_shim.so` from
  `../android-patches/shim/*.cpp` directly (not copied) plus this
  module's own `xposed_config.cpp` (sets `ssl_bypass = false` and
  `log_dir_absolute = "/sdcard/ff7ec-logs"` before the shared
  `nativeInit()` runs - everything else about the shim's behavior is
  unchanged from the patch's copy).

## Verification status

**Not yet tested on-device.** Builds clean locally (Java compiles, native
library links against only standard system libraries - `liblog.so`,
`libandroid.so`, `libm.so`, `libdl.so`, `libc.so`, no `libc++_shared.so`
dependency to resolve across APKs since this links `c++_static` - and
both JNI exports, `configureXposed` and `nativeInit`, are present and
correctly named per `llvm-nm`), but the actual LSPosed hook, native
library loading into another app's process, and `/sdcard/ff7ec-logs`
write have not been confirmed against the real game yet.
