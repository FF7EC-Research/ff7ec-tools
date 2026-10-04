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
request and response bodies to the game's own app-private folder:
`/sdcard/Android/data/com.square_enix.android_googleplay.ff7ecww/files/ff7ec_logs/`
- same place and same mechanism (`getExternalFilesDir()`) the Morphe
patch itself used, needing no storage permission at all (an app's own
external-files directory is always exempt from scoped storage). TLS
bypass and DNS redirect are off; this is passive logging only. See
`../android-patches/README.md`'s "Architecture" section for how the
shim itself works (dlsym interposition into YAHA, gRPC frame splitting,
protobuf dumping) - all of that is unchanged, just loaded a different
way.

## Requirements

- A rooted device (or one with a systemless root method) running
  **LSPosed** (or another active Xposed implementation - EdXposed,
  etc.). This cannot work without one; Xposed hooking requires a
  framework already running with elevated privileges on the device.
- Android 8.1+ (`minSdk 27`, matching LSPosed's own floor).

Or skip building it yourself entirely: CI
([`.github/workflows/android-xposed-release.yml`](../.github/workflows/android-xposed-release.yml))
builds and publishes this on every push under `android-xposed/`, to this
repo's `xposedmod` release tag - grab `app-release.apk` from there.

## Building

```sh
export ANDROID_SDK_ROOT=/path/to/android-sdk   # needs platform 36, NDK r26+, cmake 3.22+
cd android-xposed
./gradlew :app:assembleRelease
```

Output: `app/build/outputs/apk/release/app-release.apk` - already signed
(with the committed `debug.keystore`, not a secret - see
`app/build.gradle.kts` for why) and ready to `adb install`. Then enable
it for FF7 Ever Crisis in LSPosed's manager app and reboot/force-stop the
game.

No private registry credentials needed (unlike `../android-patches`) -
this is a plain Android app module plus the public XposedBridge API jar
(`de.robv.android.xposed:api:82`, from `https://api.xposed.info/`).

## Finding the logs

No special storage permission needed - the write happens from inside
FF7EC's own process under FF7EC's own UID, into FF7EC's own
`getExternalFilesDir()`, which is always exempt from scoped storage
regardless of Android version:

```
/sdcard/Android/data/com.square_enix.android_googleplay.ff7ecww/files/ff7ec_logs/
```

If nothing shows up there, `shim::log_directory()`
(`../android-patches/shim/android_bridge.cpp`) silently returns an empty
path and skips logging rather than crashing - check that the hook fired
at all (LSPosed's own logs, or the module's Xposed log entries) before
assuming it's a permissions problem.

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
  module's own `xposed_config.cpp` (sets `ssl_bypass = false` before the
  shared `nativeInit()` runs - everything else about the shim's behavior,
  including where it logs to, is unchanged from the patch's copy).

## Verification status

**Not yet tested on-device.** Builds clean locally (Java compiles, native
library links against only standard system libraries - `liblog.so`,
`libandroid.so`, `libm.so`, `libdl.so`, `libc.so`, no `libc++_shared.so`
dependency to resolve across APKs since this links `c++_static` - and
both JNI exports, `configureXposed` and `nativeInit`, are present and
correctly named per `llvm-nm`), but the actual LSPosed hook, native
library loading into another app's process, and the actual log write
have not been confirmed against the real game yet.
