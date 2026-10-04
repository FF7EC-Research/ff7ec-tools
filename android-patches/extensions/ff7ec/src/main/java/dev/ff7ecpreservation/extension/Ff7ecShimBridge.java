package dev.ff7ecpreservation.extension;

import android.content.Context;

/**
 * Bundled by the Morphe patch as a precompiled "extension" class (same
 * convention ReVanced/Morphe patches use for a small Java helper that smali
 * can call directly, rather than hand-writing the equivalent in bytecode).
 *
 * The patch inserts exactly one call at the very top of EntryApplication's
 * attachBaseContext(Context base), before any game/Unity/network code runs:
 *   Ff7ecShimBridge.init(base);   // p1, NOT p0/"this" - see below
 *
 * The argument is attachBaseContext's own `base` parameter (p1), never the
 * EntryApplication instance itself (p0/"this"). This code runs *before* the
 * original method body's super.attachBaseContext(base) call, which is what
 * assigns ContextWrapper's mBase - so any Context method called on "this"
 * at this point (getAssets(), getExternalFilesDir(), ...) dereferences a
 * null mBase. Confirmed on-device: a native SIGABRT ("JNI DETECTED ERROR IN
 * APPLICATION: obj == null in call to GetLongField", inside
 * AAssetManager_fromJava) from context.getAssets() returning null in
 * config.cpp's load_config(). `base` is the system-supplied Context,
 * already fully valid regardless of whether super.attachBaseContext() has
 * run yet.
 *
 * init() is also a *non-native* wrapper specifically so the smali injected
 * by the patch never has to hold a System.loadLibrary() string constant in
 * a scratch register of its own: invoke-static {p1}, ...init(Context)V
 * reads only an already-valid register, so it verifies regardless of how
 * many (if any) local registers attachBaseContext was compiled with -
 * unlike an earlier two-instruction version (const-string v0, ... ;
 * loadLibrary(v0) ...), which clobbered p0 itself on a `.locals 0` method
 * and crashed every launch with a VerifyError. See ../../../../README.md.
 */
public final class Ff7ecShimBridge {
    private Ff7ecShimBridge() {}

    public static void init(Context context) {
        System.loadLibrary("ff7ec_shim");
        nativeInit(context);
    }

    private static native void nativeInit(Context context);
}
