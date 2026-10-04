package dev.ff7ecpreservation.extension;

import android.content.Context;

/**
 * Bundled by the Morphe patch as a precompiled "extension" class (same
 * convention ReVanced/Morphe patches use for a small Java helper that smali
 * can call directly, rather than hand-writing the equivalent in bytecode).
 *
 * The patch inserts exactly one call at the very top of EntryApplication's
 * attachBaseContext(Context), before any game/Unity/network code runs:
 *   Ff7ecShimBridge.init(this);
 *
 * init() is a *non-native* wrapper specifically so the smali injected by the
 * patch never has to hold a System.loadLibrary() string constant in a
 * scratch register of its own: invoke-static {p0}, ...init(Context)V reads
 * only the existing p0, so it verifies regardless of how many (if any)
 * local registers attachBaseContext was compiled with - unlike the original
 * two-instruction version (const-string v0, ... ; loadLibrary(v0) ...),
 * which clobbered p0 itself on a `.locals 0` method and crashed every
 * launch with a VerifyError. See ../../../../README.md.
 */
public final class Ff7ecShimBridge {
    private Ff7ecShimBridge() {}

    public static void init(Context context) {
        System.loadLibrary("ff7ec_shim");
        nativeInit(context);
    }

    private static native void nativeInit(Context context);
}
