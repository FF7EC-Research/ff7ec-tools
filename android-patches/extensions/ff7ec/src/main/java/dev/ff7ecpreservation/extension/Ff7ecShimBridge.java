package dev.ff7ecpreservation.extension;

import android.content.Context;

/**
 * Bundled by the Morphe patch as a precompiled "extension" class (same
 * convention ReVanced/Morphe patches use for a small Java helper that smali
 * can call directly, rather than hand-writing the equivalent in bytecode).
 *
 * The patch inserts two calls at the very top of EntryApplication's
 * attachBaseContext(Context), before any game/Unity/network code runs:
 *   System.loadLibrary("ff7ec_shim");
 *   Ff7ecShimBridge.init(this);
 *
 * init() caches the JavaVM/Context (for Toasts and the log directory) and
 * installs every hook. See shim.cpp for the native side.
 */
public final class Ff7ecShimBridge {
    private Ff7ecShimBridge() {}

    public static native void init(Context context);
}
