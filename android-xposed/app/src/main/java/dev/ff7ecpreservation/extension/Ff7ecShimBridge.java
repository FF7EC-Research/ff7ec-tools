package dev.ff7ecpreservation.extension;

import android.content.Context;

/**
 * Same shape as android-patches/extensions/ff7ec's class of the same name
 * (and the same package, so the native side's JNI symbol names -
 * Java_dev_ff7ecpreservation_extension_Ff7ecShimBridge_* - work unchanged)
 * - this is a separate declaration, not a shared file, because this
 * module and the Morphe patch build two entirely separate APKs/.so's that
 * never coexist in the same classloader.
 *
 * Called from Ff7ecXposedModule's attachBaseContext hook once Xposed has
 * loaded this module's own native library into the game's process -
 * loadLibrary has to happen from Java (JNI_OnLoad alone can't call back
 * into nativeInit with a Context), so it lives here rather than in the
 * hook callback itself, matching why the Morphe patch does the same.
 */
public final class Ff7ecShimBridge {
    private Ff7ecShimBridge() {}

    public static void init(Context context) {
        System.loadLibrary("ff7ec_shim");
        configureXposed();
        nativeInit(context);
    }

    // xposed_config.cpp, not the shared shim - sets config().ssl_bypass =
    // false and config().log_dir_absolute = "/sdcard/ff7ec-logs" before
    // nativeInit() installs the hooks and reads them.
    private static native void configureXposed();

    private static native void nativeInit(Context context);
}
