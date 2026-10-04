package dev.ff7ecpreservation.xposed;

import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import dev.ff7ecpreservation.extension.Ff7ecShimBridge;

/**
 * Hooks FF7 Ever Crisis's own EntryApplication.attachBaseContext(Context)
 * the same way android-patches' Morphe patch does (see its
 * Ff7ecShimPatch.kt) - except here Xposed/LSPosed injects this module
 * into the game's *stock, unmodified* process at app-start instead of the
 * APK itself being bytecode-patched and resigned.
 *
 * Why this exists: the Morphe-patched APK crashes deterministically with
 * a silent, unresolvable native SIGABRT, confirmed (by a diagnostic build
 * where the patch's native entry point does nothing at all and the game
 * *still* crashes the same way, see android-patches/README.md's
 * "Bisecting the silent SIGABRT") to be happening somewhere in the
 * original game code *after* the patch's own hook returns - most likely
 * the game's own anti-tamper/signature verification reacting to the APK
 * being resigned, which patching inherently requires and Xposed doesn't.
 */
public class Ff7ecXposedModule implements IXposedHookLoadPackage {
    private static final String PACKAGE_NAME = "com.square_enix.android_googleplay.ff7ecww";
    private static final String ENTRY_APPLICATION_CLASS =
            "com.square_enix.android_googleplay.ff7ecww.EntryApplication";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!PACKAGE_NAME.equals(lpparam.packageName)) return;

        XposedHelpers.findAndHookMethod(
                ENTRY_APPLICATION_CLASS,
                lpparam.classLoader,
                "attachBaseContext",
                Context.class,
                new de.robv.android.xposed.XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        try {
                            // param.args[0] is attachBaseContext's own `base`
                            // parameter - already a fully valid Context at
                            // this point, regardless of whether
                            // super.attachBaseContext() has run yet (the
                            // Morphe patch hit this exact footgun passing
                            // "this" instead - see android-patches/README.md).
                            Ff7ecShimBridge.init((Context) param.args[0]);
                        } catch (Throwable t) {
                            XposedBridge.log("ff7ec_xposed: hook init failed: " + t);
                        }
                    }
                });
    }
}
