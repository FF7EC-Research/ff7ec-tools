// xposed_config.cpp - this module's own, not shared with android-patches/shim.
// Sets the config fields this module wants different from the shim's
// defaults (which are tuned for the Morphe patch's own options UI) before
// Ff7ecShimBridge.init() calls into the shared nativeInit().
#include <jni.h>
#include "config.h"

extern "C" JNIEXPORT void JNICALL
Java_dev_ff7ecpreservation_extension_Ff7ecShimBridge_configureXposed(JNIEnv*, jclass) {
    shim::Config& cfg = shim::config();
    cfg.ssl_bypass = false;  // passive logging only, no need to touch TLS
    // log_dir_absolute deliberately left empty: log_directory()
    // (android_bridge.cpp) then falls back to getExternalFilesDir() - the
    // game's own app-private folder under
    // /sdcard/Android/data/<package>/files/ff7ec_logs/, which needs no
    // storage permission at all (it's always exempt from scoped storage,
    // unlike /sdcard/ff7ec-logs/ which needed MANAGE_EXTERNAL_STORAGE
    // granted to the game on Android 11+). Same behavior as the Morphe
    // patch's own copy - see android-patches/README.md.
}
