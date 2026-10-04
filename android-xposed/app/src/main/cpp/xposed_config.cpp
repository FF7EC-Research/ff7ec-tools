// xposed_config.cpp - this module's own, not shared with android-patches/shim.
// Sets the config fields this module wants different from the shim's
// defaults (which are tuned for the Morphe patch's own options UI) before
// Ff7ecShimBridge.init() calls into the shared nativeInit().
#include <jni.h>
#include "config.h"

extern "C" JNIEXPORT void JNICALL
Java_dev_ff7ecpreservation_extension_Ff7ecShimBridge_configureXposed(JNIEnv*, jclass) {
    shim::Config& cfg = shim::config();
    cfg.ssl_bypass = false;               // passive logging only, no need to touch TLS
    cfg.log_dir_absolute = "/sdcard/ff7ec-logs";
}
