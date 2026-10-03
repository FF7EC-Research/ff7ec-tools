// bridge.cpp - the native side of dev.ff7ecpreservation.extension.Ff7ecShimBridge.
// JNI_OnLoad does nothing by itself (deliberately): all hook installation
// waits for init(context) below, so we have a Context before the first Toast
// or log write - attachBaseContext() calls loadLibrary() then init() back to
// back, so the gap is negligible.
#include <jni.h>
#include "android_bridge.h"
#include "config.h"
#include "yaha_shim.h"
#include "dns_hook.h"
#include <android/log.h>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

extern "C" JNIEXPORT void JNICALL
Java_dev_ff7ecpreservation_extension_Ff7ecShimBridge_init(JNIEnv* env, jclass, jobject context) {
    LOGT("bridge: init() called from EntryApplication.attachBaseContext");
    shim::bridge_init(env, context);
    shim::load_config(env, context);
    shim::install_yaha_hooks();
    if (shim::config().dns_redirect || shim::config().packet_log) shim::install_dns_hook();
}
