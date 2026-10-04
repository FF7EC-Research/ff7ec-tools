// bridge.cpp - the native side of dev.ff7ecpreservation.extension.Ff7ecShimBridge.
// JNI_OnLoad does nothing by itself (deliberately): all hook installation
// waits for nativeInit(context) below, called from Ff7ecShimBridge.init()
// right after it System.loadLibrary()s this .so - see Ff7ecShimBridge.java
// for why loadLibrary lives there now rather than in the smali hook.
#include <jni.h>
#include "android_bridge.h"
#include "config.h"
#include "yaha_shim.h"
#include "dns_hook.h"
#include <android/log.h>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

extern "C" JNIEXPORT void JNICALL
Java_dev_ff7ecpreservation_extension_Ff7ecShimBridge_nativeInit(JNIEnv* env, jclass, jobject context) {
    LOGT("bridge: nativeInit() called from EntryApplication.attachBaseContext");
    shim::bridge_init(env, context);
    LOGT("bridge: bridge_init() done");
    shim::load_config(env, context);
    LOGT("bridge: load_config() done");
    shim::install_yaha_hooks();
    LOGT("bridge: install_yaha_hooks() done");
    if (shim::config().dns_redirect || shim::config().packet_log) shim::install_dns_hook();
    LOGT("bridge: nativeInit() done");
}
