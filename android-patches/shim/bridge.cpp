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

// TEMPORARY bisection control, not a permanent feature - see
// ../../../../README.md's "Bisecting the silent SIGABRT" for why this
// exists. Every logcat/tombstone capture so far shows this exact SIGABRT:
// no Abort message, a 3-frame unwind debuggerd can't get past, identical
// registers every time, and critically: not even this function's own
// *first* LOGT call ever reaches logcat, even with logging armed and
// running continuously before launch. That either means something before
// nativeInit() can run at all is the actual cause, or something in here
// is fatal before __android_log_print's result would be visible. Stage 0
// isolates the former: if the app still crashes identically with every
// one of these calls skipped, the bug is not in this function's body at
// all, and the next place to look is the JNI boundary / dex merge rather
// than shim logic. Raise this one stage at a time (commit per stage) once
// a stage survives, to find exactly which call is fatal.
#ifndef FF7EC_DIAG_STAGE
#define FF7EC_DIAG_STAGE 0
#endif

extern "C" JNIEXPORT void JNICALL
Java_dev_ff7ecpreservation_extension_Ff7ecShimBridge_nativeInit(JNIEnv* env, jclass, jobject context) {
#if FF7EC_DIAG_STAGE >= 1
    LOGT("bridge: nativeInit() called from EntryApplication.attachBaseContext");
#endif
#if FF7EC_DIAG_STAGE >= 2
    shim::bridge_init(env, context);
    LOGT("bridge: bridge_init() done");
#endif
#if FF7EC_DIAG_STAGE >= 3
    shim::load_config(env, context);
    LOGT("bridge: load_config() done");
#endif
#if FF7EC_DIAG_STAGE >= 4
    shim::install_yaha_hooks();
    LOGT("bridge: install_yaha_hooks() done");
#endif
#if FF7EC_DIAG_STAGE >= 5
    if (shim::config().dns_redirect || shim::config().packet_log) shim::install_dns_hook();
    LOGT("bridge: nativeInit() done");
#endif
#if FF7EC_DIAG_STAGE == 0
    (void)env; (void)context;
#endif
}
