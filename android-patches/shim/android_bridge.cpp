// android_bridge.cpp - see android_bridge.h.
#include "android_bridge.h"
#include "config.h"
#include <android/log.h>
#include <sys/stat.h>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

namespace shim {

static JavaVM* g_vm = nullptr;
static jobject g_context = nullptr;   // global ref
static std::string g_log_dir_cache;

void bridge_init(JNIEnv* env, jobject android_context) {
    env->GetJavaVM(&g_vm);
    g_context = env->NewGlobalRef(android_context);
}

namespace {
struct ScopedEnv {
    JNIEnv* env = nullptr;
    bool attached = false;
    ScopedEnv() {
        if (!g_vm) return;
        if (g_vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (g_vm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true;
        }
    }
    ~ScopedEnv() { if (attached && g_vm) g_vm->DetachCurrentThread(); }
};
}  // namespace

void show_toast(const std::string& text) {
    if (!g_vm || !g_context) { LOGT("toast (no context yet): %s", text.c_str()); return; }
    ScopedEnv se;
    if (!se.env) return;
    JNIEnv* env = se.env;

    jclass toast_cls = env->FindClass("android/widget/Toast");
    jmethodID make_text = env->GetStaticMethodID(toast_cls, "makeText",
        "(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;");
    jstring jtext = env->NewStringUTF(text.c_str());
    jobject toast = env->CallStaticObjectMethod(toast_cls, make_text, g_context, jtext, /*LENGTH_SHORT*/0);
    jobject toast_global = env->NewGlobalRef(toast);

    // Toast.show() must run on a thread with a Looper - post it to the main one.
    jclass looper_cls = env->FindClass("android/os/Looper");
    jmethodID get_main = env->GetStaticMethodID(looper_cls, "getMainLooper", "()Landroid/os/Looper;");
    jobject main_looper = env->CallStaticObjectMethod(looper_cls, get_main);
    jclass handler_cls = env->FindClass("android/os/Handler");
    jmethodID handler_ctor = env->GetMethodID(handler_cls, "<init>", "(Landroid/os/Looper;)V");
    jobject handler = env->NewObject(handler_cls, handler_ctor, main_looper);

    jclass toast_runner_cls = env->FindClass("java/lang/Runnable");
    (void)toast_runner_cls;
    // Simplest cross-API way to run `toast.show()` on the main thread without a
    // bespoke Runnable class: Handler.post(Runnable) needs a real Runnable
    // object, which the bridge extension class provides (ToastRunner wraps a
    // Toast and calls .show() from run()). See extension/ToastRunner.java.
    jclass runner_cls = env->FindClass("dev/ff7ecpreservation/extension/ToastRunner");
    jmethodID runner_ctor = env->GetMethodID(runner_cls, "<init>", "(Landroid/widget/Toast;)V");
    jobject runner = env->NewObject(runner_cls, runner_ctor, toast_global);
    jmethodID post = env->GetMethodID(handler_cls, "post", "(Ljava/lang/Runnable;)Z");
    env->CallBooleanMethod(handler, post, runner);

    env->DeleteGlobalRef(toast_global);
    LOGT("toast: %s", text.c_str());
}

std::string log_directory() {
    if (!g_log_dir_cache.empty()) return g_log_dir_cache;
    if (!config().log_dir_absolute.empty()) {
        mkdir(config().log_dir_absolute.c_str(), 0755);
        g_log_dir_cache = config().log_dir_absolute;
        return g_log_dir_cache;
    }
    if (!g_vm || !g_context) return "";
    ScopedEnv se;
    if (!se.env) return "";
    JNIEnv* env = se.env;

    jclass ctx_cls = env->GetObjectClass(g_context);
    jmethodID get_ext = env->GetMethodID(ctx_cls, "getExternalFilesDir",
        "(Ljava/lang/String;)Ljava/io/File;");
    jobject file = env->CallObjectMethod(g_context, get_ext, nullptr);
    if (!file) return "";
    jclass file_cls = env->GetObjectClass(file);
    jmethodID get_path = env->GetMethodID(file_cls, "getAbsolutePath", "()Ljava/lang/String;");
    jstring jpath = (jstring)env->CallObjectMethod(file, get_path);
    const char* path = env->GetStringUTFChars(jpath, nullptr);

    std::string dir = std::string(path) + "/" + config().log_dir_name;
    env->ReleaseStringUTFChars(jpath, path);
    mkdir(dir.c_str(), 0755);
    g_log_dir_cache = dir;
    return dir;
}

}  // namespace shim
