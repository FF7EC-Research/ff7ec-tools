// android_bridge.h - the cached JavaVM/Context, Toast helper, and log-file
// path helper. All JNI calls that need to run on threads the JVM doesn't
// already know about (our hook trampolines, called from arbitrary Rust/libc
// threads) attach via AttachCurrentThread first.
#pragma once
#include <jni.h>
#include <string>

namespace shim {

// Called once from the Java bridge's native init() (see bridge.cpp). Caches
// the JavaVM and a global ref to the Application context.
void bridge_init(JNIEnv* env, jobject android_context);

// Shows a short Toast on the main thread. Safe to call from any thread.
void show_toast(const std::string& text);

// Returns getExternalFilesDir(null) + "/" + config().log_dir_name, creating
// the directory if needed - no storage permission required, this is always
// the calling app's own directory. Empty string if the context isn't ready
// yet or the directory couldn't be created.
std::string log_directory();

}  // namespace shim
