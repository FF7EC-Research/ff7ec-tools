// config.h - reads assets/ff7ec_shim.cfg (baked into the APK by the Morphe
// patch options at patch time, same key=value style as the PC loader's .ini).
#pragma once
#include <jni.h>
#include <string>

namespace shim {

struct Config {
    bool        ssl_bypass          = true;
    bool        packet_log          = true;
    bool        dns_redirect        = false;   // off by default: logging doesn't need it
    std::string redirect_ip;                   // the Morphe patch option text field
    std::string log_dir_name        = "ff7ec_logs";
};

Config& config();
// Reads the asset via the Java Context's AssetManager (cached from the bridge
// init call - see bridge.cpp). Missing file/keys keep the defaults above.
bool load_config(JNIEnv* env, jobject android_context);

}  // namespace shim
