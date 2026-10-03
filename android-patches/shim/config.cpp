// config.cpp - see config.h.
#include "config.h"
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <vector>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

namespace shim {

static Config g_cfg;
Config& config() { return g_cfg; }

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
static bool truthy(const std::string& s) { return s == "1" || s == "true" || s == "yes"; }

bool load_config(JNIEnv* env, jobject android_context) {
    jclass ctx_cls = env->GetObjectClass(android_context);
    jmethodID get_assets = env->GetMethodID(ctx_cls, "getAssets", "()Landroid/content/res/AssetManager;");
    jobject jassets = env->CallObjectMethod(android_context, get_assets);
    AAssetManager* mgr = AAssetManager_fromJava(env, jassets);
    AAsset* asset = mgr ? AAssetManager_open(mgr, "ff7ec_shim.cfg", AASSET_MODE_BUFFER) : nullptr;
    if (!asset) { LOGT("config: assets/ff7ec_shim.cfg not found, using defaults"); return false; }

    off_t len = AAsset_getLength(asset);
    std::vector<char> buf(len + 1, 0);
    AAsset_read(asset, buf.data(), len);
    AAsset_close(asset);

    std::string text(buf.data(), len);
    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = trim(text.substr(pos, eol - pos));
        pos = eol + 1;
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq)), val = trim(line.substr(eq + 1));
        if (key == "ssl_bypass") g_cfg.ssl_bypass = truthy(val);
        else if (key == "packet_log") g_cfg.packet_log = truthy(val);
        else if (key == "dns_redirect") g_cfg.dns_redirect = truthy(val);
        else if (key == "redirect_ip") g_cfg.redirect_ip = val;
        else if (key == "log_dir_name") g_cfg.log_dir_name = val;
    }
    LOGT("config: ssl_bypass=%d packet_log=%d dns_redirect=%d redirect_ip='%s'",
         g_cfg.ssl_bypass, g_cfg.packet_log, g_cfg.dns_redirect, g_cfg.redirect_ip.c_str());
    return true;
}

}  // namespace shim
