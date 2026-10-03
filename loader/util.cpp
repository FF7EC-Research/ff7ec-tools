// util.cpp - logging, .ini parsing, config, path helpers.
#include "loader.h"
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include <string>
#include <algorithm>

namespace loader {

static std::wstring g_log_path;
static bool g_log_enabled = true;
static std::mutex g_log_mtx;

std::wstring dll_directory() {
    wchar_t buf[MAX_PATH]{};
    HMODULE h = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)&dll_directory, &h);
    GetModuleFileNameW(h, buf, MAX_PATH);
    std::wstring p(buf);
    size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

void log_init(const std::wstring& path, bool enabled) {
    g_log_path = path;
    g_log_enabled = enabled;
}

void logf(const char* fmt, ...) {
    if (!g_log_enabled || g_log_path.empty()) return;
    char msg[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    SYSTEMTIME st; GetLocalTime(&st);
    char line[2200];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d] %s\r\n",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    std::lock_guard<std::mutex> lk(g_log_mtx);
    FILE* f = _wfopen(g_log_path.c_str(), L"ab");
    if (f) { fputs(line, f); fclose(f); }
    OutputDebugStringA(line);
}

// ---- config ------------------------------------------------------------------
static Config g_cfg;
Config& config() { return g_cfg; }

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}
static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}
static bool truthy(const std::string& v) {
    std::string s = lower(trim(v));
    return s == "1" || s == "true" || s == "yes" || s == "on";
}
static std::vector<std::string> split_list(const std::string& s) {
    std::vector<std::string> out; std::string cur;
    for (char c : s + ",") {
        if (c == ',' || c == ' ') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    return out;
}
static std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

bool load_config(const std::wstring& ini_path) {
    FILE* in = _wfopen(ini_path.c_str(), L"rb");
    if (!in) return false;  // defaults are fine if there's no ini
    char raw[1024];
    std::string section;
    while (fgets(raw, sizeof(raw), in)) {
        std::string t = trim(raw);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        if (t[0] == '[') { section = lower(trim(t.substr(1, t.find(']') - 1))); continue; }
        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string key = lower(trim(t.substr(0, eq)));
        std::string val = t.substr(eq + 1);
        // Strip an inline comment: a ';' or '#' preceded by whitespace. (Our
        // values never contain those chars unescaped, so this is safe.)
        for (size_t i = 0; i < val.size(); ++i) {
            if ((val[i] == ';' || val[i] == '#') &&
                (i == 0 || val[i - 1] == ' ' || val[i - 1] == '\t')) {
                val = val.substr(0, i);
                break;
            }
        }
        val = trim(val);

        if (section == "loader") {
            if (key == "log")          g_cfg.log_enabled = truthy(val);
            else if (key == "logpath") g_cfg.log_path = widen(val);
        } else if (section == "dns") {
            if (key == "redirect_all")      g_cfg.dns_redirect_all = truthy(val);
            else if (key == "redirect_ip")  g_cfg.redirect_ip = val;
            else if (key == "exclude")      g_cfg.dns_exclude = split_list(lower(val));
            else if (key == "only")         g_cfg.dns_only = split_list(lower(val));
        } else if (section == "mitm") {
            if (key == "enabled")               g_cfg.mitm_enabled = truthy(val);
            else if (key == "bind")             g_cfg.bind_ip = val;
            else if (key == "ports") {
                g_cfg.ports.clear();
                for (auto& p : split_list(val)) if (atoi(p.c_str()) > 0) g_cfg.ports.push_back(atoi(p.c_str()));
            }
            else if (key == "upstream_verify")  g_cfg.upstream_verify = truthy(val);
            else if (key == "traffic_log")      g_cfg.traffic_log = widen(val);
            else if (key == "capture_dir")      g_cfg.capture_dir = widen(val);
            else if (key == "save_bodies")      g_cfg.save_bodies = truthy(val);
            else if (key == "max_body_log")     g_cfg.max_body_log = (size_t)atoll(val.c_str());
            else if (key == "max_body_capture") g_cfg.max_body_capture = (size_t)atoll(val.c_str());
            else if (key == "install_ca")       g_cfg.install_ca = truthy(val);
        } else if (section == "ssl") {
            if (key == "bypass") g_cfg.ssl_bypass = truthy(val);
        }
    }
    fclose(in);
    return true;
}

// Relative paths (and empty = default name) are placed next to the DLL.
std::wstring resolve_path(const std::wstring& p, const std::wstring& def_name) {
    std::wstring v = p.empty() ? def_name : p;
    if (v.size() > 1 && (v[1] == L':' || v[0] == L'\\')) return v;
    return dll_directory() + L"\\" + v;
}

}  // namespace loader
