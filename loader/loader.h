// loader.h - shared declarations for the AndApp preservation loader (winmm proxy)
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <cstdint>

namespace loader {

// ---- logging -----------------------------------------------------------------
void log_init(const std::wstring& path, bool enabled);
void logf(const char* fmt, ...);

// ---- config (.ini) -----------------------------------------------------------
struct Config {
    bool   log_enabled          = true;
    std::wstring log_path;                       // default: <dll dir>\andapp_loader.log

    // AndAppHelper replacement (TCP)
    bool   helper_enabled       = true;
    int    command_port         = 51100;         // standard.tcp.command.ipv4.port
    int    notification_port    = 51101;         // standard.tcp.notification.ipv4.port
    bool   write_cfg            = true;          // write %LOCALAPPDATA%\AndApp\AndAppHelper.cfg
    std::string player_id       = "1000000000000000";
    std::string id_token;                        // optional pre-baked token; else synthesized

    // SSL / cert verification bypass (runtime, in-memory)
    bool   ssl_bypass           = true;

    // Mutex neutralization (launch without the official AndApp installed)
    bool   mutex_fix            = true;

    // CEF (embedded Chromium) command-line injection for webview screens
    bool   cef_enabled          = true;   // inject switches into libcef
    bool   cef_ignore_cert      = true;   // --ignore-certificate-errors etc.
    bool   cef_disable_websec   = false;  // --disable-web-security
    bool   cef_host_rules       = true;   // build --host-resolver-rules from [dns]
    std::string cef_extra_switches;       // freeform, appended verbatim

    // DNS redirects: hostname (lower-case) -> IPv4 string
    std::map<std::string, std::string> dns;
};

Config& config();
bool load_config(const std::wstring& ini_path);
std::wstring dll_directory();

// ---- hook installers ---------------------------------------------------------
// IAT hook helper: replace every import of (module, func) in the main image.
bool iat_hook(const char* import_dll, const char* func, void* replacement,
              void** original);

// IAT hook across every loaded module (returns how many modules were patched).
int iat_hook_all_modules(const char* import_dll, const char* func,
                         void* replacement, void** original);

// Force a function's prologue to `mov eax, ret_val; ret` (cdecl no-op).
bool force_return(void* func, uint32_t ret_val);

void install_dns_hooks();     // getaddrinfo / GetAddrInfoW / gethostbyname
void install_mutex_hooks();   // CreateMutexW / CreateMutexExW
void install_ssl_bypass();    // openssl X509_verify_cert / SSL_get_verify_result / libcurl

// CEF (embedded Chromium) support.
// Must run BEFORE cef_initialize, so it is installed synchronously in DllMain.
void install_cef_cmdline_hook();   // inline-hook GetCommandLineW to append switches
void install_process_hooks();      // CreateProcessW: propagate switches to CEF children
std::string cef_switch_string();   // the switches we inject (for logging/reuse)

// ---- AndApp helper TCP server ------------------------------------------------
void start_helper_server();   // spawns listener threads; writes AndAppHelper.cfg

}  // namespace loader
