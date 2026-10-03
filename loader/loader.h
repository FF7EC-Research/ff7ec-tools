// loader.h - shared declarations for the FF7EC traffic-inspection loader
// (winmm proxy).
//
// What this is: a drop-in winmm.dll for a *preservation* copy of FF7 Ever
// Crisis you own, used entirely on your own machine against your own game
// client. It redirects the game's own outgoing API-host lookups to a local
// TLS-terminating proxy (so the already-decided-to-be-shut-down traffic can
// be recorded and understood before the servers disappear), decrypts the
// game's own request/response bodies using the public key material documented
// in this project's sibling ff7ecapi research repo, and writes a readable log.
// It never touches any host other than 127.0.0.1 and the game's own real
// server, never fabricates server responses, and never installs anything
// outside the game folder unless the user explicitly opts in (install_ca).
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <cstdint>

namespace loader {

// ---- logging (loader diagnostics -> ff7ec_loader.log) ---------------------------
void log_init(const std::wstring& path, bool enabled);
void logf(const char* fmt, ...);

// ---- config (.ini) --------------------------------------------------------------
struct Config {
    bool   log_enabled      = true;
    std::wstring log_path;                       // default: <dll dir>\ff7ec_loader.log

    // [dns] - answer the game's own lookups with redirect_ip, so its traffic
    // lands on our local proxy instead of going straight to the real host.
    bool   dns_redirect_all = true;
    std::string redirect_ip = "127.0.0.1";
    std::vector<std::string> dns_exclude;        // exact hostnames never redirected
    std::vector<std::string> dns_only;           // if non-empty: only these suffixes

    // [mitm] - local decrypting proxy: terminates the game's TLS connection
    // with one static, locally-generated certificate, then opens its own
    // normal outbound connection to the real server and relays between them.
    bool   mitm_enabled     = true;
    std::string bind_ip     = "127.0.0.1";
    std::vector<int> ports  = {443};
    bool   upstream_verify  = true;              // validate the REAL server's cert
    std::wstring traffic_log;                    // default: <dll dir>\ff7ec_traffic.log
    std::wstring capture_dir;                    // default: <dll dir>\ff7ec_captures
    bool   save_bodies      = true;
    size_t max_body_log     = 4096;              // body bytes echoed into the text log
    size_t max_body_capture = 64u << 20;         // largest body buffered/decoded
    // Off by default: the game already accepts our certificate because its own
    // validation is disabled by [ssl]. This only matters if you also want a
    // browser/webview on this machine to trust it without a warning.
    bool   install_ca       = false;

    // [ssl] - make the game's own TLS stack accept our local proxy's
    // certificate (which is self-signed and not otherwise trusted).
    bool   ssl_bypass       = true;
};

Config& config();
bool load_config(const std::wstring& ini_path);
std::wstring dll_directory();
std::wstring resolve_path(const std::wstring& p, const std::wstring& def_name);

// ---- hooks ------------------------------------------------------------------------
// Set on threads the proxy itself owns: its *upstream* leg (to the real game
// server) must do a normal, real TLS validation, so the bypass/redirect hooks
// below stand down on those threads - only the game's own threads are affected.
extern thread_local bool t_proxy_thread;

bool force_return(void* func, uint32_t ret_val);
int  iat_hook_all_modules(const char* import_dll, const char* func,
                          void* replacement, void** original);
void install_dns_hooks();       // getaddrinfo / GetAddrInfoW, across all modules
void install_ssl_bypass();      // make the game accept our proxy's certificate

// ---- certificate (single, static, self-signed; not a CA) ------------------------
// One RSA certificate+key, generated on first run and cached under the game
// folder. It signs nothing else and is used only as this proxy's TLS server
// certificate, matching the same shape mitmproxy/Fiddler/Charles use for local
// interception. install_ca_to_user_root() is a separate, opt-in convenience
// for making *other* local apps (not the game) trust it too.
bool identity_init(const std::wstring& dir);
void* identity_cert_context();          // PCCERT_CONTEXT, opaque here
std::wstring identity_cert_path();
bool install_ca_to_user_root();

// ---- proxy ----------------------------------------------------------------------
bool start_mitm();              // opens listeners; returns false if none could bind

}  // namespace loader
