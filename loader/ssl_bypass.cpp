// ssl_bypass.cpp - make the game's own TLS stack accept our local proxy's
// self-signed certificate.
//
// The local proxy (proxy.cpp) presents one static, self-signed certificate
// that is not in any trust store. For the game to complete that TLS handshake
// (rather than reject it as untrusted), its validation needs to be relaxed -
// exactly like the predecessor FFBE preservation loader in this repository's
// history did for its own self-signed preservation server. We never do this
// on the proxy's own upstream connection (t_proxy_thread), which validates
// the real game server normally.
//
// Two backends are covered, since different Unity builds use different ones:
//   - Windows' own TLS (SChannel), used by WinHTTP/WinINet/.NET HttpClient:
//     crypt32!CertVerifyCertificateChainPolicy forced to "trusted".
//   - OpenSSL/libcurl, if the build links/loads a bundled copy:
//     X509_verify_cert / SSL_get_verify_result forced to "trusted", and the
//     pinning-callback installers turned into no-ops.
#include "loader.h"
#include <wincrypt.h>
#include <mutex>
#include <vector>

namespace loader {

// ---- SChannel path: crypt32!CertVerifyCertificateChainPolicy --------------------
typedef BOOL (WINAPI* CertVerifyCertificateChainPolicy_t)(LPCSTR, PCCERT_CHAIN_CONTEXT,
                                                           PCERT_CHAIN_POLICY_PARA,
                                                           PCERT_CHAIN_POLICY_STATUS);
static CertVerifyCertificateChainPolicy_t real_CertVerifyChainPolicy = nullptr;

static BOOL WINAPI hook_CertVerifyCertificateChainPolicy(LPCSTR oid, PCCERT_CHAIN_CONTEXT chain,
                                                          PCERT_CHAIN_POLICY_PARA para,
                                                          PCERT_CHAIN_POLICY_STATUS status) {
    BOOL ok = real_CertVerifyChainPolicy(oid, chain, para, status);
    if (t_proxy_thread || !config().ssl_bypass || !status || !status->dwError) return ok;
    static std::once_flag once;
    std::call_once(once, [] { logf("ssl: accepting the local proxy's certificate (schannel)"); });
    status->dwError = 0;
    status->lChainIndex = status->lElementIndex = -1;
    return TRUE;
}

// ---- OpenSSL / libcurl path ----------------------------------------------------
static const wchar_t* kSslModules[] = {
    L"libssl-1_1.dll", L"libssl-3.dll", L"libssl-3-x64.dll", L"ssleay32.dll",
    L"libcrypto-1_1.dll", L"libcrypto-3.dll", L"libcrypto-3-x64.dll", L"libeay32.dll",
};

static void patch_func_any(const char* fn, uint32_t ret_val) {
    static std::vector<void*> done;
    for (auto mod : kSslModules) {
        HMODULE h = GetModuleHandleW(mod);
        if (!h) continue;
        void* p = (void*)GetProcAddress(h, fn);
        if (!p) continue;
        bool seen = false;
        for (auto d : done) if (d == p) seen = true;
        if (seen) continue;
        if (force_return(p, ret_val)) { done.push_back(p); logf("ssl: %ls!%s -> %u", mod, fn, ret_val); }
    }
}
static void patch_openssl_all() {
    patch_func_any("X509_verify_cert", 1);
    patch_func_any("SSL_get_verify_result", 0);
    patch_func_any("SSL_CTX_set_verify", 0);
    patch_func_any("SSL_set_verify", 0);
    patch_func_any("SSL_CTX_set_cert_verify_callback", 0);
}

#define CURLOPT_SSL_VERIFYPEER    64
#define CURLOPT_SSL_VERIFYHOST    81
#define CURLOPT_SSL_VERIFYSTATUS  232
#define CURLOPT_PINNEDPUBLICKEY   10230
#define CURLOPT_SSL_CTX_FUNCTION  20108
typedef int (__cdecl* curl_setopt_t)(void*, int, void*);
static curl_setopt_t real_curl_setopt = nullptr;

static int __cdecl hook_curl_easy_setopt(void* h, int opt, void* arg) {
    switch (opt) {
        case CURLOPT_SSL_VERIFYPEER: case CURLOPT_SSL_VERIFYHOST: case CURLOPT_SSL_VERIFYSTATUS:
            arg = nullptr; break;
        case CURLOPT_PINNEDPUBLICKEY: case CURLOPT_SSL_CTX_FUNCTION:
            arg = nullptr; break;
        default: break;
    }
    return real_curl_setopt(h, opt, arg);
}

static DWORD WINAPI late_watcher(LPVOID) {
    for (int i = 0; i < 20; ++i) {   // ~10s @ 500ms: catches libraries loaded after init
        Sleep(500);
        patch_openssl_all();
        if (!real_curl_setopt)
            iat_hook_all_modules("libcurl.dll", "curl_easy_setopt", (void*)hook_curl_easy_setopt,
                                 (void**)&real_curl_setopt);
    }
    return 0;
}

void install_ssl_bypass() {
    if (!config().ssl_bypass) { logf("ssl: bypass disabled in ini"); return; }

    HMODULE c32 = GetModuleHandleW(L"crypt32.dll");
    if (c32) {
        real_CertVerifyChainPolicy =
            (CertVerifyCertificateChainPolicy_t)GetProcAddress(c32, "CertVerifyCertificateChainPolicy");
        int n = iat_hook_all_modules("crypt32.dll", "CertVerifyCertificateChainPolicy",
                                     (void*)hook_CertVerifyCertificateChainPolicy,
                                     (void**)&real_CertVerifyChainPolicy);
        logf("ssl: schannel chain-policy hook installed in %d module(s)", n);
    }

    patch_openssl_all();
    int n = iat_hook_all_modules("libcurl.dll", "curl_easy_setopt", (void*)hook_curl_easy_setopt,
                                 (void**)&real_curl_setopt);
    if (n) logf("ssl: hooked curl_easy_setopt in %d module(s)", n);

    static bool watcher_started = false;
    if (!watcher_started) { watcher_started = true; CloseHandle(CreateThread(nullptr, 0, late_watcher, nullptr, 0, nullptr)); }
    logf("ssl bypass installed (schannel + openssl/libcurl, local-proxy-only)");
}

}  // namespace loader
