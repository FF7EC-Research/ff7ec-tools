// hooks.cpp - IAT hooking, prologue patching, and the DNS / mutex / SSL hooks.
#include "loader.h"
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <algorithm>
#include <vector>
#pragma comment(lib, "ws2_32.lib")

namespace loader {

// ---- generic IAT hook (single module) ---------------------------------------
static bool iat_hook_module(HMODULE base, const char* import_dll,
                            const char* func, void* replacement,
                            void** original) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    auto imp_dir = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp_dir.VirtualAddress) return false;
    auto imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + imp_dir.VirtualAddress);

    bool hooked = false;
    for (; imp->Name; ++imp) {
        const char* dll = (const char*)base + imp->Name;
        if (_stricmp(dll, import_dll) != 0) continue;
        auto thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + imp->FirstThunk);
        auto orig = (PIMAGE_THUNK_DATA)((BYTE*)base +
                        (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                 : imp->FirstThunk));
        for (; orig->u1.AddressOfData; ++orig, ++thunk) {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            auto ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + orig->u1.AddressOfData);
            if (strcmp((const char*)ibn->Name, func) != 0) continue;
            DWORD old;
            VirtualProtect(&thunk->u1.Function, sizeof(void*),
                           PAGE_READWRITE, &old);
            if (original && !*original) *original = (void*)thunk->u1.Function;
            thunk->u1.Function = (ULONG_PTR)replacement;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
            hooked = true;
        }
    }
    return hooked;
}

// Hook the main image only (used for ws2_32 / kernel32 imports).
bool iat_hook(const char* import_dll, const char* func, void* replacement,
              void** original) {
    return iat_hook_module(GetModuleHandleW(nullptr), import_dll, func,
                           replacement, original);
}

// Hook the import in EVERY loaded module. Needed for libcurl, which is called
// by libcocos2d.dll (and the SDK), not by the game exe directly.
int iat_hook_all_modules(const char* import_dll, const char* func,
                         void* replacement, void** original) {
    int count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            if (me.hModule == GetModuleHandleW(L"winmm.dll")) continue;  // skip self
            if (iat_hook_module(me.hModule, import_dll, func, replacement,
                                original))
                ++count;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return count;
}

// ---- prologue patch: make a function return a constant -----------------------
bool force_return(void* func, uint32_t ret_val) {
    if (!func) return false;
    BYTE stub[] = {0xB8, 0, 0, 0, 0, 0xC3};      // mov eax, imm32 ; ret
    memcpy(stub + 1, &ret_val, 4);
    DWORD old;
    if (!VirtualProtect(func, sizeof(stub), PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(func, stub, sizeof(stub));
    VirtualProtect(func, sizeof(stub), old, &old);
    FlushInstructionCache(GetCurrentProcess(), func, sizeof(stub));
    return true;
}

// ================= DNS redirect ==============================================
// The game resolves game-server hostnames via ws2_32 getaddrinfo. We intercept
// it, and if the [dns] section maps that host to an IP, we return that instead,
// so preservation traffic goes to your replacement server.
typedef int (WSAAPI* getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef INT (WSAAPI* GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
static getaddrinfo_t  real_getaddrinfo = nullptr;
static GetAddrInfoW_t real_GetAddrInfoW = nullptr;

static const std::string* redirect_for(const std::string& host) {
    auto& m = config().dns;
    std::string h = host;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    auto it = m.find(h);
    return it == m.end() ? nullptr : &it->second;
}

static int WSAAPI hook_getaddrinfo(PCSTR node, PCSTR svc,
                                   const ADDRINFOA* hints, PADDRINFOA* res) {
    if (node) {
        const std::string* ip = redirect_for(node);
        if (ip) {
            logf("getaddrinfo redirect %s -> %s", node, ip->c_str());
            return real_getaddrinfo(ip->c_str(), svc, hints, res);
        }
    }
    return real_getaddrinfo(node, svc, hints, res);
}

static INT WSAAPI hook_GetAddrInfoW(PCWSTR node, PCWSTR svc,
                                    const ADDRINFOW* hints, PADDRINFOW* res) {
    if (node) {
        char nb[512];
        WideCharToMultiByte(CP_UTF8, 0, node, -1, nb, sizeof(nb), nullptr, nullptr);
        const std::string* ip = redirect_for(nb);
        if (ip) {
            std::wstring wip(ip->begin(), ip->end());
            logf("GetAddrInfoW redirect %s -> %s", nb, ip->c_str());
            return real_GetAddrInfoW(wip.c_str(), svc, hints, res);
        }
    }
    return real_GetAddrInfoW(node, svc, hints, res);
}

void install_dns_hooks() {
    if (config().dns.empty()) { logf("dns: no redirects configured"); return; }
    bool a = iat_hook("ws2_32.dll", "getaddrinfo",
                      (void*)hook_getaddrinfo, (void**)&real_getaddrinfo);
    bool w = iat_hook("ws2_32.dll", "GetAddrInfoW",
                      (void*)hook_GetAddrInfoW, (void**)&real_GetAddrInfoW);
    // ws2_32 is sometimes imported as WS2_32.DLL from a forwarder; also try mswsock.
    logf("dns hooks installed: getaddrinfo=%d GetAddrInfoW=%d (%zu redirects)",
         (int)a, (int)w, config().dns.size());
}

// ================= Mutex neutralization ======================================
// The SDK creates a single-instance mutex; with the official AndApp absent it
// can fail ("Failed to create a mutex object"). We wrap CreateMutexW so a name
// clash / access failure is turned into a fresh, owned mutex, letting the game
// launch standalone. We do NOT change unnamed-mutex behavior.
typedef HANDLE (WINAPI* CreateMutexW_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
typedef HANDLE (WINAPI* CreateMutexExW_t)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
static CreateMutexW_t   real_CreateMutexW = nullptr;
static CreateMutexExW_t real_CreateMutexExW = nullptr;

static HANDLE WINAPI hook_CreateMutexW(LPSECURITY_ATTRIBUTES sa, BOOL owner,
                                       LPCWSTR name) {
    HANDLE h = real_CreateMutexW ? real_CreateMutexW(sa, owner, name)
                                 : CreateMutexW(sa, owner, name);
    if (!h) {
        logf("CreateMutexW failed for '%ls' -> creating anonymous mutex",
             name ? name : L"(null)");
        h = CreateMutexW(sa, owner, nullptr);
    }
    // Report success even if it already existed, so the "already running" guard
    // does not abort a standalone launch.
    SetLastError(ERROR_SUCCESS);
    return h;
}

static HANDLE WINAPI hook_CreateMutexExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name,
                                         DWORD flags, DWORD access) {
    HANDLE h = real_CreateMutexExW
                   ? real_CreateMutexExW(sa, name, flags, access)
                   : CreateMutexExW(sa, name, flags, access);
    if (!h) {
        logf("CreateMutexExW failed for '%ls' -> anonymous",
             name ? name : L"(null)");
        h = CreateMutexExW(sa, nullptr, flags, access);
    }
    SetLastError(ERROR_SUCCESS);
    return h;
}

void install_mutex_hooks() {
    bool a = iat_hook("kernel32.dll", "CreateMutexW",
                      (void*)hook_CreateMutexW, (void**)&real_CreateMutexW);
    bool b = iat_hook("kernel32.dll", "CreateMutexExW",
                      (void*)hook_CreateMutexExW, (void**)&real_CreateMutexExW);
    logf("mutex hooks installed: CreateMutexW=%d CreateMutexExW=%d", (int)a, (int)b);
}

// ================= SSL / certificate + pinning bypass ========================
// FF_EXVIUS does HTTPS via libcurl -> OpenSSL. To accept any certificate from a
// recreated preservation server (self-signed, hostname mismatch, and to defeat
// certificate pinning) we neutralize verification on every layer, in memory.
// This only affects this local client process.
//
// Layers covered:
//   OpenSSL (libcrypto/libssl):
//     X509_verify_cert                 -> 1  (chain always "valid")
//     SSL_get_verify_result            -> 0  (X509_V_OK)
//     SSL_CTX_set_verify / SSL_set_verify        -> no-op (can't force VERIFY_PEER
//                                                  or install a per-cert callback)
//     SSL_CTX_set_cert_verify_callback -> no-op (can't install a pinning callback
//                                                  that replaces X509_verify_cert)
//   libcurl (its OWN hostname check + pinning live here, not in OpenSSL):
//     curl_easy_setopt filters:
//       SSL_VERIFYPEER/HOST/STATUS -> 0     (chain, hostname, OCSP off)
//       PINNEDPUBLICKEY            -> NULL  (drop public-key pin)
//       SSL_CTX_FUNCTION           -> NULL  (drop app's custom SSL_CTX hook,
//                                            a common place to add pinning)

// Candidate module names across OpenSSL 1.0/1.1/3.x, 32/64-bit and legacy.
static const wchar_t* kSslModules[] = {
    L"libssl-1_1.dll", L"libssl-3.dll", L"libssl-3-x86.dll", L"ssleay32.dll",
    L"libcrypto-1_1.dll", L"libcrypto-3.dll", L"libcrypto-3-x86.dll",
    L"libeay32.dll",
};

// Force `fn` (found in whichever candidate module exports it) to return ret_val.
static void patch_func_any(const char* fn, uint32_t ret_val) {
    for (auto mod : kSslModules) {
        HMODULE h = GetModuleHandleW(mod);
        if (!h) continue;
        void* p = (void*)GetProcAddress(h, fn);
        if (p && force_return(p, ret_val))
            logf("ssl: patched %ls!%s -> %u", mod, fn, ret_val);
    }
}

static void patch_openssl_all() {
    patch_func_any("X509_verify_cert", 1);
    patch_func_any("SSL_get_verify_result", 0);
    // Neutralize the "set verify" / pinning-callback installers (return value
    // ignored by callers; making them no-ops keeps the default VERIFY_NONE).
    patch_func_any("SSL_CTX_set_verify", 0);
    patch_func_any("SSL_set_verify", 0);
    patch_func_any("SSL_CTX_set_cert_verify_callback", 0);
}

// libcurl option ids (from curl.h): LONG=n, OBJECTPOINT=10000+n, FUNCTION=20000+n
#define CURLOPT_SSL_VERIFYPEER    64
#define CURLOPT_SSL_VERIFYHOST    81
#define CURLOPT_SSL_VERIFYSTATUS  232
#define CURLOPT_PINNEDPUBLICKEY   10230
#define CURLOPT_SSL_CTX_FUNCTION  20108

typedef int (__cdecl* curl_setopt_t)(void*, int, ...);
static curl_setopt_t real_curl_setopt = nullptr;

static int __cdecl hook_curl_easy_setopt(void* h, int opt, ...) {
    va_list ap; va_start(ap, opt);
    // On x86 every parameter here (long / pointer / function ptr) is 4 bytes,
    // so we can read one slot uniformly and rewrite it.
    void* arg = va_arg(ap, void*);
    va_end(ap);
    switch (opt) {
        case CURLOPT_SSL_VERIFYPEER:
        case CURLOPT_SSL_VERIFYHOST:
        case CURLOPT_SSL_VERIFYSTATUS:
            arg = (void*)0;      // turn every verification off
            logf("ssl: curl setopt %d forced to 0", opt);
            break;
        case CURLOPT_PINNEDPUBLICKEY:
        case CURLOPT_SSL_CTX_FUNCTION:
            arg = nullptr;       // strip pinning vectors
            logf("ssl: curl setopt %d dropped (pinning)", opt);
            break;
        default:
            break;
    }
    return ((int(__cdecl*)(void*, int, void*))real_curl_setopt)(h, opt, arg);
}

static DWORD WINAPI ssl_late_watcher(LPVOID) {
    for (int i = 0; i < 20; ++i) {   // ~10s @ 500ms
        Sleep(500);
        patch_openssl_all();
        if (!real_curl_setopt) {
            iat_hook_all_modules("libcurl.dll", "curl_easy_setopt",
                                 (void*)hook_curl_easy_setopt,
                                 (void**)&real_curl_setopt);
        }
    }
    logf("ssl: late-load watcher finished");
    return 0;
}

void install_ssl_bypass() {
    patch_openssl_all();

    static bool curl_hooked = false;
    if (!curl_hooked) {
        int n = iat_hook_all_modules("libcurl.dll", "curl_easy_setopt",
                                     (void*)hook_curl_easy_setopt,
                                     (void**)&real_curl_setopt);
        // Some builds name the import table entry with different casing.
        if (!n)
            n = iat_hook_all_modules("LIBCURL.dll", "curl_easy_setopt",
                                     (void*)hook_curl_easy_setopt,
                                     (void**)&real_curl_setopt);
        if (n) { curl_hooked = true; logf("ssl: hooked curl_easy_setopt in %d module(s)", n); }
        else   logf("ssl: curl_easy_setopt import not found yet");
    }

    // OpenSSL / libcurl may be loaded lazily. Re-apply the (idempotent) prologue
    // patches and retry the curl hook for a short while to catch late loads.
    static bool watcher = false;
    if (!watcher) {
        watcher = true;
        CloseHandle(CreateThread(nullptr, 0, ssl_late_watcher, nullptr, 0, nullptr));
    }
    logf("ssl bypass installed (validation + pinning)");
}

}  // namespace loader
