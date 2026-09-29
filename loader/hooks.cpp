// hooks.cpp - IAT hooking, prologue patching, and the DNS / mutex / SSL hooks.
#include "loader.h"
#include <ws2tcpip.h>
#include <algorithm>
#pragma comment(lib, "ws2_32.lib")

namespace loader {

// ---- generic IAT hook --------------------------------------------------------
// Walk the main module's import table and swap the thunk for (import_dll, func).
bool iat_hook(const char* import_dll, const char* func, void* replacement,
              void** original) {
    HMODULE base = GetModuleHandleW(nullptr);
    auto dos = (PIMAGE_DOS_HEADER)base;
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

// ================= SSL / certificate bypass ==================================
// FF_EXVIUS uses libcurl -> OpenSSL. We neutralize verification in memory so the
// client accepts your preservation server's self-signed cert. This only affects
// the local client process. Two well-known no-ops cover the OpenSSL path; we
// also relax libcurl's easy handles as a belt-and-suspenders.
static void patch_openssl(const wchar_t* mod) {
    HMODULE h = GetModuleHandleW(mod);
    if (!h) return;
    struct { const char* fn; uint32_t ret; } t[] = {
        {"X509_verify_cert", 1},        // 1 == success
        {"SSL_get_verify_result", 0},   // 0 == X509_V_OK
    };
    for (auto& e : t) {
        void* p = (void*)GetProcAddress(h, e.fn);
        if (p && force_return(p, e.ret))
            logf("ssl: patched %ls!%s -> %u", mod, e.fn, e.ret);
    }
}

// libcurl: intercept curl_easy_setopt and force the two verify options off,
// regardless of what the app requests.
typedef int (WINAPI* curl_setopt_t)(void*, int, ...);
static curl_setopt_t real_curl_setopt = nullptr;
#define CURLOPT_SSL_VERIFYPEER 64
#define CURLOPT_SSL_VERIFYHOST 81
static int __cdecl hook_curl_easy_setopt(void* h, int opt, ...) {
    va_list ap; va_start(ap, opt);
    // We must consume exactly one argument matching the option's type. For the
    // two verify options the argument is a long; force it to 0.
    if (opt == CURLOPT_SSL_VERIFYPEER || opt == CURLOPT_SSL_VERIFYHOST) {
        va_end(ap);
        return ((int(__cdecl*)(void*, int, long))real_curl_setopt)(h, opt, 0L);
    }
    // Pass through as a pointer-sized argument (works for the common cases).
    void* arg = va_arg(ap, void*);
    va_end(ap);
    return ((int(__cdecl*)(void*, int, void*))real_curl_setopt)(h, opt, arg);
}

void install_ssl_bypass() {
    // Try both OpenSSL 1.1 and 3.x / legacy module names.
    const wchar_t* mods[] = {L"libssl-1_1.dll", L"libssl-3.dll",
                             L"ssleay32.dll", L"libcrypto-1_1.dll"};
    for (auto m : mods) patch_openssl(m);

    if (iat_hook("libcurl.dll", "curl_easy_setopt",
                 (void*)hook_curl_easy_setopt, (void**)&real_curl_setopt))
        logf("ssl: hooked libcurl.dll!curl_easy_setopt");
    logf("ssl bypass installed");
}

}  // namespace loader
