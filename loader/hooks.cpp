// hooks.cpp - IAT hooking and the DNS-redirect hook.
//
// Scope: this file only ever redirects *this game process's own* outgoing
// lookups to the local preservation proxy (127.0.0.1), and only for hosts the
// user has configured in ff7ec_loader.ini. It never touches the OS resolver,
// other processes, or the network beyond this machine.
#include "loader.h"
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <algorithm>
#include <mutex>
#pragma comment(lib, "ws2_32.lib")

namespace loader {

thread_local bool t_proxy_thread = false;

// ---- generic IAT hook, applied across every loaded module ---------------------
static bool iat_hook_module(HMODULE base, const char* import_dll, const char* func,
                            void* replacement, void** original) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;
    auto imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + dir.VirtualAddress);
    bool hooked = false;
    for (; imp->Name; ++imp) {
        const char* dll = (const char*)base + imp->Name;
        if (_stricmp(dll, import_dll) != 0) continue;
        auto thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + imp->FirstThunk);
        auto orig  = (PIMAGE_THUNK_DATA)((BYTE*)base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        for (; orig->u1.AddressOfData; ++orig, ++thunk) {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            auto ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + orig->u1.AddressOfData);
            if (strcmp((const char*)ibn->Name, func) != 0) continue;
            DWORD old;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) continue;
            if (original && !*original) *original = (void*)thunk->u1.Function;
            thunk->u1.Function = (ULONG_PTR)replacement;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), old, &old);
            hooked = true;
        }
    }
    return hooked;
}

static HMODULE self_module() {
    static HMODULE h = [] {
        HMODULE m = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&self_module, &m);
        return m;
    }();
    return h;
}

int iat_hook_all_modules(const char* import_dll, const char* func, void* replacement, void** original) {
    int count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) do {
        if (me.hModule == self_module()) continue;   // never hook our own imports
        if (iat_hook_module(me.hModule, import_dll, func, replacement, original)) ++count;
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return count;
}

bool force_return(void* func, uint32_t ret_val) {
    if (!func) return false;
    BYTE stub[] = {0xB8, 0, 0, 0, 0, 0xC3};   // mov eax, imm32 ; ret
    memcpy(stub + 1, &ret_val, 4);
    DWORD old;
    if (!VirtualProtect(func, sizeof(stub), PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(func, stub, sizeof(stub));
    VirtualProtect(func, sizeof(stub), old, &old);
    FlushInstructionCache(GetCurrentProcess(), func, sizeof(stub));
    return true;
}

// ================= DNS redirect: send the game's own lookups to our proxy =======
// The game's HTTPS client calls getaddrinfo()/GetAddrInfoW() to resolve the API
// host before connecting. We answer with redirect_ip (127.0.0.1 by default) for
// hostnames matched against the [dns] allow/deny lists in the ini, so the TCP
// connection lands on our local MITM listener instead of the real server. Our own
// proxy threads (t_proxy_thread) always resolve for real, since they are the ones
// making the genuine upstream connection.
typedef int  (WSAAPI* getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef INT  (WSAAPI* GetAddrInfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
static getaddrinfo_t  real_getaddrinfo  = nullptr;
static GetAddrInfoW_t real_GetAddrInfoW = nullptr;

static bool is_ip_literal(const std::string& h) {
    in_addr a4; in6_addr a6;
    return InetPtonA(AF_INET, h.c_str(), &a4) == 1 || InetPtonA(AF_INET6, h.c_str(), &a6) == 1;
}

static bool should_redirect(const char* host) {
    Config& c = config();
    if (!c.dns_redirect_all || t_proxy_thread || !host || !*host) return false;
    std::string h = host;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    if (h == "localhost" || is_ip_literal(h)) return false;
    for (auto& e : c.dns_exclude) if (h == e) return false;
    if (!c.dns_only.empty()) {
        bool ok = false;
        for (auto& s : c.dns_only)
            if (h == s || (h.size() > s.size() && h.compare(h.size() - s.size(), s.size(), s) == 0 && h[h.size() - s.size() - 1] == '.'))
                ok = true;
        if (!ok) return false;
    }
    return true;
}

static std::string narrow(PCWSTR w) {
    char b[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, w, -1, b, sizeof(b) - 1, nullptr, nullptr);
    return b;
}

static int WSAAPI hook_getaddrinfo(PCSTR node, PCSTR svc, const ADDRINFOA* hints, PADDRINFOA* res) {
    if (should_redirect(node)) {
        logf("dns: getaddrinfo %s -> %s", node, config().redirect_ip.c_str());
        ADDRINFOA h{}; if (hints) h = *hints;
        h.ai_flags |= AI_NUMERICHOST;
        return real_getaddrinfo(config().redirect_ip.c_str(), svc, &h, res);
    }
    return real_getaddrinfo(node, svc, hints, res);
}

static INT WSAAPI hook_GetAddrInfoW(PCWSTR node, PCWSTR svc, const ADDRINFOW* hints, PADDRINFOW* res) {
    std::string n = node ? narrow(node) : std::string();
    if (node && should_redirect(n.c_str())) {
        logf("dns: GetAddrInfoW %s -> %s", n.c_str(), config().redirect_ip.c_str());
        std::wstring ip(config().redirect_ip.begin(), config().redirect_ip.end());
        ADDRINFOW h{}; if (hints) h = *hints;
        h.ai_flags |= AI_NUMERICHOST;
        return real_GetAddrInfoW(ip.c_str(), svc, &h, res);
    }
    return real_GetAddrInfoW(node, svc, hints, res);
}

void install_dns_hooks() {
    if (!config().dns_redirect_all) { logf("dns: redirect disabled in ini"); return; }
    int a = iat_hook_all_modules("ws2_32.dll", "getaddrinfo",  (void*)hook_getaddrinfo,  (void**)&real_getaddrinfo);
    int w = iat_hook_all_modules("ws2_32.dll", "GetAddrInfoW", (void*)hook_GetAddrInfoW, (void**)&real_GetAddrInfoW);
    logf("dns hooks installed: getaddrinfo=%d GetAddrInfoW=%d module(s), redirecting to %s",
         a, w, config().redirect_ip.c_str());
}

}  // namespace loader
