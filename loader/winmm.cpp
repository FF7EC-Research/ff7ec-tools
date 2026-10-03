// winmm.cpp - DLL entry point + transparent winmm.dll proxy.
//
// Drop this winmm.dll next to the FF7 Ever Crisis executable. The game imports
// winmm by name and Windows searches the application directory first, so our DLL
// loads instead of the system one. We load the real winmm from System32 and tail-
// jump every export to it (audio/timers keep working), and use DllMain as the
// injection point for the DNS redirect, TLS MITM proxy and traffic logger.
//
// Build for the same bitness as the game (Unity builds are normally x64).

#include "loader.h"

using namespace loader;

extern "C" {
static void stub_ret() {}
#define WINMM_FN(name) void* g_real_##name = (void*)&stub_ret;
#include "winmm_exports.inc"
#undef WINMM_FN
}

static void load_real_winmm() {
    wchar_t sys[MAX_PATH];
    // 64-bit: System32 is the 64-bit winmm. 32-bit on WOW64: SysWOW64. Both correct.
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring path = std::wstring(sys) + L"\\winmm.dll";
    HMODULE h = LoadLibraryW(path.c_str());
    if (!h) { logf("FATAL: cannot load real winmm from %ls", path.c_str()); return; }
#define WINMM_FN(name) if (void* p = (void*)GetProcAddress(h, #name)) g_real_##name = p;
#include "winmm_exports.inc"
#undef WINMM_FN
    logf("real winmm loaded from %ls", path.c_str());
}

// ---- tail-jump stubs (one shape fits every calling convention) --------------------
#if defined(_WIN64)
#define WINMM_JMP(name) "jmp *g_real_" #name "(%rip)\n\t"
#else
#define WINMM_JMP(name) "jmp *_g_real_" #name "\n\t"
#endif
#define WINMM_FN(name)                                                    \
    extern "C" __attribute__((naked)) void name() {                       \
        __asm__ __volatile__(WINMM_JMP(name));                            \
    }
#include "winmm_exports.inc"
#undef WINMM_FN

// ---- heavier initialization on a worker thread (off the loader lock) ---------------
static DWORD WINAPI init_thread(LPVOID) {
    Config& c = config();
    if (c.mitm_enabled) {
        // Order matters: have the listener(s) up BEFORE any lookup is redirected
        // to 127.0.0.1, or the game's first connection would be refused.
        std::wstring dir = dll_directory();
        if (!identity_init(dir)) logf("certs: local proxy certificate unavailable - TLS interception disabled");
        else {
            if (c.install_ca) install_ca_to_user_root();
            if (!start_mitm()) logf("mitm: no listener could be started");
        }
    }
    install_ssl_bypass();
    install_dns_hooks();
    logf("initialization complete");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        std::wstring ini = dll_directory() + L"\\ff7ec_loader.ini";
        load_config(ini);
        log_init(resolve_path(config().log_path, L"ff7ec_loader.log"), config().log_enabled);
        load_real_winmm();
        logf("=== FF7EC traffic loader (winmm proxy), %d-bit ===", (int)(sizeof(void*) * 8));
        logf("ini: %ls", ini.c_str());
        CloseHandle(CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr));
    }
    return TRUE;
}
