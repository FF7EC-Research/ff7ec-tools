// cef_hook.cpp - inject Chromium/CEF command-line switches for preservation.
//
// The game embeds CEF (libcef.dll + chrome_elf.dll + *.pak + v8 snapshots), so
// its login / portal / store screens are likely web pages rendered by Chromium.
// CEF has its OWN network stack and TLS (BoringSSL inside libcef.dll), separate
// from libcurl/OpenSSL - so the curl/OpenSSL bypass does not touch it, and CEF
// often runs networking in child processes that don't even load our winmm.dll.
//
// The clean way to relax CEF is Chromium command-line switches. CEF reads the
// process command line via GetCommandLineW. We inline-patch GetCommandLineW to
// return an augmented command line with:
//   --ignore-certificate-errors                accept any TLS cert (incl. pinned)
//   --ignore-urlfetcher-cert-requests
//   --allow-running-insecure-content
//   --disable-web-security                     (optional)
//   --host-resolver-rules="MAP host ip,..."    DNS redirect, built from [dns]
//
// Because GetCommandLineW is patched in EVERY process that loads winmm.dll (the
// browser process and, since CEF reuses FF_EXVIUS.exe as its subprocess, the
// renderer/gpu/utility/network children too), all CEF processes pick the
// switches up. As a belt-and-suspenders we also append them to child command
// lines in CreateProcessW (install_process_hooks), guarded against duplication.

#include "loader.h"
#include <string>
#include <vector>

namespace loader {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// Marker switch used to detect an already-augmented command line (avoid doubling
// when CEF children re-run our DllMain / when CreateProcessW also appends).
const wchar_t* kMarker = L"--ignore-certificate-errors";

std::wstring g_switches;           // cached, built once
LPWSTR       g_fake_cmdline = nullptr;  // persists for process lifetime

typedef LPWSTR (WINAPI* GetCommandLineW_t)();

}  // namespace

// Build the switch string from config; also used by the CreateProcessW hook.
std::string cef_switch_string() {
    std::string s;
    if (config().cef_ignore_cert) {
        s += "--ignore-certificate-errors";
        s += " --ignore-urlfetcher-cert-requests";
        s += " --allow-running-insecure-content";
        s += " --test-type";  // suppresses the "unsupported flag" info bar
    }
    if (config().cef_disable_websec)
        s += " --disable-web-security";
    if (config().cef_host_rules && !config().dns.empty()) {
        std::string rules;
        for (auto& kv : config().dns) {
            if (!rules.empty()) rules += ",";
            rules += "MAP " + kv.first + " " + kv.second;
        }
        // Keep loopback resolving normally.
        rules += ",EXCLUDE localhost";
        // Quote because the value contains spaces/commas.
        s += " --host-resolver-rules=\"" + rules + "\"";
    }
    if (!config().cef_extra_switches.empty())
        s += " " + config().cef_extra_switches;
    return s;
}

void install_cmdline_hook() {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto real = (GetCommandLineW_t)GetProcAddress(k32, "GetCommandLineW");
    if (!real) { logf("cmdline: GetCommandLineW not found"); return; }
    LPWSTR cur = real();
    std::wstring cmd = cur ? cur : L"";

    // Build what we append: payload id (for the SDK) + CEF switches (for libcef).
    // g_switches holds ONLY the CEF switches (reused by the CreateProcessW hook
    // for child processes; children don't need the payload id).
    std::string cef = config().cef_enabled ? cef_switch_string() : "";
    g_switches = widen(cef);

    std::wstring append;
    if (config().inject_payload_id &&
        cmd.find(L"--andapp-payload-id") == std::wstring::npos) {
        append += L" --andapp-payload-id=" + widen(config().andapp_payload_id);
        logf("cmdline: injecting --andapp-payload-id=%s",
             config().andapp_payload_id.c_str());
    }
    if (!cef.empty() && cmd.find(kMarker) == std::wstring::npos)
        append += L" " + g_switches;

    if (append.empty()) { logf("cmdline: nothing to inject"); return; }
    std::wstring full = cmd + append;

    // Persist a copy that lives forever; GetCommandLineW must keep returning it.
    size_t bytes = (full.size() + 1) * sizeof(wchar_t);
    g_fake_cmdline = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, bytes);
    memcpy(g_fake_cmdline, full.c_str(), bytes);

    // GetCommandLineW just returns a pointer; force it to return ours.
    // (32-bit: the pointer fits in the mov-eax immediate.)
    if (force_return((void*)real, (uint32_t)(uintptr_t)g_fake_cmdline))
        logf("cmdline: patched GetCommandLineW");
    else
        logf("cmdline: failed to patch GetCommandLineW");
}

// ---- CreateProcessW: append switches to CEF child processes ------------------
typedef BOOL (WINAPI* CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION);
static CreateProcessW_t real_CreateProcessW = nullptr;

static BOOL WINAPI hook_CreateProcessW(LPCWSTR app, LPWSTR cmd,
    LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD flags,
    LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    std::wstring newcmd;
    if (cmd && wcsstr(cmd, L"--type=") && !wcsstr(cmd, kMarker) &&
        !g_switches.empty()) {
        // A CEF child (renderer/gpu/utility/network). Append our switches.
        newcmd = std::wstring(cmd) + L" " + g_switches;
        logf("cef: augmented child process command line");
        // CreateProcessW may modify the buffer, so pass a writable copy.
        std::vector<wchar_t> buf(newcmd.begin(), newcmd.end());
        buf.push_back(L'\0');
        return real_CreateProcessW(app, buf.data(), pa, ta, inh, flags, env,
                                   cwd, si, pi);
    }
    return real_CreateProcessW(app, cmd, pa, ta, inh, flags, env, cwd, si, pi);
}

void install_process_hooks() {
    if (!config().cef_enabled || g_switches.empty()) return;
    int n = iat_hook_all_modules("kernel32.dll", "CreateProcessW",
                                 (void*)hook_CreateProcessW,
                                 (void**)&real_CreateProcessW);
    logf("cef: CreateProcessW child-propagation hooked in %d module(s)", n);
}

}  // namespace loader
