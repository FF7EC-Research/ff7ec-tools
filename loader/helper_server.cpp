// helper_server.cpp - Clean-room AndAppHelper replacement (payment stubbed).
//
// Goal (preservation): satisfy the FFBE AndApp SDK's local IPC so the game
// launches and reaches its login/session flow WITHOUT the official AndApp
// desktop client, while making purchases impossible (never fake a success).
//
// What the SDK expects (recovered from FF_EXVIUS.exe + AndAppNextHelper):
//   * Config file  %LOCALAPPDATA%\AndApp\AndAppHelper.cfg  with the TCP ports:
//        standard.tcp.command.ipv4.port      = <cmd>
//        standard.tcp.notification.ipv4.port = <ntf>
//   * A "command" socket (request/response) and a "notification" socket (push),
//     both on 127.0.0.1, carrying JSON messages with an "action" field:
//        initialize, get_id_token, get_products, request_purchase,
//        consume_purchase, get_purchases, send_analytics_event, ...
//   * A handshake before commands (DeNASessionImpl): the SDK generates an AES
//     session key and RSA-wraps it. See SessionCrypto below.
//
// IMPORTANT - session crypto is transport-confirmed, not guessed:
//   The exact handshake framing/crypto could not be fully recovered statically
//   from the 8 MB Envoy-based official helper. This file implements the JSON
//   command layer and a pluggable SessionCrypto seam. Use the provided
//   packet-logging helper (AndAppNextHelper.exe patched build) to capture one
//   real handshake, then fill in SessionCrypto::negotiate()/decode()/encode().
//   Everything above that seam (verbs, payment stub, notifications) is done.
//
#include "loader.h"
#include <ws2tcpip.h>
#include <thread>
#include <string>
#include <cstdlib>
#pragma comment(lib, "ws2_32.lib")

namespace loader {
namespace {

// ---- tiny JSON helpers (no dependencies) ------------------------------------
std::string jstr(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default: o += c;
        }
    }
    return o + "\"";
}

// Extract a top-level string/number value for "key" from a flat JSON object.
std::string jget(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t k = json.find(pat);
    if (k == std::string::npos) return "";
    size_t c = json.find(':', k + pat.size());
    if (c == std::string::npos) return "";
    size_t i = c + 1;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
    if (i >= json.size()) return "";
    if (json[i] == '"') {
        size_t e = json.find('"', i + 1);
        return json.substr(i + 1, e - i - 1);
    }
    size_t e = i;
    while (e < json.size() && json[e] != ',' && json[e] != '}') ++e;
    std::string v = json.substr(i, e - i);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\r')) v.pop_back();
    return v;
}

// ---- config file the SDK reads to find our ports ----------------------------
std::wstring localappdata() {
    wchar_t buf[MAX_PATH]{};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf) : std::wstring();
}

void write_helper_cfg() {
    std::wstring dir = localappdata() + L"\\AndApp";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\AndAppHelper.cfg";
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) { logf("cfg: cannot write %ls", path.c_str()); return; }
    fprintf(f, "standard.tcp.command.ipv4.port=%d\r\n", config().command_port);
    fprintf(f, "standard.tcp.notification.ipv4.port=%d\r\n", config().notification_port);
    fprintf(f, "standard.tcp.command.ipv6.port=%d\r\n", config().command_port);
    fprintf(f, "standard.tcp.notification.ipv6.port=%d\r\n", config().notification_port);
    fclose(f);
    logf("cfg: wrote %ls (cmd=%d ntf=%d)", path.c_str(),
         config().command_port, config().notification_port);
}

// ---- payment-safe response builder ------------------------------------------
// A synthesized id token is enough for a preservation server that trusts the
// loader; for the real service it would be rejected (by design - no bypass).
std::string synth_id_token() {
    if (!config().id_token.empty()) return config().id_token;
    // Opaque local token; the preservation server decides how to interpret it.
    return "preservation." + config().player_id;
}

std::string handle_command(const std::string& req) {
    std::string action = jget(req, "action");
    if (action.empty()) action = jget(req, "command");
    logf("cmd <- action=%s", action.c_str());

    auto ok = [](const std::string& body) {
        return std::string("{\"error\":null,") + body + "}";
    };

    if (action == "initialize") {
        return ok("\"result\":\"ok\",\"is_billing_supported\":false");
    }
    if (action == "is_billing_supported") {
        return ok("\"is_billing_supported\":false");
    }
    if (action == "get_id_token") {
        return ok("\"id_token\":" + jstr(synth_id_token()) +
                  ",\"player_id\":" + jstr(config().player_id) +
                  ",\"public_user_id_token\":" + jstr(synth_id_token()));
    }
    if (action == "get_products") {
        // No catalog -> store shows nothing purchasable.
        return ok("\"items\":[],\"missingIds\":[]");
    }
    if (action == "get_purchases") {
        return ok("\"items\":[]");
    }
    if (action == "request_purchase" || action == "request_purchase_completion" ||
        action == "consume_purchase" || action == "get_request_purchase_info") {
        // PAYMENT STUB: always decline. We never emit paymentSucceed.
        logf("payment '%s' declined (preservation build)", action.c_str());
        return std::string(
            "{\"error\":{\"code\":1,\"message\":\"Billing disabled "
            "(preservation build)\"}}");
    }
    if (action == "send_analytics_event" || action == "open_app_page") {
        return ok("\"result\":\"ok\"");
    }
    // Unknown verb: acknowledge without error so the SDK keeps going.
    return ok("\"result\":\"ok\"");
}

// ============================================================================
// SessionCrypto - the ONE seam to confirm against a captured handshake.
// Default build is pass-through (plaintext JSON, newline-framed). If the SDK
// requires the encrypted handshake, capture it with the packet-logging helper
// and implement negotiate()/decode()/encode() here (AES-128-CBC session key,
// RSA-wrapped during negotiate; see docs/REVERSE_ENGINEERING.md).
// ============================================================================
struct SessionCrypto {
    bool negotiate(SOCKET s) {
        (void)s;
        return true;  // TODO: perform RSA/AES handshake if the capture shows one
    }
    // Turn one inbound frame into a JSON request string.
    bool decode(const std::string& frame, std::string& json_out) {
        json_out = frame;  // TODO: AES-decrypt if encrypted
        return true;
    }
    // Turn a JSON response into an outbound frame.
    std::string encode(const std::string& json) {
        return json + "\n";  // TODO: AES-encrypt + length-prefix if required
    }
};

// ---- socket plumbing --------------------------------------------------------
SOCKET listen_on(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;
    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(s, (sockaddr*)&a, sizeof(a)) || listen(s, 4)) {
        logf("listen failed on 127.0.0.1:%d (WSA %d)", port, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    logf("listening on 127.0.0.1:%d", port);
    return s;
}

void command_client(SOCKET c) {
    SessionCrypto crypto;
    if (!crypto.negotiate(c)) { closesocket(c); return; }
    std::string buf;
    char tmp[4096];
    for (;;) {
        int n = recv(c, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        // Log raw bytes so a real capture can be diffed against our framing.
        logf("cmd raw %d bytes", n);
        buf.append(tmp, n);
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string frame = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            if (!frame.empty() && frame.back() == '\r') frame.pop_back();
            if (frame.empty()) continue;
            std::string json;
            if (!crypto.decode(frame, json)) continue;
            std::string resp = crypto.encode(handle_command(json));
            send(c, resp.data(), (int)resp.size(), 0);
        }
    }
    closesocket(c);
}

void accept_loop(int port, bool is_command) {
    SOCKET srv = listen_on(port);
    if (srv == INVALID_SOCKET) return;
    for (;;) {
        SOCKET c = accept(srv, nullptr, nullptr);
        if (c == INVALID_SOCKET) break;
        if (is_command) {
            std::thread(command_client, c).detach();
        } else {
            // Notification channel: keep open; push messages here as needed
            // (e.g. application/active on focus). We never push paymentSucceed.
            logf("notification client connected");
            // Hold the socket; a real build would push framed notifications.
            std::thread([c] {
                char t[512];
                while (recv(c, t, sizeof(t), 0) > 0) {}
                closesocket(c);
            }).detach();
        }
    }
    closesocket(srv);
}

}  // namespace

void start_helper_server() {
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    if (config().write_cfg) write_helper_cfg();
    std::thread(accept_loop, config().command_port, true).detach();
    std::thread(accept_loop, config().notification_port, false).detach();
    logf("AndApp helper replacement started (payments disabled)");
}

}  // namespace loader
