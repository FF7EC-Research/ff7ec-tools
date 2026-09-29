// helper_server.cpp - Clean-room AndAppHelper replacement (payment stubbed).
//
// Goal (preservation): satisfy the FFBE AndApp SDK's local IPC so the game
// launches and reaches its login/session flow WITHOUT the official AndApp
// desktop client, while making purchases impossible (never fake a success).
//
// What the SDK expects (recovered from FF_EXVIUS.exe + AndAppNextHelper):
//   * Config file  %APPDATA%\AndApp\AndAppHelper.cfg  - a single-line JSON object:
//        {"standard.tcp.command.ipv4.port":<cmd>,"standard.tcp.command.ipv6.port":0,
//         "standard.tcp.notification.ipv4.port":<ntf>,"standard.tcp.notification.ipv6.port":0}
//     (the genuine helper also lists a "standard.command.pipe.name" named pipe;
//      we omit it so the SDK uses the TCP channel.)
//   * A "command" socket (request/response) and a "notification" socket (push),
//     both on 127.0.0.1, carrying JSON messages with an "action" field:
//        initialize, get_id_token, get_products, request_purchase,
//        consume_purchase, get_purchases, send_analytics_event, ...
//     A real launch's SDK sequence (from AndAppHelperDebug.txt) is:
//        initialize -> send_analytics_event -> get_id_token
//   * A handshake before commands (DeNASessionImpl): the SDK generates an AES
//     session key and RSA-wraps it. See SessionCrypto below.
//
// Session crypto is IMPLEMENTED from a live capture (see SessionCrypto below and
// docs/REVERSE_ENGINEERING.md §5): 8-byte framed messages, a CryptoAPI RSA/AES
// handshake where the client sends its RSA public key and we return a minted
// AES-256 key, then AES-256-CBC JSON commands. No secret from the real helper is
// needed. The response JSON schema is a best effort; because we hold the key the
// helper now logs each DECRYPTED request, so the exact schema can be refined by
// reading andapp_loader.log after a run.
//
#include "loader.h"
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <thread>
#include <string>
#include <vector>
#include <cstdlib>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

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
std::wstring appdata() {
    // Resolve exactly the way the game does: SHGetFolderPathW(CSIDL_APPDATA)
    // (roaming). This matches the game's own path resolution even under folder
    // redirection, unlike the %APPDATA% env var. Falls back to the env var.
    wchar_t buf[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr,
                                   SHGFP_TYPE_CURRENT, buf)) && buf[0])
        return std::wstring(buf);
    DWORD n = GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::wstring(buf) : std::wstring();
}

void write_helper_cfg() {
    std::wstring dir = appdata() + L"\\AndApp";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\AndAppHelper.cfg";
    FILE* f = _wfopen(path.c_str(), L"wb");
    if (!f) { logf("cfg: cannot write %ls", path.c_str()); return; }
    // Real format is a single-line JSON object. The genuine helper also lists a
    // "standard.command.pipe.name" (\\.\pipe\AndAppNextHelper-<hash>); we omit it
    // so the SDK falls back to the TCP command channel we implement. ipv6 = 0
    // means "not listening", matching the real cfg.
    fprintf(f,
        "{\"standard.tcp.command.ipv4.port\":%d,"
        "\"standard.tcp.command.ipv6.port\":0,"
        "\"standard.tcp.notification.ipv4.port\":%d,"
        "\"standard.tcp.notification.ipv6.port\":0}",
        config().command_port, config().notification_port);
    fclose(f);
    logf("cfg: wrote %ls (JSON, cmd=%d ntf=%d, TCP only)", path.c_str(),
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

// The request is {"<command>":{...params...}} - the command is the sole
// top-level key. Return it.
std::string top_command(const std::string& req) {
    size_t b = req.find('{');
    if (b == std::string::npos) return "";
    size_t q1 = req.find('"', b);
    if (q1 == std::string::npos) return "";
    size_t q2 = req.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return req.substr(q1 + 1, q2 - q1 - 1);
}

std::string handle_command(const std::string& req) {
    std::string action = top_command(req);
    logf("cmd <- action=%s  json=%s", action.c_str(), req.c_str());

    // The SDK reads result fields at the TOP LEVEL of the response object, and
    // only if a required field is missing does it look for a top-level "error"
    // key (any "error" key = failure). So a success reply is FLAT with the
    // expected fields and NO "error" key. (Confirmed by disassembly of the
    // initialize response parser at RVA 0x0105c3a0.)
    auto reply = [&](const std::string& fields) {
        std::string r = "{" + fields + "}";
        logf("cmd -> %s", r.c_str());
        return r;
    };
    auto fail = [&](int code, const std::string& msg) {
        std::string r = "{\"error\":{\"code\":" + std::to_string(code) +
                        ",\"message\":" + jstr(msg) + "}}";
        logf("cmd -> %s", r.c_str());
        return r;
    };

    if (action == "initialize") {
        // Required top-level keys: session, is_billing_supported,
        // andapp_client_version (player_id included for good measure).
        return reply(
            "\"session\":" + jstr("preservation-session") +
            ",\"player_id\":" + jstr(config().player_id) +
            ",\"is_billing_supported\":false" +
            ",\"andapp_client_version\":\"3.8.0\"");
    }
    if (action == "is_billing_supported") {
        return reply("\"is_billing_supported\":false");
    }
    if (action == "get_id_token") {
        return reply(
            "\"id_token\":" + jstr(synth_id_token()) +
            ",\"player_id\":" + jstr(config().player_id) +
            ",\"public_user_id_token\":" + jstr(synth_id_token()));
    }
    if (action == "get_products") {
        return reply("\"items\":[],\"missingIds\":[]");
    }
    if (action == "get_purchases") {
        return reply("\"items\":[]");
    }
    if (action == "request_purchase" || action == "request_purchase_completion" ||
        action == "consume_purchase" || action == "get_request_purchase_info") {
        // PAYMENT STUB: always decline. We never emit paymentSucceed.
        logf("payment '%s' declined (preservation build)", action.c_str());
        return fail(1, "Billing disabled (preservation build)");
    }
    if (action == "send_analytics_event" || action == "open_app_page") {
        return reply("");  // empty object, no error = success
    }
    // Unknown verb: acknowledge without error so the SDK keeps going.
    return reply("");
}

// ============================================================================
// Wire protocol (recovered from a live capture; see docs/REVERSE_ENGINEERING.md):
//   Frame = [4-byte BE opcode][4-byte BE length][payload]
//   Handshake (on BOTH the command and notification sockets):
//     op 1  C->S  client RSA-1024 public key   (CryptoAPI PUBLICKEYBLOB)
//     op 2  S->C  AES-256 session key           (SIMPLEBLOB, RSA-encrypted to it)
//     op 3  C->S  plaintext JSON {"clientid":"..."}
//     op 4  S->C  single 0x00 byte (ack)
//   Application data:
//     op 0x10  both ways  AES-256-CBC (IV=0, PKCS7) ciphertext of JSON
// The client does not authenticate the server, so we mint our own AES key and
// send it encrypted to the client's public key - no secret from the real helper
// is required. Holding the key also lets us log the decrypted request JSON.
// ============================================================================
constexpr uint32_t OP_CLIENT_PUBKEY = 1;
constexpr uint32_t OP_SERVER_AESKEY = 2;
constexpr uint32_t OP_CLIENT_HELLO  = 3;
constexpr uint32_t OP_SERVER_ACK    = 4;
constexpr uint32_t OP_DATA          = 0x10;

bool recv_all(SOCKET s, char* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool read_frame(SOCKET s, uint32_t& op, std::string& payload) {
    unsigned char h[8];
    if (!recv_all(s, (char*)h, 8)) return false;
    op = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
    uint32_t len = (h[4] << 24) | (h[5] << 16) | (h[6] << 8) | h[7];
    if (len > 64 * 1024 * 1024) return false;
    payload.resize(len);
    return len == 0 || recv_all(s, &payload[0], (int)len);
}

bool send_frame(SOCKET s, uint32_t op, const std::string& payload) {
    unsigned char h[8];
    uint32_t len = (uint32_t)payload.size();
    h[0] = op >> 24; h[1] = op >> 16; h[2] = op >> 8; h[3] = op;
    h[4] = len >> 24; h[5] = len >> 16; h[6] = len >> 8; h[7] = len;
    if (send(s, (char*)h, 8, 0) != 8) return false;
    return len == 0 || send(s, payload.data(), (int)len, 0) == (int)len;
}

struct SessionCrypto {
    HCRYPTPROV prov = 0;
    HCRYPTKEY  aes = 0;
    bool ok = false;

    ~SessionCrypto() {
        if (aes) CryptDestroyKey(aes);
        if (prov) CryptReleaseContext(prov, 0);
    }

    void zero_iv() {
        BYTE iv[16] = {0};
        CryptSetKeyParam(aes, KP_IV, iv, 0);
    }

    bool negotiate(SOCKET s) {
        if (!CryptAcquireContextW(
                &prov, nullptr,
                L"Microsoft Enhanced RSA and AES Cryptographic Provider",
                PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            logf("crypto: CryptAcquireContext failed %lu", GetLastError());
            return false;
        }
        uint32_t op; std::string p;
        if (!read_frame(s, op, p) || op != OP_CLIENT_PUBKEY) return false;
        HCRYPTKEY client = 0;
        if (!CryptImportKey(prov, (const BYTE*)p.data(), (DWORD)p.size(), 0, 0,
                            &client)) {
            logf("crypto: import client pubkey failed %lu", GetLastError());
            return false;
        }
        if (!CryptGenKey(prov, CALG_AES_256, CRYPT_EXPORTABLE, &aes)) {
            logf("crypto: gen AES key failed %lu", GetLastError());
            CryptDestroyKey(client); return false;
        }
        DWORD mode = CRYPT_MODE_CBC;
        CryptSetKeyParam(aes, KP_MODE, (BYTE*)&mode, 0);
        zero_iv();
        DWORD blen = 0;
        CryptExportKey(aes, client, SIMPLEBLOB, 0, nullptr, &blen);
        std::string blob(blen, '\0');
        BOOL e = CryptExportKey(aes, client, SIMPLEBLOB, 0, (BYTE*)&blob[0], &blen);
        CryptDestroyKey(client);
        if (!e) { logf("crypto: export AES key failed %lu", GetLastError()); return false; }
        blob.resize(blen);
        if (!send_frame(s, OP_SERVER_AESKEY, blob)) return false;
        if (!read_frame(s, op, p) || op != OP_CLIENT_HELLO) return false;
        logf("crypto: client hello %s", p.c_str());
        if (!send_frame(s, OP_SERVER_ACK, std::string(1, '\0'))) return false;
        ok = true;
        logf("crypto: session established");
        return true;
    }

    bool decrypt(const std::string& ct, std::string& out) {
        std::vector<BYTE> buf(ct.begin(), ct.end());
        DWORD len = (DWORD)buf.size();
        zero_iv();
        if (!CryptDecrypt(aes, 0, TRUE, 0, buf.data(), &len)) {
            logf("crypto: decrypt failed %lu", GetLastError());
            return false;
        }
        out.assign((char*)buf.data(), len);
        return true;
    }

    std::string encrypt(const std::string& pt) {
        std::vector<BYTE> buf(pt.begin(), pt.end());
        buf.resize(((pt.size() / 16) + 1) * 16, 0);  // room for PKCS7 padding
        DWORD len = (DWORD)pt.size();
        zero_iv();
        if (!CryptEncrypt(aes, 0, TRUE, 0, buf.data(), &len, (DWORD)buf.size())) {
            logf("crypto: encrypt failed %lu", GetLastError());
            return std::string();
        }
        return std::string((char*)buf.data(), len);
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
    for (;;) {
        uint32_t op; std::string payload;
        if (!read_frame(c, op, payload)) break;
        if (op != OP_DATA) { logf("cmd: unexpected opcode %u", op); continue; }
        std::string json;
        if (!crypto.decrypt(payload, json)) break;
        std::string resp = handle_command(json);
        std::string ct = crypto.encrypt(resp);
        if (ct.empty() || !send_frame(c, OP_DATA, ct)) break;
    }
    closesocket(c);
}

void notification_client(SOCKET c) {
    // The notification channel does the same handshake, then the server may push
    // op 0x10 messages. For a basic preservation launch we complete the
    // handshake and stay idle (we never push paymentSucceed). Drain and discard.
    SessionCrypto crypto;
    if (!crypto.negotiate(c)) { closesocket(c); return; }
    logf("notification channel established");
    for (;;) {
        uint32_t op; std::string payload;
        if (!read_frame(c, op, payload)) break;
    }
    closesocket(c);
}

void accept_loop(int port, bool is_command) {
    SOCKET srv = listen_on(port);
    if (srv == INVALID_SOCKET) return;
    for (;;) {
        SOCKET c = accept(srv, nullptr, nullptr);
        if (c == INVALID_SOCKET) break;
        std::thread(is_command ? command_client : notification_client, c).detach();
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
