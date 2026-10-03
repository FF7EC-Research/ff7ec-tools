// proxy.cpp - the local loopback decrypting proxy.
//
// Binds 127.0.0.1 (configurable) on the configured ports. Each connection:
// the game connects here (because install_dns_hooks() redirected its lookup),
// we complete its TLS handshake with our own certificate, learn the real
// target host from the ClientHello's SNI, open a *real*, normally-validated
// TLS connection to that host ourselves, and relay HTTP messages between the
// two - logging a decoded copy of each one via decode.cpp, forwarding the
// bytes unmodified. Nothing is fabricated or altered; this only observes
// traffic this local game client already generates.
#include "loader.h"
#include "tls_schannel.h"
#include "decode.h"
#include <ws2tcpip.h>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace loader {

// ---- buffered reader over a TlsStream --------------------------------------------
class BufReader {
public:
    explicit BufReader(TlsStream& s) : s_(s) {}
    // Up to and including the trailing '\n'; false on EOF/error with no data.
    bool get_line(std::string& out) {
        out.clear();
        for (;;) {
            for (; pos_ < buf_.size(); ++pos_) {
                out.push_back((char)buf_[pos_]);
                if (buf_[pos_] == '\n') { ++pos_; return true; }
            }
            if (!top_up()) return !out.empty();
        }
    }
    bool read_n(std::vector<uint8_t>& out, size_t n) {
        out.clear();
        while (out.size() < n) {
            if (pos_ >= buf_.size() && !top_up()) return false;
            size_t take = std::min(n - out.size(), buf_.size() - pos_);
            out.insert(out.end(), buf_.begin() + pos_, buf_.begin() + pos_ + take);
            pos_ += take;
        }
        return true;
    }
private:
    bool top_up() {
        buf_.erase(buf_.begin(), buf_.begin() + pos_); pos_ = 0;
        uint8_t tmp[16384];
        int n = s_.read(tmp, sizeof tmp);
        if (n <= 0) return false;
        buf_.insert(buf_.end(), tmp, tmp + n);
        return true;
    }
    TlsStream& s_;
    std::vector<uint8_t> buf_;
    size_t pos_ = 0;
};

struct HttpMessage {
    std::string start_line;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
    std::string header(const char* name) const {
        for (auto& h : headers) if (_stricmp(h.first.c_str(), name) == 0) return h.second;
        return "";
    }
};

static std::string rtrim(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}

// Reads one request or response: start line, headers, and a body sized by
// Content-Length or (if chunked) by the chunked-encoding framing. Returns
// false on EOF/parse failure (normal at connection close).
static bool read_http_message(BufReader& r, HttpMessage& m) {
    m = {};
    std::string line;
    if (!r.get_line(line)) return false;
    m.start_line = rtrim(line);
    for (;;) {
        if (!r.get_line(line)) return false;
        line = rtrim(line);
        if (line.empty()) break;
        size_t c = line.find(':');
        if (c == std::string::npos) continue;
        std::string k = line.substr(0, c), v = line.substr(c + 1);
        size_t a = v.find_first_not_of(' '); v = a == std::string::npos ? "" : v.substr(a);
        m.headers.emplace_back(k, v);
    }
    std::string te = m.header("Transfer-Encoding"), cl = m.header("Content-Length");
    if (!te.empty() && te.find("chunked") != std::string::npos) {
        for (;;) {
            if (!r.get_line(line)) return false;
            unsigned long sz = strtoul(line.c_str(), nullptr, 16);
            if (sz == 0) { r.get_line(line); break; }   // trailing CRLF after last chunk
            std::vector<uint8_t> chunk;
            if (!r.read_n(chunk, sz)) return false;
            m.body.insert(m.body.end(), chunk.begin(), chunk.end());
            if (!r.get_line(line)) return false;        // CRLF after chunk data
        }
    } else if (!cl.empty()) {
        size_t n = strtoull(cl.c_str(), nullptr, 10);
        if (n && !r.read_n(m.body, n)) return false;
    }
    return true;
}

static bool write_http_message(TlsStream& s, const HttpMessage& m) {
    std::string out = m.start_line + "\r\n";
    for (auto& h : m.headers) out += h.first + ": " + h.second + "\r\n";
    out += "\r\n";
    if (!s.write((const uint8_t*)out.data(), (int)out.size())) return false;
    if (!m.body.empty() && !s.write(m.body.data(), (int)m.body.size())) return false;
    return true;
}

// ---- traffic log -------------------------------------------------------------------
static std::mutex g_log_mtx;
static void traffic_log(const std::string& host, const char* dir, const HttpMessage& m) {
    Config& c = config();
    std::wstring path = resolve_path(c.traffic_log, L"ff7ec_traffic.log");
    FILE* f = _wfopen(path.c_str(), L"ab");
    if (!f) return;
    std::lock_guard<std::mutex> lk(g_log_mtx);
    fprintf(f, "==== %s %s %s ====\n%s\n", host.c_str(), dir, m.start_line.c_str(), m.start_line.c_str());
    for (auto& h : m.headers) fprintf(f, "%s: %s\n", h.first.c_str(), h.second.c_str());
    fprintf(f, "\n");
    if (!m.body.empty()) {
        auto kind = dir[0] == '>' ? decode::Kind::Request : decode::Kind::Response;
        auto d = decode::decode_body(m.body.data(), m.body.size(), kind);
        if (d.ok) {
            fprintf(f, "[decrypted body, %s, %zu bytes]\n%s\n", d.cipher.c_str(), d.plain.size(), d.text.c_str());
        } else {
            size_t n = std::min(m.body.size(), c.max_body_log);
            fprintf(f, "[body, %zu bytes, not decryptable as the game's API format]\n%s\n",
                    m.body.size(), decode::hexdump(m.body.data(), n, n).c_str());
        }
    }
    fprintf(f, "\n");
    fclose(f);
}

// ---- one connection: accept the game, connect upstream, relay -------------------------
static void handle_connection(SOCKET client, int port) {
    t_proxy_thread = true;   // this thread's own upstream leg gets real DNS + real TLS validation
    TlsStream down;
    std::string host;
    if (!down.accept_as_server(client, identity_cert_context(), &host)) {
        logf("mitm: TLS handshake with the game failed on port %d", port);
        closesocket(client); return;
    }
    if (host.empty()) { logf("mitm: no SNI host name from the game's ClientHello; cannot route upstream"); closesocket(client); return; }

    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char portbuf[8]; snprintf(portbuf, sizeof portbuf, "%d", port);
    if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || !res) {
        logf("mitm: could not resolve the real address of %s", host.c_str()); closesocket(client); return;
    }
    SOCKET up = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    bool connected = up != INVALID_SOCKET && connect(up, res->ai_addr, (int)res->ai_addrlen) == 0;
    freeaddrinfo(res);
    if (!connected) { logf("mitm: could not connect to the real %s:%d", host.c_str(), port); closesocket(client); return; }

    TlsStream upstream;
    if (!upstream.connect_as_client(up, host, config().upstream_verify)) {
        logf("mitm: TLS handshake with the real %s failed", host.c_str());
        closesocket(up); closesocket(client); return;
    }
    logf("mitm: relaying %s (port %d)", host.c_str(), port);

    BufReader down_r(down), up_r(upstream);
    for (;;) {
        HttpMessage req;
        if (!read_http_message(down_r, req)) break;
        traffic_log(host, ">>", req);
        if (!write_http_message(upstream, req)) break;

        HttpMessage resp;
        if (!read_http_message(up_r, resp)) break;
        traffic_log(host, "<<", resp);
        if (!write_http_message(down, resp)) break;
    }
    closesocket(up); closesocket(client);
}

static void listener_thread(std::string bind_ip, int port) {
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET) return;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((u_short)port);
    InetPtonA(AF_INET, bind_ip.c_str(), &addr.sin_addr);
    int yes = 1; setsockopt(l, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof yes);
    if (bind(l, (sockaddr*)&addr, sizeof addr) != 0 || listen(l, 16) != 0) {
        logf("mitm: could not bind %s:%d (port in use?)", bind_ip.c_str(), port);
        closesocket(l); return;
    }
    logf("mitm: listening on %s:%d", bind_ip.c_str(), port);
    for (;;) {
        SOCKET c = accept(l, nullptr, nullptr);
        if (c == INVALID_SOCKET) break;
        std::thread(handle_connection, c, port).detach();
    }
}

bool start_mitm() {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    Config& c = config();
    if (c.ports.empty()) return false;
    for (int port : c.ports) std::thread(listener_thread, c.bind_ip, port).detach();
    return true;
}

}  // namespace loader
