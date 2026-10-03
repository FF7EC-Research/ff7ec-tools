// tls_schannel.cpp - see tls_schannel.h. Standard blocking SChannel
// handshake/record loops (the same shape as Microsoft's "Simple Server" /
// "Simple Client" SChannel samples), used only over the local loopback proxy
// socket and the proxy's own upstream socket to the real game server.
#include "tls_schannel.h"
#include "loader.h"
#include <wincrypt.h>
#include <sddl.h>
#include <algorithm>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

namespace loader {

static const DWORD kAsc = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                          ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                          ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
static const DWORD kIsc = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                          ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                          ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

TlsStream::~TlsStream() {
    if (have_ctx_) DeleteSecurityContext(&ctx_);
    if (have_cred_) FreeCredentialsHandle(&cred_);
}

// ---- raw socket I/O, used only to feed/drain SChannel buffers -------------------
static int sock_recv_some(SOCKET s, uint8_t* buf, int len) { return recv(s, (char*)buf, len, 0); }
static bool sock_send_all(SOCKET s, const uint8_t* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool TlsStream::fill_recv(int at_least) {
    while ((int)recv_buf_.size() < at_least) {
        uint8_t tmp[4096];
        int n = sock_recv_some(sock_, tmp, sizeof tmp);
        if (n <= 0) return false;
        recv_buf_.insert(recv_buf_.end(), tmp, tmp + n);
    }
    return true;
}

// ---- optional: read the ClientHello's SNI without disturbing recv_buf_ ----------
static bool parse_sni(const uint8_t* p, size_t n, std::string& out) {
    // TLS record: type(1)=0x16 version(2) length(2) ; handshake: type(1)=0x01
    // length(3) version(2) random(32) session_id_len(1)+id cipher_len(2)+ciphers
    // compression_len(1)+methods extensions_len(2) then [ext_type(2) ext_len(2) data]*
    if (n < 5 || p[0] != 0x16) return false;
    size_t rec_len = (p[3] << 8) | p[4];
    if (n < 5 + rec_len || rec_len < 4) return false;
    const uint8_t* h = p + 5;
    if (h[0] != 0x01) return false;
    size_t i = 4 + 2 + 32;                      // skip hs header, version, random
    if (i >= rec_len) return false;
    size_t sid_len = h[i]; i += 1 + sid_len;
    if (i + 2 > rec_len) return false;
    size_t cs_len = (h[i] << 8) | h[i + 1]; i += 2 + cs_len;
    if (i + 1 > rec_len) return false;
    size_t comp_len = h[i]; i += 1 + comp_len;
    if (i + 2 > rec_len) return false;
    size_t ext_total = (h[i] << 8) | h[i + 1]; i += 2;
    size_t ext_end = i + ext_total;
    if (ext_end > rec_len) return false;
    while (i + 4 <= ext_end) {
        int type = (h[i] << 8) | h[i + 1];
        size_t len = (h[i + 2] << 8) | h[i + 3];
        i += 4;
        if (i + len > ext_end) return false;
        if (type == 0 && len >= 5) {            // server_name extension
            size_t list_len = (h[i] << 8) | h[i + 1];
            size_t name_len = (h[i + 3] << 8) | h[i + 4];
            if (5 + name_len <= list_len + 2 && i + 5 + name_len <= ext_end) {
                out.assign((const char*)h + i + 5, name_len);
                return true;
            }
        }
        i += len;
    }
    return false;
}

// ---- server (downstream, towards the game) ---------------------------------------
bool TlsStream::accept_as_server(SOCKET s, void* cert_ctx, std::string* sni_out) {
    sock_ = s;
    SCHANNEL_CRED cred{}; cred.dwVersion = SCHANNEL_CRED_VERSION;
    PCCERT_CONTEXT cert = (PCCERT_CONTEXT)cert_ctx;
    cred.cCreds = 1; cred.paCred = &cert;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
    cred.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
    TimeStamp exp;
    if (AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_INBOUND, nullptr,
                                  &cred, nullptr, nullptr, &cred_, &exp) != SEC_E_OK)
        return false;
    have_cred_ = true;

    // Make sure at least the fixed TLS record header is present, then size the
    // whole ClientHello record before SNI-sniffing it.
    if (!fill_recv(5)) return false;
    size_t rec_len = ((size_t)recv_buf_[3] << 8) | recv_buf_[4];
    if (!fill_recv((int)(5 + rec_len))) return false;
    if (sni_out) parse_sni(recv_buf_.data(), recv_buf_.size(), *sni_out);

    return server_handshake_loop(s, nullptr);
}

bool TlsStream::server_handshake_loop(SOCKET /*s*/, std::string*) {
    SecBuffer in_bufs[2], out_bufs[1];
    SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in_bufs}, out_desc{SECBUFFER_VERSION, 1, out_bufs};
    DWORD ctx_attr = 0; TimeStamp exp;
    bool first = true;

    for (;;) {
        in_bufs[0] = {(unsigned long)recv_buf_.size(), SECBUFFER_TOKEN, recv_buf_.data()};
        in_bufs[1] = {0, SECBUFFER_EMPTY, nullptr};
        out_bufs[0] = {0, SECBUFFER_TOKEN, nullptr};

        SECURITY_STATUS st = AcceptSecurityContext(
            &cred_, first ? nullptr : &ctx_, &in_desc, kAsc, 0,
            first ? &ctx_ : nullptr, &out_desc, &ctx_attr, &exp);
        first = false;
        have_ctx_ = true;

        if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
            sock_send_all(sock_, (uint8_t*)out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
            FreeContextBuffer(out_bufs[0].pvBuffer);
        }

        if (st == SEC_E_OK) {
            // Consume whatever of recv_buf_ SChannel didn't use for the handshake.
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA)
                recv_buf_.erase(recv_buf_.begin(), recv_buf_.end() - in_bufs[1].cbBuffer);
            else
                recv_buf_.clear();
            QueryContextAttributes(&ctx_, SECPKG_ATTR_STREAM_SIZES, &sizes_);
            return true;
        }
        if (st == SEC_I_CONTINUE_NEEDED) {
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA)
                recv_buf_.erase(recv_buf_.begin(), recv_buf_.end() - in_bufs[1].cbBuffer);
            else
                recv_buf_.clear();
            if (!fill_recv(5)) return false;
            continue;
        }
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            if (!fill_recv((int)recv_buf_.size() + 1)) return false;
            continue;
        }
        logf("tls(server): handshake failed, status=0x%08x", (unsigned)st);
        return false;
    }
}

// ---- client (upstream, towards the real game server) ----------------------------
bool TlsStream::connect_as_client(SOCKET s, const std::string& host, bool verify) {
    sock_ = s;
    SCHANNEL_CRED cred{}; cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    if (!verify) cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    TimeStamp exp;
    if (AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr,
                                  &cred, nullptr, nullptr, &cred_, &exp) != SEC_E_OK)
        return false;
    have_cred_ = true;
    std::wstring whost(host.begin(), host.end());
    return client_handshake_loop(s, whost);
}

bool TlsStream::client_handshake_loop(SOCKET /*s*/, const std::wstring& host) {
    SecBuffer out_bufs[1]; SecBufferDesc out_desc{SECBUFFER_VERSION, 1, out_bufs};
    DWORD ctx_attr = 0; TimeStamp exp;
    out_bufs[0] = {0, SECBUFFER_TOKEN, nullptr};

    SECURITY_STATUS st = InitializeSecurityContextW(
        &cred_, nullptr, (LPWSTR)host.c_str(), kIsc, 0, 0, nullptr, 0,
        &ctx_, &out_desc, &ctx_attr, &exp);
    have_ctx_ = true;
    if (out_bufs[0].cbBuffer) { sock_send_all(sock_, (uint8_t*)out_bufs[0].pvBuffer, out_bufs[0].cbBuffer); FreeContextBuffer(out_bufs[0].pvBuffer); }
    if (st != SEC_I_CONTINUE_NEEDED) { logf("tls(client): unexpected initial status 0x%08x", (unsigned)st); return false; }

    for (;;) {
        if (!fill_recv((int)recv_buf_.size() + 1)) return false;

        SecBuffer in_bufs[2];
        in_bufs[0] = {(unsigned long)recv_buf_.size(), SECBUFFER_TOKEN, recv_buf_.data()};
        in_bufs[1] = {0, SECBUFFER_EMPTY, nullptr};
        SecBufferDesc in_desc{SECBUFFER_VERSION, 2, in_bufs};
        out_bufs[0] = {0, SECBUFFER_TOKEN, nullptr};

        st = InitializeSecurityContextW(&cred_, &ctx_, (LPWSTR)host.c_str(), kIsc, 0, 0,
                                        &in_desc, 0, nullptr, &out_desc, &ctx_attr, &exp);

        if (out_bufs[0].cbBuffer) { sock_send_all(sock_, (uint8_t*)out_bufs[0].pvBuffer, out_bufs[0].cbBuffer); FreeContextBuffer(out_bufs[0].pvBuffer); }

        if (st == SEC_E_OK) {
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA) recv_buf_.erase(recv_buf_.begin(), recv_buf_.end() - in_bufs[1].cbBuffer);
            else recv_buf_.clear();
            QueryContextAttributes(&ctx_, SECPKG_ATTR_STREAM_SIZES, &sizes_);
            return true;
        }
        if (st == SEC_I_CONTINUE_NEEDED) {
            if (in_bufs[1].BufferType == SECBUFFER_EXTRA) recv_buf_.erase(recv_buf_.begin(), recv_buf_.end() - in_bufs[1].cbBuffer);
            else recv_buf_.clear();
            continue;
        }
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        logf("tls(client): handshake to %ls failed, status=0x%08x", host.c_str(), (unsigned)st);
        return false;
    }
}

// ---- established-session record I/O ----------------------------------------------
int TlsStream::read(uint8_t* out, int len) {
    while (plain_buf_.empty()) {
        if (!fill_recv((int)recv_buf_.size() + 1)) return 0;

        SecBuffer bufs[4];
        bufs[0] = {(unsigned long)recv_buf_.size(), SECBUFFER_DATA, recv_buf_.data()};
        bufs[1] = bufs[2] = bufs[3] = {0, SECBUFFER_EMPTY, nullptr};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};

        SECURITY_STATUS st = DecryptMessage(&ctx_, &desc, 0, nullptr);
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (st == SEC_I_CONTEXT_EXPIRED || st == SEC_I_RENEGOTIATE) return 0;   // treat as clean EOF
        if (st != SEC_E_OK) { logf("tls: DecryptMessage failed 0x%08x", (unsigned)st); return -1; }

        size_t leftover = 0;
        for (auto& b : bufs) {
            if (b.BufferType == SECBUFFER_DATA && b.cbBuffer)
                plain_buf_.insert(plain_buf_.end(), (uint8_t*)b.pvBuffer, (uint8_t*)b.pvBuffer + b.cbBuffer);
            if (b.BufferType == SECBUFFER_EXTRA) leftover = b.cbBuffer;
        }
        recv_buf_.erase(recv_buf_.begin(), recv_buf_.end() - leftover);
    }
    int n = (int)std::min((size_t)len, plain_buf_.size());
    memcpy(out, plain_buf_.data(), n);
    plain_buf_.erase(plain_buf_.begin(), plain_buf_.begin() + n);
    return n;
}

bool TlsStream::write(const uint8_t* data, int len) {
    int header = sizes_.cbHeader, trailer = sizes_.cbTrailer;
    int chunk = sizes_.cbMaximumMessage ? (int)sizes_.cbMaximumMessage : 16384;
    std::vector<uint8_t> msg(header + chunk + trailer);

    for (int off = 0; off < len || (len == 0 && off == 0); off += chunk) {
        int n = std::min(chunk, len - off);
        if (len == 0) n = 0;
        memcpy(msg.data() + header, data + off, n);

        SecBuffer bufs[4];
        bufs[0] = {(unsigned long)header, SECBUFFER_STREAM_HEADER, msg.data()};
        bufs[1] = {(unsigned long)n, SECBUFFER_DATA, msg.data() + header};
        bufs[2] = {(unsigned long)trailer, SECBUFFER_STREAM_TRAILER, msg.data() + header + n};
        bufs[3] = {0, SECBUFFER_EMPTY, nullptr};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, bufs};

        if (EncryptMessage(&ctx_, 0, &desc, 0) != SEC_E_OK) return false;
        int total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        if (!sock_send_all(sock_, msg.data(), total)) return false;
        if (len == 0) break;
    }
    return true;
}

}  // namespace loader
