// tls_schannel.h - minimal blocking TLS stream over SChannel.
//
// Used on both legs of the local loopback proxy: as a TLS *server* (presenting
// our local proxy certificate to the game, which already trusts it via
// ssl_bypass.cpp) and as a TLS *client* (making the genuine, normally-
// validated connection to the real game server). No network access beyond
// the socket it's given.
#pragma once
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <string>
#include <vector>
#include <cstdint>

namespace loader {

class TlsStream {
public:
    ~TlsStream();

    // Server role: `cert` is our own PCCERT_CONTEXT (identity_cert_context()).
    // `sni_out`, if non-null, receives the ClientHello's SNI host name (read
    // before the handshake completes) so the caller knows who to connect
    // upstream to.
    bool accept_as_server(SOCKET s, void* cert, std::string* sni_out);

    // Client role: real handshake against `host`; set `verify` to false only
    // to intentionally skip validation (e.g. the server was already renamed/
    // replaced as part of this preservation effort).
    bool connect_as_client(SOCKET s, const std::string& host, bool verify);

    // Blocking plaintext read/write over the established TLS session.
    int  read(uint8_t* buf, int len);     // 0 = clean close, <0 = error
    bool write(const uint8_t* buf, int len);

private:
    SOCKET sock_ = INVALID_SOCKET;
    CredHandle cred_{};
    CtxtHandle ctx_{};
    bool have_cred_ = false, have_ctx_ = false;
    SecPkgContext_StreamSizes sizes_{};
    std::vector<uint8_t> recv_buf_;   // raw bytes read from the socket, not yet decrypted
    std::vector<uint8_t> plain_buf_;  // decrypted bytes not yet consumed by read()
    bool fill_recv(int at_least);
    bool server_handshake_loop(SOCKET s, std::string* sni_out);
    bool client_handshake_loop(SOCKET s, const std::wstring& host);
};

}  // namespace loader
