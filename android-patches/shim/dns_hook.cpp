// dns_hook.cpp - see dns_hook.h.
#include "dns_hook.h"
#include "elf_hook.h"
#include "config.h"
#include "log_file.h"
#include <android/log.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

namespace shim {

using getaddrinfo_t = int (*)(const char*, const char*, const addrinfo*, addrinfo**);
static getaddrinfo_t real_getaddrinfo = nullptr;

static int hook_getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) {
    Config& c = config();
    const char* target = node;
    std::string redirected;
    if (c.dns_redirect && node && !c.redirect_ip.empty()) {
        redirected = c.redirect_ip;
        target = redirected.c_str();
    }
    int rc = real_getaddrinfo(target, service, hints, res);

    if (c.packet_log && node) {
        char ip[INET6_ADDRSTRLEN] = "?";
        if (rc == 0 && res && *res) {
            void* addr = (*res)->ai_family == AF_INET
                ? (void*)&((sockaddr_in*)(*res)->ai_addr)->sin_addr
                : (void*)&((sockaddr_in6*)(*res)->ai_addr)->sin6_addr;
            inet_ntop((*res)->ai_family, addr, ip, sizeof ip);
        }
        if (!redirected.empty())
            log_line("dns", "%s -> redirected to %s -> resolved %s", node, redirected.c_str(), ip);
        else
            log_line("dns", "%s -> resolved %s", node, ip);
    }
    return rc;
}

void install_dns_hook() {
    int n = shim::elf_hook_symbol("getaddrinfo", (void*)hook_getaddrinfo, (void**)&real_getaddrinfo);
    LOGT("dns: hooked getaddrinfo in %d module(s), redirect=%d", n, config().dns_redirect);
}

}  // namespace shim
