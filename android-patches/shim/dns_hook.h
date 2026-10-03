// dns_hook.h - optional DNS redirect + always-on resolved-address logging.
#pragma once

namespace shim {

// Hooks getaddrinfo() (GOT/PLT, wherever it's imported - the Rust HTTP client
// calls the normal libc resolver, not a yaha_* FFI function). Always logs
// what host each lookup was for and what address it resolved to; only
// substitutes config().redirect_ip when config().dns_redirect is on.
void install_dns_hook();

}  // namespace shim
