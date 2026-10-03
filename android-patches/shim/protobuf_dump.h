// protobuf_dump.h - schema-less protobuf wire-format dump + hexdump.
//
// Ported from ../../loader/decode.h (the PC preservation loader). That file
// also implements AES-256-CBC + an LZ4 frame, for the game's *old* REST API
// body cipher - this Android build's traffic no longer uses that scheme (see
// android-patches/README.md), so only the protobuf/hex pieces are reused
// here, trimmed to drop the Win32-free-but-crypto-specific parts.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace shim {

std::string hexdump(const uint8_t* p, size_t n, size_t max_bytes);

// Schema-less protobuf wire-format dump. Returns "" if `p[0..n)` doesn't
// parse as a well-formed message (used to decide whether to fall back to
// hexdump instead).
std::string protobuf_dump(const uint8_t* p, size_t n);

}  // namespace shim
