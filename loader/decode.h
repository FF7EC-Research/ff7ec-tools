// decode.h - portable (no Win32) payload decoding: AES-256-CBC, LZ4 frame,
// generic protobuf dump, hexdump. Kept free of Windows headers so it can be
// unit-tested natively (see ../tests).
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace decode {

typedef std::vector<uint8_t> Bytes;

// AES-256-CBC decrypt; strips PKCS#7 padding. False if size/padding is invalid.
bool aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                        const uint8_t* in, size_t n, Bytes& out);
// LZ4 frame (magic 04 22 4D 18) decompress; handles concatenated frames.
bool lz4_frame_decompress(const uint8_t* in, size_t n, Bytes& out);

std::string hexdump(const uint8_t* p, size_t n, size_t max_bytes);

struct FieldName { int number; const char* name; };
// Schema-less protobuf wire-format dump. `top` optionally names the top-level
// field numbers (ApiRequest / ApiResponse oneof). Returns "" if not protobuf.
std::string protobuf_dump(const uint8_t* p, size_t n, const FieldName* top = nullptr);

enum class Kind { Request, Response };
struct ApiDecode {
    bool        ok = false;
    std::string cipher;     // which key matched: "client-api-key" / "server-api-key" / "file-key"
    Bytes       plain;      // decrypted + decompressed payload
    bool        is_protobuf = false;
    std::string text;       // human-readable rendering
};
// Try to undo the game's body protection (IV16 | AES-256-CBC | LZ4 frame).
ApiDecode decode_body(const uint8_t* body, size_t n, Kind kind);

}  // namespace decode
