// decode.cpp - see decode.h. Key material comes from the public ff7ecapi
// research repo (Utils/Crypto.cs); the algorithms are standard.
#include "decode.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace decode {

#include "api_fields.inc"

// ---- AES (decrypt only) ---------------------------------------------------------
static uint8_t g_sbox[256], g_inv[256];
static bool g_aes_init = false;
static uint8_t xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) { if (b & 1) r ^= a; a = xt(a); b >>= 1; }
    return r;
}
static void aes_init() {
    if (g_aes_init) return;
    uint8_t p = 1, q = 1;                     // generate S-box from GF(2^8) inverses
    do {
        p = p ^ (uint8_t)(p << 1) ^ ((p & 0x80) ? 0x1b : 0);
        q ^= q << 1; q ^= q << 2; q ^= q << 4; if (q & 0x80) q ^= 0x09;
        uint8_t x = q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6)) ^
                    (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4));
        g_sbox[p] = x ^ 0x63;
    } while (p != 1);
    g_sbox[0] = 0x63;
    for (int i = 0; i < 256; ++i) g_inv[g_sbox[i]] = (uint8_t)i;
    g_aes_init = true;
}
static void key_expand(const uint8_t key[32], uint8_t rk[240]) {
    memcpy(rk, key, 32);
    uint8_t rcon = 1;
    for (int i = 32; i < 240; i += 4) {
        uint8_t t[4]; memcpy(t, rk + i - 4, 4);
        if (i % 32 == 0) {
            uint8_t a = t[0]; t[0] = g_sbox[t[1]] ^ rcon; t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]]; t[3] = g_sbox[a]; rcon = xt(rcon);
        } else if (i % 32 == 16) {
            for (int j = 0; j < 4; ++j) t[j] = g_sbox[t[j]];
        }
        for (int j = 0; j < 4; ++j) rk[i + j] = rk[i + j - 32] ^ t[j];
    }
}
static void decrypt_block(const uint8_t rk[240], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[14 * 16 + i];
    for (int r = 13; r >= 0; --r) {
        uint8_t t[16];                          // InvShiftRows
        for (int c = 0; c < 4; ++c)
            for (int row = 0; row < 4; ++row)
                t[((c + row) % 4) * 4 + row] = s[c * 4 + row];
        for (int i = 0; i < 16; ++i) s[i] = g_inv[t[i]] ^ rk[r * 16 + i];  // InvSub + AddRoundKey
        if (r > 0) {                            // InvMixColumns
            for (int c = 0; c < 4; ++c) {
                uint8_t* col = s + c * 4; uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);
                col[1] = gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);
                col[2] = gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11);
                col[3] = gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14);
            }
        }
    }
    memcpy(out, s, 16);
}
bool aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t* in,
                        size_t n, Bytes& out) {
    if (n == 0 || n % 16) return false;
    aes_init();
    uint8_t rk[240]; key_expand(key, rk);
    out.resize(n);
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (size_t i = 0; i < n; i += 16) {
        uint8_t b[16]; decrypt_block(rk, in + i, b);
        for (int j = 0; j < 16; ++j) out[i + j] = b[j] ^ prev[j];
        memcpy(prev, in + i, 16);
    }
    uint8_t pad = out.back();
    if (pad == 0 || pad > 16 || pad > n) return false;
    for (size_t i = n - pad; i < n; ++i) if (out[i] != pad) return false;
    out.resize(n - pad);
    return true;
}

// ---- LZ4 -------------------------------------------------------------------------
// Block decoder appends to `out`; matches may reach back into earlier data (linked blocks).
static bool lz4_block(const uint8_t* p, size_t n, Bytes& out) {
    size_t i = 0;
    while (i < n) {
        uint8_t tok = p[i++];
        size_t lit = tok >> 4;
        if (lit == 15) { uint8_t b; do { if (i >= n) return false; b = p[i++]; lit += b; } while (b == 255); }
        if (i + lit > n) return false;
        out.insert(out.end(), p + i, p + i + lit); i += lit;
        if (i >= n) break;                                     // last sequence: literals only
        if (i + 2 > n) return false;
        size_t off = p[i] | (p[i + 1] << 8); i += 2;
        if (off == 0 || off > out.size()) return false;
        size_t ml = tok & 15;
        if (ml == 15) { uint8_t b; do { if (i >= n) return false; b = p[i++]; ml += b; } while (b == 255); }
        ml += 4;
        size_t from = out.size() - off;
        for (size_t k = 0; k < ml; ++k) out.push_back(out[from + k]);   // overlap-safe
    }
    return true;
}
bool lz4_frame_decompress(const uint8_t* p, size_t n, Bytes& out) {
    size_t i = 0; bool any = false;
    while (i + 7 <= n) {
        if (!(p[i] == 0x04 && p[i+1] == 0x22 && p[i+2] == 0x4D && p[i+3] == 0x18)) return any;
        uint8_t flg = p[i + 4];
        if ((flg >> 6) != 1) return false;
        bool bchk = flg & 0x10, csize = flg & 0x08, cchk = flg & 0x04, dict = flg & 0x01;
        i += 6;
        if (csize) i += 8;
        if (dict) i += 4;
        i += 1;                                                // header checksum
        for (;;) {
            if (i + 4 > n) return false;
            uint32_t bs = p[i] | (p[i+1] << 8) | (p[i+2] << 16) | ((uint32_t)p[i+3] << 24); i += 4;
            if (bs == 0) break;
            bool raw = bs & 0x80000000u; bs &= 0x7fffffffu;
            if (i + bs > n) return false;
            if (raw) out.insert(out.end(), p + i, p + i + bs);
            else if (!lz4_block(p + i, bs, out)) return false;
            i += bs + (bchk ? 4 : 0);
        }
        if (cchk) i += 4;
        any = true;
    }
    return any;
}

// ---- hexdump ---------------------------------------------------------------------
std::string hexdump(const uint8_t* p, size_t n, size_t max_bytes) {
    std::string s; char line[128];
    size_t lim = n < max_bytes ? n : max_bytes;
    for (size_t o = 0; o < lim; o += 16) {
        int w = snprintf(line, sizeof line, "%08zx  ", o);
        for (size_t j = 0; j < 16; ++j) {
            if (o + j < lim) w += snprintf(line + w, sizeof line - w, "%02x ", p[o + j]);
            else w += snprintf(line + w, sizeof line - w, "   ");
            if (j == 7) line[w++] = ' ';
        }
        line[w++] = ' ';
        for (size_t j = 0; j < 16 && o + j < lim; ++j) line[w++] = (p[o+j] >= 32 && p[o+j] < 127) ? p[o+j] : '.';
        line[w++] = '\n'; s.append(line, w);
    }
    if (lim < n) { snprintf(line, sizeof line, "... (%zu more bytes)\n", n - lim); s += line; }
    return s;
}

// ---- generic protobuf dump -------------------------------------------------------
static bool rd_varint(const uint8_t* p, size_t n, size_t& i, uint64_t& v) {
    v = 0;
    for (int sh = 0; sh < 70; sh += 7) {
        if (i >= n) return false;
        uint8_t b = p[i++]; v |= (uint64_t)(b & 0x7f) << sh;
        if (!(b & 0x80)) return true;
    }
    return false;
}
// Strict structural check: does the whole buffer parse as a protobuf message?
static bool looks_like_message(const uint8_t* p, size_t n, int depth = 0) {
    if (n == 0 || depth > 8) return false;
    size_t i = 0; int fields = 0;
    while (i < n) {
        uint64_t tag; if (!rd_varint(p, n, i, tag)) return false;
        uint64_t fn = tag >> 3; int wt = tag & 7;
        if (fn == 0 || fn > 536870911) return false;
        if (wt == 0) { uint64_t v; if (!rd_varint(p, n, i, v)) return false; }
        else if (wt == 1) { if (i + 8 > n) return false; i += 8; }
        else if (wt == 5) { if (i + 4 > n) return false; i += 4; }
        else if (wt == 2) { uint64_t l; if (!rd_varint(p, n, i, l) || l > n - i) return false; i += l; }
        else return false;
        ++fields;
    }
    return fields > 0;
}
// strict: no control characters at all (so "\n\tfoo" is tried as a message first)
static bool printable(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] < 32 || p[i] == 127) return false;
    return true;
}
static bool texty(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) if ((p[i] < 9 || (p[i] > 13 && p[i] < 32) || p[i] == 127)) return false;
    return true;
}
static void dump_msg(const uint8_t* p, size_t n, int ind, const FieldName* top, std::string& o, int depth) {
    size_t i = 0; char b[96];
    while (i < n) {
        uint64_t tag; rd_varint(p, n, i, tag);
        int fn = (int)(tag >> 3), wt = tag & 7;
        o.append(ind * 2, ' ');
        const char* nm = nullptr;
        for (const FieldName* f = top; f && f->name; ++f) if (f->number == fn) nm = f->name;
        if (nm) snprintf(b, sizeof b, "%d (%s)", fn, nm); else snprintf(b, sizeof b, "%d", fn);
        o += b;
        if (wt == 0) {
            uint64_t v; rd_varint(p, n, i, v);
            if ((int64_t)v < 0) snprintf(b, sizeof b, ": %llu (int64 %lld)\n", (unsigned long long)v, (long long)v);
            else snprintf(b, sizeof b, ": %llu\n", (unsigned long long)v);
            o += b;
        } else if (wt == 1) {
            uint64_t v = 0; memcpy(&v, p + i, 8); i += 8;
            double d; memcpy(&d, &v, 8);
            snprintf(b, sizeof b, ": fixed64 0x%016llx (%llu)\n", (unsigned long long)v, (unsigned long long)v); o += b;
        } else if (wt == 5) {
            uint32_t v; memcpy(&v, p + i, 4); i += 4;
            float f; memcpy(&f, &v, 4);
            snprintf(b, sizeof b, ": fixed32 0x%08x (%u)\n", v, v); o += b;
        } else {
            uint64_t l; rd_varint(p, n, i, l);
            const uint8_t* d = p + i; i += (size_t)l;
            if (l == 0) { o += ": \"\"\n"; }
            else if (printable(d, (size_t)l)) {
                o += ": \"";
                for (size_t k = 0; k < l; ++k) {
                    unsigned char c = d[k];
                    if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
                    else if (c == '\n') o += "\\n"; else if (c == '\r') o += "\\r"; else if (c == '\t') o += "\\t";
                    else o += (char)c;
                }
                o += "\"\n";
            } else if (depth < 8 && looks_like_message(d, (size_t)l, depth)) {
                o += " {\n"; dump_msg(d, (size_t)l, ind + 1, nullptr, o, depth + 1);
                o.append(ind * 2, ' '); o += "}\n";
            } else if (texty(d, (size_t)l)) {
                o += ": \"";
                for (size_t k = 0; k < l; ++k) { if (d[k] == '\n') o += "\\n"; else if (d[k] == '\r') o += "\\r"; else if (d[k] == '\t') o += "\\t"; else o += (char)d[k]; }
                o += "\"\n";
            } else {
                snprintf(b, sizeof b, ": bytes[%llu] ", (unsigned long long)l); o += b;
                for (size_t k = 0; k < l && k < 48; ++k) { snprintf(b, sizeof b, "%02x", d[k]); o += b; }
                if (l > 48) o += "...";
                o += "\n";
            }
        }
    }
}
std::string protobuf_dump(const uint8_t* p, size_t n, const FieldName* top) {
    if (!looks_like_message(p, n)) return "";
    std::string o; dump_msg(p, n, 0, top, o, 0); return o;
}

// ---- body protection ---------------------------------------------------------------
// Public research keys (ff7ecapi Utils/Crypto.cs). api: IV16|AES-256-CBC(LZ4(protobuf)).
static const uint8_t kClientApiKey[32] = {0x1a,0xce,0xbd,0xf9,0x48,0x99,0x0c,0x60,0x6b,0x8f,0x38,0xf4,0xb8,0x6a,0xbf,0x9b,0xa9,0x85,0xb3,0xae,0x9b,0x05,0x40,0x0f,0xe7,0x29,0x07,0x39,0x13,0x9e,0xb1,0x9e};
static const uint8_t kServerApiKey[32] = {0x08,0xc3,0x27,0xb1,0xe9,0xd7,0xbe,0xbe,0xe2,0xcc,0x01,0x5b,0xa2,0xb2,0x6f,0x09,0x91,0xf0,0x16,0xb1,0xb8,0xd2,0xcc,0xa4,0x36,0x05,0x12,0xaa,0x02,0x7d,0xf7,0xe0};
static const uint8_t kFileKey[32] = {102,213,122,113,226,89,169,26,130,132,188,167,10,45,6,6,
                                     121,122,150,83,91,70,132,153,161,61,144,105,181,62,72,144};

ApiDecode decode_body(const uint8_t* body, size_t n, Kind kind) {
    ApiDecode r;
    if (n < 32) return r;
    struct K { const uint8_t* key; const char* name; };
    K order[3];
    if (kind == Kind::Request) { order[0] = {kClientApiKey, "client-api-key"}; order[1] = {kServerApiKey, "server-api-key"}; }
    else                       { order[0] = {kServerApiKey, "server-api-key"}; order[1] = {kClientApiKey, "client-api-key"}; }
    order[2] = {kFileKey, "file-key"};
    for (auto& k : order) {
        Bytes dec;
        if (!aes256_cbc_decrypt(k.key, body, body + 16, n - 16, dec)) continue;
        Bytes plain;
        if (!lz4_frame_decompress(dec.data(), dec.size(), plain)) continue;
        r.ok = true; r.cipher = k.name; r.plain = plain;
        const FieldName* top = kind == Kind::Request ? kApiReqNames : kApiRespNames;
        std::string pb = protobuf_dump(plain.data(), plain.size(), top);
        if (!pb.empty()) { r.is_protobuf = true; r.text = pb; }
        else r.text = hexdump(plain.data(), plain.size(), 256);
        return r;
    }
    return r;
}

}  // namespace decode
