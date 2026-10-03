// protobuf_dump.cpp - see protobuf_dump.h. Ported from ../../loader/decode.cpp
// (protobuf_dump()/hexdump(), unchanged in substance; FieldName/top-level
// service-method naming isn't used here since the method name comes from the
// gRPC :path pseudo-header instead of a fixed field table).
#include "protobuf_dump.h"
#include <cstdio>
#include <cstring>

namespace shim {

static bool rd_varint(const uint8_t* p, size_t n, size_t& i, uint64_t& v) {
    v = 0;
    for (int sh = 0; sh < 70; sh += 7) {
        if (i >= n) return false;
        uint8_t b = p[i++]; v |= (uint64_t)(b & 0x7f) << sh;
        if (!(b & 0x80)) return true;
    }
    return false;
}

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

static bool printable(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] < 32 || p[i] == 127) return false;
    return true;
}
static bool texty(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] < 9 || (p[i] > 13 && p[i] < 32) || p[i] == 127) return false;
    return true;
}

static void dump_msg(const uint8_t* p, size_t n, int ind, std::string& o, int depth) {
    size_t i = 0; char b[96];
    while (i < n) {
        uint64_t tag; rd_varint(p, n, i, tag);
        int fn = (int)(tag >> 3), wt = tag & 7;
        o.append(ind * 2, ' ');
        snprintf(b, sizeof b, "%d", fn); o += b;
        if (wt == 0) {
            uint64_t v; rd_varint(p, n, i, v);
            snprintf(b, sizeof b, ": %llu\n", (unsigned long long)v); o += b;
        } else if (wt == 1) {
            uint64_t v = 0; memcpy(&v, p + i, 8); i += 8;
            snprintf(b, sizeof b, ": fixed64 0x%016llx\n", (unsigned long long)v); o += b;
        } else if (wt == 5) {
            uint32_t v; memcpy(&v, p + i, 4); i += 4;
            snprintf(b, sizeof b, ": fixed32 0x%08x\n", v); o += b;
        } else {
            uint64_t l; rd_varint(p, n, i, l);
            const uint8_t* d = p + i; i += (size_t)l;
            if (l == 0) { o += ": \"\"\n"; }
            else if (printable(d, (size_t)l)) {
                o += ": \"";
                for (size_t k = 0; k < l; ++k) { unsigned char c = d[k]; if (c=='"'||c=='\\') o+='\\'; o += (char)c; }
                o += "\"\n";
            } else if (depth < 8 && looks_like_message(d, (size_t)l, depth)) {
                o += " {\n"; dump_msg(d, (size_t)l, ind + 1, o, depth + 1);
                o.append(ind * 2, ' '); o += "}\n";
            } else if (texty(d, (size_t)l)) {
                o += ": \"";
                for (size_t k = 0; k < l; ++k) { if (d[k]=='\n') o+="\\n"; else if (d[k]=='\r') o+="\\r"; else if (d[k]=='\t') o+="\\t"; else o += (char)d[k]; }
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

std::string protobuf_dump(const uint8_t* p, size_t n) {
    if (!looks_like_message(p, n)) return "";
    std::string o; dump_msg(p, n, 0, o, 0); return o;
}

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

}  // namespace shim
