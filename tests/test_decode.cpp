// Native test: decode.cpp against vectors produced by tests/make_vectors.py
#include "../loader/decode.h"
#include <cstdio>
#include <fstream>
#include <iterator>
using namespace decode;
static Bytes rd(const char* f) { std::ifstream i(f, std::ios::binary); return Bytes((std::istreambuf_iterator<char>(i)), {}); }
int main(int argc, char** argv) {
    const char* d = argc > 1 ? argv[1] : ".";
    int fail = 0;
    auto path = [&](const char* n) { return std::string(d) + "/" + n; };
    Bytes req = rd(path("req.bin").c_str()), resp = rd(path("resp.bin").c_str()), want = rd(path("plain.pb").c_str());
    auto a = decode_body(req.data(), req.size(), Kind::Request);
    if (!a.ok || a.plain != want || a.cipher != "client-api-key") { puts("FAIL request"); ++fail; }
    auto b = decode_body(resp.data(), resp.size(), Kind::Response);
    if (!b.ok || b.plain != want || b.cipher != "server-api-key") { puts("FAIL response"); ++fail; }
    if (!a.is_protobuf || a.text.find("get_check") == std::string::npos) { puts("FAIL pb dump"); ++fail; }
    puts(a.text.c_str());
    // LZ4 frame with a real match: literals "abcd", match(off 4,len 8), literal "x"
    const uint8_t fr[] = {0x04,0x22,0x4D,0x18,0x60,0x40,0x82, 9,0,0,0, 0x44,'a','b','c','d',4,0, 0x10,'x', 0,0,0,0};
    Bytes lz; if (!lz4_frame_decompress(fr, sizeof fr, lz) || std::string(lz.begin(), lz.end()) != "abcdabcdabcdx") { puts("FAIL lz4 match"); ++fail; }
    Bytes junk(64, 7);
    if (decode_body(junk.data(), junk.size(), Kind::Request).ok) { puts("FAIL junk accepted"); ++fail; }
    puts(fail ? "FAILED" : "ALL OK");
    return fail;
}
