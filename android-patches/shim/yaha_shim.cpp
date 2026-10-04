// yaha_shim.cpp - see yaha_shim.h.
#include "yaha_shim.h"
#include "elf_hook.h"
#include "config.h"
#include "log_file.h"
#include "android_bridge.h"
#include "protobuf_dump.h"
#include <android/log.h>
#include <dlfcn.h>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

namespace shim {

// ---- FFI types, exactly as native/yaha_native/src/{interop,primitives}.rs ------
extern "C" {
struct StringBuffer { const uint8_t* ptr; int32_t length; };
struct YahaNativeRuntimeContext;
struct YahaNativeContext;
struct YahaNativeRequestContext;
enum class YahaHttpVersion : int32_t { Http09, Http10, Http11, Http2, Http3 };
enum class CompletionReason : int32_t { Success, Error, Aborted };
enum class WriteResult : int32_t { Success, Full, AlreadyCompleted };
}

static std::string sb(const StringBuffer* s) {
    return (s && s->ptr && s->length > 0) ? std::string((const char*)s->ptr, s->length) : std::string();
}

// ---- per-request bookkeeping, correlated by req_ctx (set-up) and req_seq (I/O) --
struct PendingRequest {
    int32_t seq = -1;
    std::string method, uri;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
    bool has_body = false;
};

static std::mutex g_mtx;
static std::map<const void*, PendingRequest> g_by_ctx;     // req_ctx -> request
static std::map<int32_t, const void*> g_ctx_by_seq;        // req_seq -> req_ctx
static std::map<int32_t, std::vector<uint8_t>> g_response; // req_seq -> accumulated response body
static bool g_first_decode_toasted = false;

// Splits `buf` into gRPC length-prefixed messages (1-byte compression flag +
// 4-byte big-endian length + message) and protobuf-dumps each; falls back to
// a hexdump if the buffer isn't (or isn't fully) that framing.
static std::string dump_grpc_frames(const uint8_t* buf, size_t n, bool& any_protobuf) {
    std::string out;
    size_t i = 0;
    while (i + 5 <= n) {
        uint32_t len = (buf[i+1] << 24) | (buf[i+2] << 16) | (buf[i+3] << 8) | buf[i+4];
        if (i + 5 + len > n) break;
        char hdr[64]; snprintf(hdr, sizeof hdr, "-- message (%u bytes, compressed=%d) --\n", len, buf[i]);
        out += hdr;
        std::string pb = protobuf_dump(buf + i + 5, len);
        if (!pb.empty()) { out += pb; any_protobuf = true; }
        else out += hexdump(buf + i + 5, len, 512);
        i += 5 + len;
    }
    if (i < n) {
        out += "-- trailing non-frame bytes --\n";
        out += hexdump(buf + i, n - i, 512);
    }
    return out.empty() ? "(empty body)\n" : out;
}

static void maybe_toast_first_decode(bool any_protobuf) {
    if (!any_protobuf) return;
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_first_decode_toasted) return;
    g_first_decode_toasted = true;
    show_toast("FF7EC shim: first decrypted traffic logged");
}

static void flush_request(const PendingRequest& r) {
    log_line("grpc", "--> %s %s (%zu header(s), %zu byte body)",
             r.method.c_str(), r.uri.c_str(), r.headers.size(), r.body.size());
    for (auto& h : r.headers) log_line("grpc", "    %s: %s", h.first.c_str(), h.second.c_str());
    if (!r.body.empty()) {
        bool any = false;
        std::string dump = dump_grpc_frames(r.body.data(), r.body.size(), any);
        log_block("grpc", (">> request body for " + r.uri).c_str(), dump.c_str());
        maybe_toast_first_decode(any);
    }
}

static void flush_response(int32_t /*seq*/, const std::string& uri, int status, const std::vector<uint8_t>& body) {
    log_line("grpc", "<-- %d for %s (%zu byte body)", status, uri.c_str(), body.size());
    if (!body.empty()) {
        bool any = false;
        std::string dump = dump_grpc_frames(body.data(), body.size(), any);
        log_block("grpc", ("<< response body for " + uri).c_str(), dump.c_str());
        maybe_toast_first_decode(any);
    }
}

// =================================================================================
// Real function pointers, resolved once the native lib is loaded (see
// resolve_real() in install_yaha_hooks()).
namespace real {
static void (*yaha_build_client)(YahaNativeContext*) = nullptr;
static void (*yaha_client_config_skip_certificate_verification)(YahaNativeContext*, bool) = nullptr;
using OnStatus = void (*)(int32_t, intptr_t, int32_t, YahaHttpVersion);
using OnReceive = void (*)(int32_t, intptr_t, size_t, const uint8_t*, size_t);
using OnComplete = void (*)(int32_t, intptr_t, CompletionReason, uint32_t);
static YahaNativeContext* (*yaha_init_context)(YahaNativeRuntimeContext*, OnStatus, OnReceive, OnComplete) = nullptr;
static OnStatus    on_status  = nullptr;
static OnReceive   on_receive = nullptr;
static OnComplete  on_complete = nullptr;
static const YahaNativeRequestContext* (*yaha_request_new)(const YahaNativeContext*, int32_t) = nullptr;
static bool (*yaha_request_set_method)(const YahaNativeContext*, const YahaNativeRequestContext*, const StringBuffer*) = nullptr;
static bool (*yaha_request_set_uri)(const YahaNativeContext*, const YahaNativeRequestContext*, const StringBuffer*) = nullptr;
static bool (*yaha_request_set_header)(const YahaNativeContext*, const YahaNativeRequestContext*, const StringBuffer*, const StringBuffer*) = nullptr;
static bool (*yaha_request_set_has_body)(const YahaNativeContext*, const YahaNativeRequestContext*, bool) = nullptr;
static WriteResult (*yaha_request_write_body)(const YahaNativeContext*, const YahaNativeRequestContext*, const uint8_t*, size_t) = nullptr;
static bool (*yaha_request_complete_body)(const YahaNativeContext*, const YahaNativeRequestContext*) = nullptr;
static bool (*yaha_request_destroy)(const YahaNativeContext*, const YahaNativeRequestContext*) = nullptr;
}  // namespace real

// Finds req_ctx's seq -> request map entry status for logging; status_code is
// cached per-seq too so flush_response can report it.
static std::map<int32_t, int32_t> g_status_by_seq;

// ---- trampolines ----------------------------------------------------------------
static void shim_build_client(YahaNativeContext* ctx) {
    if (config().ssl_bypass && real::yaha_client_config_skip_certificate_verification) {
        real::yaha_client_config_skip_certificate_verification(ctx, true);
        log_line("init", "ssl_bypass: forced skip_certificate_verification(true)");
    }
    real::yaha_build_client(ctx);
}

static void shim_on_status(int32_t seq, intptr_t state, int32_t status_code, YahaHttpVersion version) {
    { std::lock_guard<std::mutex> lk(g_mtx); g_status_by_seq[seq] = status_code; g_response[seq] = {}; }
    if (real::on_status) real::on_status(seq, state, status_code, version);
}
static void shim_on_receive(int32_t seq, intptr_t state, size_t length, const uint8_t* buf, size_t task_handle) {
    if (config().packet_log && buf && length) {
        std::lock_guard<std::mutex> lk(g_mtx);
        auto& v = g_response[seq];
        v.insert(v.end(), buf, buf + length);
    }
    if (real::on_receive) real::on_receive(seq, state, length, buf, task_handle);
}
static void shim_on_complete(int32_t seq, intptr_t state, CompletionReason reason, uint32_t h2_error) {
    if (config().packet_log) {
        std::string uri; int status = -1; std::vector<uint8_t> body;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            auto ci = g_ctx_by_seq.find(seq);
            if (ci != g_ctx_by_seq.end()) {
                auto ri = g_by_ctx.find(ci->second);
                if (ri != g_by_ctx.end()) uri = ri->second.uri;
            }
            auto si = g_status_by_seq.find(seq); if (si != g_status_by_seq.end()) status = si->second;
            auto bi = g_response.find(seq);
            if (bi != g_response.end()) { body = std::move(bi->second); g_response.erase(bi); }
            g_status_by_seq.erase(seq);
        }
        if (reason != CompletionReason::Success)
            log_line("grpc", "<-- %s for %s (h2 error %u)",
                     reason == CompletionReason::Aborted ? "ABORTED" : "ERROR", uri.c_str(), h2_error);
        else
            flush_response(seq, uri, status, body);
    }
    if (real::on_complete) real::on_complete(seq, state, reason, h2_error);
}

static YahaNativeContext* shim_init_context(YahaNativeRuntimeContext* rt, real::OnStatus s, real::OnReceive r, real::OnComplete c) {
    real::on_status = s; real::on_receive = r; real::on_complete = c;
    return real::yaha_init_context(rt, shim_on_status, shim_on_receive, shim_on_complete);
}

static const YahaNativeRequestContext* shim_request_new(const YahaNativeContext* ctx, int32_t seq) {
    const YahaNativeRequestContext* req_ctx = real::yaha_request_new(ctx, seq);
    if (config().packet_log && req_ctx) {
        std::lock_guard<std::mutex> lk(g_mtx);
        PendingRequest req;
        req.seq = seq;
        g_by_ctx[req_ctx] = std::move(req);
        g_ctx_by_seq[seq] = req_ctx;
    }
    return req_ctx;
}
static bool shim_set_method(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc, const StringBuffer* v) {
    if (config().packet_log) { std::lock_guard<std::mutex> lk(g_mtx); auto it = g_by_ctx.find(rc); if (it != g_by_ctx.end()) it->second.method = sb(v); }
    return real::yaha_request_set_method(ctx, rc, v);
}
static bool shim_set_uri(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc, const StringBuffer* v) {
    if (config().packet_log) { std::lock_guard<std::mutex> lk(g_mtx); auto it = g_by_ctx.find(rc); if (it != g_by_ctx.end()) it->second.uri = sb(v); }
    return real::yaha_request_set_uri(ctx, rc, v);
}
static bool shim_set_header(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc, const StringBuffer* k, const StringBuffer* v) {
    if (config().packet_log) { std::lock_guard<std::mutex> lk(g_mtx); auto it = g_by_ctx.find(rc); if (it != g_by_ctx.end()) it->second.headers.emplace_back(sb(k), sb(v)); }
    return real::yaha_request_set_header(ctx, rc, k, v);
}
static bool shim_set_has_body(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc, bool v) {
    if (config().packet_log) { std::lock_guard<std::mutex> lk(g_mtx); auto it = g_by_ctx.find(rc); if (it != g_by_ctx.end()) it->second.has_body = v; }
    bool r = real::yaha_request_set_has_body(ctx, rc, v);
    if (config().packet_log && !v) {
        // No body coming (e.g. a unary call with an empty request message, or a
        // GET-equivalent) - nothing will call complete_body, so log now.
        std::lock_guard<std::mutex> lk(g_mtx);
        auto it = g_by_ctx.find(rc);
        if (it != g_by_ctx.end()) flush_request(it->second);
    }
    return r;
}
static WriteResult shim_write_body(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc, const uint8_t* buf, size_t len) {
    if (config().packet_log) { std::lock_guard<std::mutex> lk(g_mtx); auto it = g_by_ctx.find(rc); if (it != g_by_ctx.end() && buf && len) it->second.body.insert(it->second.body.end(), buf, buf + len); }
    return real::yaha_request_write_body(ctx, rc, buf, len);
}
static bool shim_complete_body(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc) {
    if (config().packet_log) {
        std::lock_guard<std::mutex> lk(g_mtx);
        auto it = g_by_ctx.find(rc);
        if (it != g_by_ctx.end()) flush_request(it->second);
    }
    return real::yaha_request_complete_body(ctx, rc);
}
static bool shim_request_destroy(const YahaNativeContext* ctx, const YahaNativeRequestContext* rc) {
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        auto it = g_by_ctx.find(rc);
        if (it != g_by_ctx.end()) { g_ctx_by_seq.erase(it->second.seq); g_by_ctx.erase(it); }
    }
    return real::yaha_request_destroy(ctx, rc);
}

// ---- dlsym interposition --------------------------------------------------------
using dlsym_t = void* (*)(void*, const char*);
static dlsym_t real_dlsym = nullptr;

// Resolves the real address directly (bypassing our own dlsym hook) once,
// from our own handle to the already-loaded native library.
static void* resolve_real(const char* name) {
    static void* handle = dlopen("libCysharp.Net.Http.YetAnotherHttpHandler.Native.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle) return nullptr;
    return real_dlsym ? real_dlsym(handle, name) : dlsym(handle, name);
}

static void* hook_dlsym(void* handle, const char* name) {
    void* real_result = real_dlsym(handle, name);
    if (!real_result || !name) return real_result;

#define MAP(sym, slot, trampoline) \
    if (!strcmp(name, sym)) { if (!real::slot) real::slot = (decltype(real::slot))real_result; return (void*)trampoline; }

    MAP("yaha_build_client", yaha_build_client, shim_build_client)
    MAP("yaha_client_config_skip_certificate_verification", yaha_client_config_skip_certificate_verification, real_result)
    MAP("yaha_init_context", yaha_init_context, shim_init_context)
    MAP("yaha_request_new", yaha_request_new, shim_request_new)
    MAP("yaha_request_set_method", yaha_request_set_method, shim_set_method)
    MAP("yaha_request_set_uri", yaha_request_set_uri, shim_set_uri)
    MAP("yaha_request_set_header", yaha_request_set_header, shim_set_header)
    MAP("yaha_request_set_has_body", yaha_request_set_has_body, shim_set_has_body)
    MAP("yaha_request_write_body", yaha_request_write_body, shim_write_body)
    MAP("yaha_request_complete_body", yaha_request_complete_body, shim_complete_body)
    MAP("yaha_request_destroy", yaha_request_destroy, shim_request_destroy)
#undef MAP
    return real_result;
}

void install_yaha_hooks() {
    LOGT("yaha: install_yaha_hooks() starting");
    // skip_certificate_verification is called BY our own shim_build_client, not
    // by the app, so it may never otherwise be dlsym'd - resolve it directly.
    real::yaha_client_config_skip_certificate_verification =
        (decltype(real::yaha_client_config_skip_certificate_verification))resolve_real("yaha_client_config_skip_certificate_verification");

    int n = elf_hook_symbol("dlsym", (void*)hook_dlsym, (void**)&real_dlsym);
    LOGT("yaha: dlsym interposer installed in %d module(s)", n);
    log_line("init", "hooks installed: dlsym interposer in %d module(s); ssl_bypass=%d packet_log=%d",
             n, config().ssl_bypass, config().packet_log);
    show_toast("FF7EC shim: hooks loaded");
}

}  // namespace shim
