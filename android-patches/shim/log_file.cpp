// log_file.cpp - see log_file.h.
#include "log_file.h"
#include "android_bridge.h"
#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>

namespace shim {

static std::mutex g_mtx;

static FILE* open_log() {
    std::string dir = log_directory();
    if (dir.empty()) return nullptr;
    std::string path = dir + "/ff7ec_traffic.log";
    return fopen(path.c_str(), "a");
}

static void write_timestamp(FILE* f) {
    timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    tm t; localtime_r(&ts.tv_sec, &t);
    fprintf(f, "[%02d:%02d:%02d.%03ld] ", t.tm_hour, t.tm_min, t.tm_sec, ts.tv_nsec / 1000000);
}

void log_line(const char* tag, const char* fmt, ...) {
    char msg[2048];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", "[%s] %s", tag, msg);

    std::lock_guard<std::mutex> lk(g_mtx);
    FILE* f = open_log();
    if (!f) return;
    write_timestamp(f);
    fprintf(f, "[%s] %s\n", tag, msg);
    fclose(f);
}

void log_block(const char* tag, const char* header, const char* body) {
    std::lock_guard<std::mutex> lk(g_mtx);
    FILE* f = open_log();
    if (!f) return;
    write_timestamp(f);
    fprintf(f, "[%s] %s\n%s\n", tag, header, body);
    fclose(f);
}

}  // namespace shim
