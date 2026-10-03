// log_file.h - append-only text logging into log_directory() (see
// android_bridge.h). One small helper shared by every hook so they all write
// to the same timestamped file.
#pragma once

namespace shim {

// printf-style; `tag` is a short category ("dns", "grpc", "init", ...).
void log_line(const char* tag, const char* fmt, ...);

// Writes a longer, already-formatted block (e.g. a decoded gRPC message)
// verbatim, with its own header line.
void log_block(const char* tag, const char* header, const char* body);

}  // namespace shim
