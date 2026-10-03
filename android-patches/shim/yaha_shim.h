// yaha_shim.h - hooks into Cysharp.Net.Http.YetAnotherHttpHandler.Native
// (the Rust/hyper/rustls HTTP-2 client this game's MagicOnion/gRPC layer
// runs over), via the FFI surface documented at
// https://github.com/Cysharp/YetAnotherHttpHandler (native/yaha_native/src/
// {interop,primitives,binding,context}.rs, commit 2dfd96c).
//
// IL2CPP resolves every [DllImport] target with its own dlopen()+dlsym()
// at first use rather than a static ELF dependency, so these are hooked by
// interposing dlsym() itself (see install()) and returning our own
// trampoline's address the first time a given yaha_* name is looked up -
// the same technique the public writeup at
// https://blog.vibbit.me/2026/08/qa-grpc-yaha/ describes using against this
// exact library for a different game.
#pragma once

namespace shim {

// Installs the dlsym interposer covering every hook below. Call once, after
// config::load_config(). Shows the "hooks loaded" toast once installed.
void install_yaha_hooks();

}  // namespace shim
