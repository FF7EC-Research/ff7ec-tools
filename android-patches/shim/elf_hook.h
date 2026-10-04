// elf_hook.h - GOT/PLT symbol hooking across every loaded ELF module.
//
// Android's dynamic linker resolves an external call like getaddrinfo() or
// dlsym() through a per-module GOT slot. This rewrites that slot wherever it
// appears (enumerated via dl_iterate_phdr(), the standard, supported way to
// walk loaded modules and their program headers - no /proc/self/maps text
// parsing or guessed load addresses), so every module's calls to that symbol
// land in `replacement` instead. `*out_original` receives the value the slot
// held before the first hook (the real function, for forwarding).
//
// Platform libraries (/apex/, /system/, /system_ext/, /vendor/, /product/)
// are always skipped, regardless of module_substr - confirmed on-device
// (see ../../../../README.md): one of them is cross-DSO CFI-hardened, and a
// GOT slot redirected to a replacement in a different DSO trips CFI's
// indirect-call type check, which aborts with no message and an
// unsymbolized backtrace. IL2CPP/Unity/YAHA are never in these partitions
// anyway - only the app's own libraries under /data/app/... are.
//
// Scope note: this only ever rewrites a GOT entry whose *name* matches one we
// deliberately chose (getaddrinfo, dlsym); it does not disassemble, relocate,
// or alter any function's own code.
#pragma once
#include <cstdint>
#include <cstddef>

namespace shim {

// Hooks `symbol` in every loaded module's PLT relocations (.rela.plt, i.e.
// lazily-bound external calls - what getaddrinfo()/dlsym() calls compile to).
// Returns how many modules were patched. Safe to call again with the same
// symbol/replacement (already-hooked slots are left alone).
int elf_hook_symbol(const char* symbol, void* replacement, void** out_original);

// Same, but restricted to modules whose path contains `module_substr`
// (e.g. "libil2cpp.so"). Pass nullptr for module_substr to hook everywhere.
int elf_hook_symbol_in(const char* module_substr, const char* symbol,
                       void* replacement, void** out_original);

}  // namespace shim
