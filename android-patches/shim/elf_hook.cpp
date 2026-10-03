// elf_hook.cpp - see elf_hook.h.
#include "elf_hook.h"
#include <android/log.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

#define LOGT(...) __android_log_print(ANDROID_LOG_INFO, "ff7ec_shim", __VA_ARGS__)

namespace shim {

#if defined(__aarch64__)
using Rela = Elf64_Rela;
using Sym = Elf64_Sym;
using Dyn = Elf64_Dyn;
#define R_SYM(info) ELF64_R_SYM(info)
#else
#error "This shim targets arm64-v8a only."
#endif

namespace {

struct ModuleDynInfo {
    uintptr_t base = 0;
    const char* strtab = nullptr;
    const Sym* symtab = nullptr;
    const Rela* jmprel = nullptr;
    size_t jmprel_count = 0;
    const Rela* rela = nullptr;      // .rela.dyn - not used for PLT symbols, but
    size_t rela_count = 0;           // tried as a fallback for -z,now binaries.
};

bool find_dynamic(dl_phdr_info* info, ModuleDynInfo& out) {
    out.base = info->dlpi_addr;
    const ElfW(Phdr)* dyn_phdr = nullptr;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) { dyn_phdr = &info->dlpi_phdr[i]; break; }
    }
    if (!dyn_phdr) return false;
    auto* dyn = (const Dyn*)(info->dlpi_addr + dyn_phdr->p_vaddr);

    uintptr_t strtab_addr = 0, pltrelsz = 0, relasz = 0;
    for (; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_STRTAB:   strtab_addr = dyn->d_un.d_ptr; break;
            case DT_SYMTAB:   out.symtab  = (const Sym*)dyn->d_un.d_ptr; break;
            case DT_JMPREL:   out.jmprel  = (const Rela*)dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz    = dyn->d_un.d_val; break;
            case DT_RELA:     out.rela    = (const Rela*)dyn->d_un.d_ptr; break;
            case DT_RELASZ:   relasz      = dyn->d_un.d_val; break;
            default: break;
        }
    }
    // These DT_* pointers are either already absolute (most modern lld output)
    // or need the load bias added (older/bfd-linked libs). Heuristic: if the
    // "pointer" looks smaller than our own base, it's still a link-time
    // (pre-bias) address and needs `base` added.
    auto fixup = [&](uintptr_t v) { return v < out.base ? v + out.base : v; };
    if (strtab_addr) out.strtab = (const char*)fixup(strtab_addr);
    if (out.symtab)  out.symtab = (const Sym*)fixup((uintptr_t)out.symtab);
    if (out.jmprel)  out.jmprel = (const Rela*)fixup((uintptr_t)out.jmprel);
    if (out.rela)    out.rela   = (const Rela*)fixup((uintptr_t)out.rela);
    out.jmprel_count = pltrelsz / sizeof(Rela);
    out.rela_count   = relasz / sizeof(Rela);
    return out.symtab && out.strtab && (out.jmprel || out.rela);
}

// Overwrites one GOT slot (the relocation's target address) with `replacement`,
// after making its page writable (GOT pages are RELRO/read-only post-startup).
bool patch_slot(uintptr_t slot_addr, void* replacement, void** out_original) {
    long page = sysconf(_SC_PAGESIZE);
    void* page_addr = (void*)(slot_addr & ~(page - 1));
    if (mprotect(page_addr, page, PROT_READ | PROT_WRITE) != 0) return false;

    auto* slot = (void**)slot_addr;
    if (*slot == replacement) { mprotect(page_addr, page, PROT_READ); return true; }  // already hooked
    if (out_original && !*out_original) *out_original = *slot;
    *slot = replacement;

    mprotect(page_addr, page, PROT_READ);
    return true;
}

bool patch_relocs(const ModuleDynInfo& m, const Rela* rels, size_t count, const char* symbol,
                  void* replacement, void** out_original) {
    bool any = false;
    for (size_t i = 0; i < count; ++i) {
        uint32_t sym_idx = R_SYM(rels[i].r_info);
        if (!sym_idx) continue;
        const char* name = m.strtab + m.symtab[sym_idx].st_name;
        if (strcmp(name, symbol) != 0) continue;
        uintptr_t slot_addr = m.base + rels[i].r_offset;
        if (patch_slot(slot_addr, replacement, out_original)) any = true;
    }
    return any;
}

struct HookArgs {
    const char* module_substr;
    const char* symbol;
    void* replacement;
    void** out_original;
    int count;
};

int hook_one_module(dl_phdr_info* info, size_t, void* data) {
    auto* args = (HookArgs*)data;
    if (args->module_substr && (!info->dlpi_name || !strstr(info->dlpi_name, args->module_substr)))
        return 0;
    ModuleDynInfo m;
    if (!find_dynamic(info, m)) return 0;
    bool hit = false;
    if (m.jmprel) hit |= patch_relocs(m, m.jmprel, m.jmprel_count, args->symbol, args->replacement, args->out_original);
    if (m.rela)   hit |= patch_relocs(m, m.rela, m.rela_count, args->symbol, args->replacement, args->out_original);
    if (hit) {
        ++args->count;
        LOGT("elf_hook: patched %s in %s", args->symbol, info->dlpi_name ? info->dlpi_name : "(main)");
    }
    return 0;
}

}  // namespace

int elf_hook_symbol_in(const char* module_substr, const char* symbol, void* replacement, void** out_original) {
    HookArgs args{module_substr, symbol, replacement, out_original, 0};
    dl_iterate_phdr(hook_one_module, &args);
    return args.count;
}

int elf_hook_symbol(const char* symbol, void* replacement, void** out_original) {
    return elf_hook_symbol_in(nullptr, symbol, replacement, out_original);
}

}  // namespace shim
