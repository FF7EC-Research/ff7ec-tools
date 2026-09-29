#!/usr/bin/env python3
"""
patch_ssl.py - Disable TLS certificate verification for the FFBE/AndApp client
               so it can talk to a self-signed / renamed preservation server.

WHY THIS EXISTS (preservation context)
--------------------------------------
For preservation you redirect the game's own client (running on your machine) to
your own replacement server (see loader/andapp_loader.ini + dns_hook). That
server will not hold a certificate signed by DigiCert/GlobalSign for the
original hostname, so ordinary TLS validation fails. This makes the client
accept any certificate. It only affects the local client you own; it is not a
tool for intercepting anyone else's traffic.

WHERE VERIFICATION ACTUALLY LIVES
---------------------------------
FF_EXVIUS.exe does its HTTPS through libcurl.dll, which in turn uses OpenSSL
(libssl-1_1.dll / libcrypto-1_1.dll). The exe itself contains no certificate
logic, so the reliable place to neutralize verification is the OpenSSL/libcurl
DLLs that ship next to the game, not the exe. This script therefore patches
those DLLs' exported functions in place (with a .bak backup).

The two safest, best-known no-ops:
    X509_verify_cert       -> return 1   (chain "valid")
    SSL_get_verify_result  -> return 0   (X509_V_OK)
Optionally we also relax libcurl by making curl_easy_setopt ignore the
VERIFYPEER/VERIFYHOST toggles is NOT done here (that needs argument inspection);
the OpenSSL no-ops above are sufficient and self-contained.

If you prefer a NO-FILES-MODIFIED approach, use the runtime hook built into the
winmm loader (loader/ssl_hook.cpp) instead - it applies the exact same two
patches in memory after the DLLs load.

USAGE
-----
    python patch_ssl.py <game_dir>            # patch every OpenSSL/curl DLL found
    python patch_ssl.py <path-to-dll> ...     # patch specific files
    python patch_ssl.py --restore <game_dir>  # restore .bak backups

Cross-checks the architecture of each function it patches (x86 vs x64).
Requires: pefile   (pip install pefile)
"""
import glob
import os
import shutil
import struct
import sys

try:
    import pefile
except ImportError:
    sys.exit("pefile required: pip install pefile")

# Function -> return value we want to force.
TARGETS = {
    "X509_verify_cert": 1,        # 1 == success in OpenSSL
    "SSL_get_verify_result": 0,   # 0 == X509_V_OK
}

DLL_GLOBS = ["libssl*.dll", "libcrypto*.dll", "ssleay32.dll", "libeay32.dll"]


def _stub_bytes(is64, retval):
    """Bytes for `mov eax, retval; ret` (cdecl - caller cleans args)."""
    if is64:
        # 32-bit immediate into eax zero-extends into rax; ret
        return b"\xB8" + struct.pack("<I", retval & 0xFFFFFFFF) + b"\xC3"
    return b"\xB8" + struct.pack("<I", retval & 0xFFFFFFFF) + b"\xC3"


def _export_offset(pe, name):
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return None
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.decode(errors="replace") == name:
            try:
                return pe.get_offset_from_rva(exp.address)
            except Exception:  # noqa: BLE001
                return None
    return None


def patch_file(path):
    pe = pefile.PE(path)
    is64 = pe.FILE_HEADER.Machine == 0x8664
    found = {n: _export_offset(pe, n) for n in TARGETS}
    found = {n: o for n, o in found.items() if o is not None}
    pe.close()
    if not found:
        return False  # not one of our OpenSSL DLLs

    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
    data = bytearray(open(path, "rb").read())
    for name, off in found.items():
        stub = _stub_bytes(is64, TARGETS[name])
        data[off:off + len(stub)] = stub
        print("  patched %-24s @ file off 0x%06x -> return %d"
              % (name, off, TARGETS[name]))
    open(path, "wb").write(data)
    return True


def collect(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for pat in DLL_GLOBS:
                out += glob.glob(os.path.join(p, "**", pat), recursive=True)
        else:
            out.append(p)
    # de-dup, skip backups
    seen, res = set(), []
    for p in out:
        rp = os.path.abspath(p)
        if rp in seen or rp.endswith(".bak"):
            continue
        seen.add(rp)
        res.append(p)
    return res


def restore(paths):
    for p in paths:
        base = p
        if os.path.isdir(p):
            for bak in glob.glob(os.path.join(p, "**", "*.bak"), recursive=True):
                orig = bak[:-4]
                shutil.copy2(bak, orig)
                print("restored", orig)
            continue
        bak = base + ".bak"
        if os.path.exists(bak):
            shutil.copy2(bak, base)
            print("restored", base)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    if argv[1] == "--restore":
        restore(argv[2:] or ["."])
        return 0
    files = collect(argv[1:])
    if not files:
        print("No OpenSSL/libcurl DLLs found. Point me at the game directory,")
        print("or use the winmm runtime SSL hook (loader/ssl_hook.cpp) instead.")
        return 2
    patched = 0
    for f in files:
        print("checking", f)
        try:
            if patch_file(f):
                patched += 1
        except Exception as exc:  # noqa: BLE001
            print("  skip (%s)" % exc)
    print("\nPatched %d file(s). Backups saved as *.bak; --restore to revert."
          % patched)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
