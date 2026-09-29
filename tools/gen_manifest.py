#!/usr/bin/env python3
"""
gen_manifest.py - Regenerate an AndApp-style manifest.json for a game directory.

WHAT manifest.json IS
---------------------
It is AndApp's file inventory + integrity manifest. Top-level fields:
    release, clientId, versionCode, versionName, platform, architecture,
    entryPointBaseName, signature[]
`signature[]` is one entry per shipped file: {path, signature}, where each
`signature` is a 64-byte value (base64) - an ECDSA-P256 (r||s) or Ed25519
digital signature over that file, produced with DeNA's PRIVATE key. There is
also a sibling `signature` file next to manifest.json: a 64-byte signature over
manifest.json itself.

WHO CHECKS IT
-------------
Only the AndApp launcher / BootHelper (install + launch integrity). The game
executable does NOT: FF_EXVIUS.exe imports only symmetric crypto (AES/MD5) from
libcrypto and has no signature-verification imports. It reads manifest.json
solely to parse version fields for the SDK. So when the game is launched
directly (our winmm loader replacing AndApp), NOTHING verifies these signatures
and modified files run fine - no in-game bypass is required.

Because the per-file/manifest signatures are asymmetric, they CANNOT be
regenerated to satisfy AndApp without DeNA's private key. This script therefore
rebuilds the manifest's STRUCTURE for our own tooling (correct file list +
version fields), and for the `signature` field offers:
    --sig sha512   (default) base64(SHA-512(file)) - a real integrity hash our
                   own tools can verify; NOT valid for AndApp.
    --sig preserve reuse the original signature string from --template for files
                   that still exist (drops entries for missing files, adds
                   sha512 for new ones).
    --sig empty    empty strings.

USAGE
-----
    python gen_manifest.py <game_dir> [-o manifest.json]
        [--template old_manifest.json] [--sig sha512|preserve|empty]
        [--version-name 11.0.0] [--version-code 124]
        [--client-id 5701868182306816] [--entry FF_EXVIUS.exe]

If --template is given, version/clientId/entry fields default to its values.
File set: the entry exe, every *.dll in the game root, and bin/*.exe - matching
how the shipped manifest is organized. Paths use forward slashes.
"""
import argparse
import base64
import hashlib
import json
import os
import sys


def sha512_b64(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return base64.b64encode(h.digest()).decode()


def collect_files(game_dir, entry):
    """Return manifest-relative paths, ordered like the shipped manifest."""
    rels = []
    # bin/*.exe first (matches original ordering: crashpad_* under bin/)
    bindir = os.path.join(game_dir, "bin")
    if os.path.isdir(bindir):
        for name in sorted(os.listdir(bindir)):
            if name.lower().endswith(".exe"):
                rels.append("bin/" + name)
    # entry exe, then all root DLLs (alphabetical), de-duplicated
    root = []
    if os.path.isfile(os.path.join(game_dir, entry)):
        root.append(entry)
    for name in sorted(os.listdir(game_dir)):
        if name.lower().endswith(".dll") and name not in root:
            root.append(name)
    # Original manifest lists chrome_elf/d3d/exe/dlls intermixed alphabetically
    # with the entry exe among them; emit entry + dlls sorted together.
    merged = sorted(set(root), key=str.lower)
    return rels + merged


def main(argv):
    ap = argparse.ArgumentParser(description="Regenerate AndApp manifest.json")
    ap.add_argument("game_dir")
    ap.add_argument("-o", "--out", default="manifest.json")
    ap.add_argument("--template", help="existing manifest.json to inherit fields/sigs")
    ap.add_argument("--sig", choices=["sha512", "preserve", "empty"], default="sha512")
    ap.add_argument("--version-name")
    ap.add_argument("--version-code", type=int)
    ap.add_argument("--client-id")
    ap.add_argument("--entry")
    ap.add_argument("--platform", default="win32")
    ap.add_argument("--architecture", default="x86")
    args = ap.parse_args(argv[1:])

    tmpl = {}
    tmpl_sigs = {}
    if args.template:
        tmpl = json.load(open(args.template, encoding="utf-8"))
        tmpl_sigs = {e["path"]: e["signature"] for e in tmpl.get("signature", [])}

    entry = args.entry or tmpl.get("entryPointBaseName", "FF_EXVIUS.exe")
    files = collect_files(args.game_dir, entry)

    sig_entries = []
    for rel in files:
        full = os.path.join(args.game_dir, rel.replace("/", os.sep))
        if not os.path.isfile(full):
            continue
        if args.sig == "preserve" and rel in tmpl_sigs:
            sig = tmpl_sigs[rel]
        elif args.sig == "empty":
            sig = ""
        else:
            sig = sha512_b64(full)
        sig_entries.append({"path": rel, "signature": sig})

    out = {
        "release": tmpl.get("release", True),
        "clientId": args.client_id or tmpl.get("clientId", ""),
        "versionCode": args.version_code if args.version_code is not None
                       else tmpl.get("versionCode", 0),
        "versionName": args.version_name or tmpl.get("versionName", "0.0.0"),
        "platform": args.platform or tmpl.get("platform", "win32"),
        "architecture": args.architecture or tmpl.get("architecture", "x86"),
        "entryPointBaseName": entry,
        "signature": sig_entries,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"), ensure_ascii=False)
    kind = {"sha512": "SHA-512 integrity hashes (not AndApp-valid)",
            "preserve": "original signatures preserved where unchanged",
            "empty": "empty signatures"}[args.sig]
    print("wrote %s: %d files, %s" % (args.out, len(sig_entries), kind))
    if args.sig != "preserve":
        print("note: signatures here are NOT valid AndApp signatures (no private "
              "key). Fine for direct launch - the game does not verify them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
