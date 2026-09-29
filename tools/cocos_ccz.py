#!/usr/bin/env python3
"""
cocos_ccz.py - Decrypt / inspect cocos2d-x "CCZp" (encrypted CCZ) assets.

Recovered from FF_EXVIUS.exe (FFBE JP / AndApp build 10.0.0):
    The game sets the cocos2d-x XXTEA encryption key via four calls to
    ZipUtils::setPvrEncryptionKeyPart(index, value) at RVA ~0x750d2c:

        setPvrEncryptionKeyPart(0, 0x10872fa8)
        setPvrEncryptionKeyPart(1, 0x12eb74c3)
        setPvrEncryptionKeyPart(2, 0x4ada7aa3)
        setPvrEncryptionKeyPart(3, 0xf4783fd9)

    This same routine then decrypts "VersionAndApp.xml", confirming the key.

CCZp container layout (16-byte big-endian header):
    off 0  : sig            "CCZp"           (4 bytes)
    off 4  : compression    uint16 BE        (0 = zlib)
    off 6  : version        uint16 BE
    off 8  : reserved       uint32 BE
    off 12 : len            uint32 BE        (uncompressed size; ENCRYPTED)
    off 16 : zlib stream    ...              (ENCRYPTED)

Decryption:
    A 1024-word keystream is expanded in place (starting from all-zeros) using
    an XXTEA schedule driven by the four key parts, then the payload words from
    offset 12 onward are XORed word-for-word with keystream[i] (aligned).
    After decrypt, header.len is valid and the zlib stream begins at offset 16.

This is for interoperability / preservation of assets from a game you own.

Usage:
    python cocos_ccz.py decrypt  <in.ccz|in.xml> [out]
    python cocos_ccz.py encrypt  <in.raw>        [out]     # re-pack (round-trip)
    python cocos_ccz.py info     <file>
    python cocos_ccz.py keystream                          # dump first words
"""
import struct
import sys
import zlib

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
ENC_LEN = 1024  # keystream length in 32-bit words

# --- XXTEA key parts recovered from FF_EXVIUS.exe -------------------------------
KEY_PARTS = (0x10872FA8, 0x12EB74C3, 0x4ADA7AA3, 0xF4783FD9)


def build_keystream(parts=KEY_PARTS):
    """Reproduce cocos2d-x ZipUtils keystream expansion (6 rounds, in-place)."""
    key = [0] * ENC_LEN
    z = key[ENC_LEN - 1]
    total = 0
    for _ in range(6):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(ENC_LEN - 1):
            y = key[p + 1]
            mx = ((((z >> 5) ^ ((y << 2) & MASK)) + ((y >> 3) ^ ((z << 4) & MASK))) & MASK) \
                ^ (((total ^ y) + (parts[(p & 3) ^ e] ^ z)) & MASK)
            key[p] = (key[p] + mx) & MASK
            z = key[p]
        p = ENC_LEN - 1
        y = key[0]
        mx = ((((z >> 5) ^ ((y << 2) & MASK)) + ((y >> 3) ^ ((z << 4) & MASK))) & MASK) \
            ^ (((total ^ y) + (parts[(p & 3) ^ e] ^ z)) & MASK)
        key[ENC_LEN - 1] = (key[ENC_LEN - 1] + mx) & MASK
        z = key[ENC_LEN - 1]
    return key


def _xor_payload(header_and_payload, key):
    """XOR words from offset 12 onward with keystream[i] (aligned). Returns bytes."""
    region = bytearray(header_and_payload[12:])
    n = len(region) // 4
    words = list(struct.unpack("<%dI" % n, bytes(region[: n * 4])))
    for i in range(n):
        words[i] ^= key[i]
    out = bytearray(header_and_payload[:12])
    out += struct.pack("<%dI" % n, *words)
    out += region[n * 4:]  # trailing bytes (not a full word) are left untouched
    return bytes(out)


def is_cczp(data):
    return len(data) >= 16 and data[:4] == b"CCZp"


def decrypt(data):
    if not is_cczp(data):
        raise ValueError("not a CCZp container (bad signature)")
    key = build_keystream()
    dec = _xor_payload(data, key)
    length = struct.unpack(">I", dec[12:16])[0]
    raw = zlib.decompress(dec[16:])
    if len(raw) != length:
        sys.stderr.write(
            "warning: header len %d != inflated %d\n" % (length, len(raw)))
    return raw


def encrypt(raw):
    """Re-pack raw bytes into a CCZp container (round-trippable by the game)."""
    comp = zlib.compress(raw, 9)
    header = bytearray(b"CCZp")
    header += struct.pack(">H", 0)          # compression = zlib
    header += struct.pack(">H", 0)          # version
    header += struct.pack(">I", 0)          # reserved
    header += struct.pack(">I", len(raw))   # uncompressed length
    plain = bytes(header) + comp
    key = build_keystream()
    return _xor_payload(plain, key)


def info(data):
    print("size          :", len(data))
    print("signature     :", data[:4])
    if is_cczp(data):
        comp = struct.unpack(">H", data[4:6])[0]
        ver = struct.unpack(">H", data[6:8])[0]
        print("compression   :", comp, "(0=zlib)")
        print("version       :", ver)
        try:
            raw = decrypt(data)
            print("uncompressed  :", len(raw), "bytes")
            head = raw[:200].decode("utf-8", "replace")
            print("preview       :\n" + head)
        except Exception as exc:  # noqa: BLE001
            print("decrypt failed:", exc)
    elif data[:4] == b"CCZ!":
        print("(unencrypted CCZ - use standard cocos tooling)")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "keystream":
        ks = build_keystream()
        print("parts     :", ", ".join("0x%08x" % p for p in KEY_PARTS))
        print("keystream :", ", ".join("0x%08x" % w for w in ks[:8]), "...")
        return 0
    if cmd not in ("decrypt", "encrypt", "info") or len(argv) < 3:
        print(__doc__)
        return 1
    src = argv[2]
    data = open(src, "rb").read()
    if cmd == "info":
        info(data)
        return 0
    if cmd == "decrypt":
        out = argv[3] if len(argv) > 3 else src + ".dec"
        open(out, "wb").write(decrypt(data))
    else:
        out = argv[3] if len(argv) > 3 else src + ".ccz"
        open(out, "wb").write(encrypt(data))
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
