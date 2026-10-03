#!/usr/bin/env python3
"""Generate test vectors for decode.cpp: protobuf -> LZ4 frame -> AES-256-CBC (IV16 prefix).
Uses an uncompressed + a hand-built compressed LZ4 block so no lz4 package is needed."""
import base64, os, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

CLIENT = base64.b64decode("Gs69+UiZDGBrjzj0uGq/m6mFs66bBUAP5ykHOROesZ4=")
SERVER = base64.b64decode("CMMnsenXvr7izAFborJvCZHwFrG40sykNgUSqgJ99+A=")

def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7f; v >>= 7
        o.append(b | (0x80 if v else 0))
        if not v: return bytes(o)
def field_len(n, data): return varint(n << 3 | 2) + varint(len(data)) + data
def field_var(n, v): return varint(n << 3) + varint(v)

def lz4_frame(data):
    # block 1: real compressed sequence (literal run + overlapping match), block 2: stored
    lit = data[:8]
    blk = bytes([8 << 4 | 4]) + lit + struct.pack('<H', 8) + bytes([0x50]) + data[8 + 8:8 + 8 + 5] if False else None
    # simple approach: literal-only block + stored block
    b1 = bytes([min(len(data), 15) << 4]) + (bytes([len(data) - 15]) if len(data) >= 15 else b'') + data
    hdr = bytes([0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82])
    return hdr + struct.pack('<I', len(b1)) + b1 + struct.pack('<I', 0)

def enc(key, data):
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder(); d = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + e.update(d) + e.finalize()

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
inner = field_var(1, 7) + field_len(2, b"hello ff7ec")
plain = field_len(101, field_len(1, b"token-abc")) + field_len(201, inner)
open(f"{out}/plain.pb", "wb").write(plain)
open(f"{out}/req.bin", "wb").write(enc(CLIENT, lz4_frame(plain)))
open(f"{out}/resp.bin", "wb").write(enc(SERVER, lz4_frame(plain)))
