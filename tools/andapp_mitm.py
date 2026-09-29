#!/usr/bin/env python3
"""
andapp_mitm.py - Decrypting man-in-the-middle for the AndApp SDK <-> helper IPC.

A passive tee (ipc_capture.py) cannot read the traffic: the AES session key is
RSA-sealed to the *game's* public key, whose private half never leaves the game.
This tool instead terminates both sides. Neither the SDK nor the helper
authenticates its peer, so the proxy can:

  * toward the game  : act as the helper - accept the game's RSA public key and
                       return its OWN minted AES key K1  -> decrypts requests
  * toward the helper: act as a client   - present its OWN RSA key, receive the
                       helper's minted AES key K2        -> decrypts responses

and relay by decrypting with one key, logging plaintext, re-encrypting with the
other. Run it in front of the REAL helper and launch a game that still works
(e.g. FFRK) to capture the authoritative plaintext request/response sequence for
the shared SDK commands (initialize, get_id_token, ...), which the replacement
helper must reproduce.

Wire protocol (see docs/REVERSE_ENGINEERING.md §5):
  frame = [4-byte BE opcode][4-byte BE length][payload]
  op 1 C->S client CryptoAPI PUBLICKEYBLOB (RSA-1024 public key)
  op 2 S->C CryptoAPI SIMPLEBLOB (AES-256 key, RSA-encrypted to that key)
  op 3 C->S plaintext {"clientid":"..."}
  op 4 S->C 0x00 ack
  op 0x10 both ways: AES-256-CBC (IV=0, PKCS7) JSON

Usage:
  python andapp_mitm.py --cfg "%APPDATA%\\AndApp\\AndAppHelper.cfg" --out mitm.log
  python andapp_mitm.py --selftest      # validate blob parsing (no network)

Requires: pycryptodome  (pip install pycryptodome).  Start the real AndApp first,
run this, then launch the game. Ctrl-C restores the cfg.
"""
import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

CALG_RSA_KEYX = 0x0000A400
CALG_AES_256 = 0x00006610
OP_PUBKEY, OP_AESKEY, OP_HELLO, OP_ACK, OP_DATA = 1, 2, 3, 4, 0x10

_lock = threading.Lock()
_out = None


def log(s):
    with _lock:
        _out.write(s + "\n"); _out.flush()


# ---- CryptoAPI blob helpers --------------------------------------------------
def parse_publickeyblob(blob):
    """CryptoAPI PUBLICKEYBLOB -> pycryptodome RSA public key."""
    if blob[0] != 0x06 or blob[8:12] != b"RSA1":
        raise ValueError("not a PUBLICKEYBLOB")
    bitlen = struct.unpack_from("<I", blob, 12)[0]
    pubexp = struct.unpack_from("<I", blob, 16)[0]
    modlen = bitlen // 8
    modulus = int.from_bytes(blob[20:20 + modlen], "little")  # CryptoAPI is LE
    return RSA.construct((modulus, pubexp)), bitlen


def make_publickeyblob(pubkey):
    """pycryptodome RSA public key -> CryptoAPI PUBLICKEYBLOB."""
    bitlen = (pubkey.n.bit_length() + 7) // 8 * 8
    out = bytes([0x06, 0x02, 0x00, 0x00]) + struct.pack("<I", CALG_RSA_KEYX)
    out += b"RSA1" + struct.pack("<I", bitlen) + struct.pack("<I", pubkey.e)
    out += pubkey.n.to_bytes(bitlen // 8, "little")
    return out


def make_simpleblob(aes_key, client_pub):
    """AES key encrypted to client_pub as a CryptoAPI SIMPLEBLOB."""
    ct = PKCS1_v1_5.new(client_pub).encrypt(aes_key)      # modlen bytes
    out = bytes([0x01, 0x02, 0x00, 0x00]) + struct.pack("<I", CALG_AES_256)
    out += struct.pack("<I", CALG_RSA_KEYX)
    out += ct[::-1]                                       # CryptoAPI LE
    return out


def parse_simpleblob(blob, priv):
    """CryptoAPI SIMPLEBLOB -> AES key (decrypt with our private key)."""
    if blob[0] != 0x01:
        raise ValueError("not a SIMPLEBLOB")
    ct = blob[12:][::-1]
    key = PKCS1_v1_5.new(priv).decrypt(ct, None)
    if not key:
        raise ValueError("SIMPLEBLOB RSA decrypt failed")
    return key


def aes_dec(key, ct):
    pt = AES.new(key, AES.MODE_CBC, iv=b"\0" * 16).decrypt(ct)
    return pt[:-pt[-1]] if pt else pt        # strip PKCS7


def aes_enc(key, pt):
    padlen = 16 - (len(pt) % 16)
    pt = pt + bytes([padlen]) * padlen
    return AES.new(key, AES.MODE_CBC, iv=b"\0" * 16).encrypt(pt)


# ---- frame IO ----------------------------------------------------------------
def recv_all(s, n):
    buf = b""
    while len(buf) < n:
        r = s.recv(n - len(buf))
        if not r:
            return None
        buf += r
    return buf


def read_frame(s):
    h = recv_all(s, 8)
    if not h:
        return None, None
    op, ln = struct.unpack(">II", h)
    return op, (recv_all(s, ln) or b"") if ln else b""


def send_frame(s, op, payload):
    s.sendall(struct.pack(">II", op, len(payload)) + payload)


# ---- MITM per connection -----------------------------------------------------
def mitm(client, real_host, real_port, tag):
    try:
        # --- toward the game: we are the helper ---
        op, blob = read_frame(client)
        if op != OP_PUBKEY:
            log("[%s] unexpected first op %s" % (tag, op)); client.close(); return
        game_pub, bits = parse_publickeyblob(blob)
        k1 = os.urandom(32)
        send_frame(client, OP_AESKEY, make_simpleblob(k1, game_pub))
        op, hello = read_frame(client)              # op 3 clientid (plaintext)
        log("[%s] client hello: %s" % (tag, hello.decode("utf-8", "replace")))
        send_frame(client, OP_ACK, b"\x00")

        # --- toward the real helper: we are a client ---
        up = socket.create_connection((real_host, real_port))
        priv = RSA.generate(bits)
        send_frame(up, OP_PUBKEY, make_publickeyblob(priv.publickey()))
        op, sb = read_frame(up)
        k2 = parse_simpleblob(sb, priv)
        send_frame(up, OP_HELLO, hello)             # forward the same clientid
        read_frame(up)                              # op 4 ack
        log("[%s] session established (both sides)" % tag)

        def pump(src, dst, kd, ke, direction):
            while True:
                op, payload = read_frame(src)
                if op is None:
                    break
                if op == OP_DATA:
                    try:
                        pt = aes_dec(kd, payload)
                        log("[%s] %s %s" % (tag, direction,
                                            pt.decode("utf-8", "replace")))
                        send_frame(dst, OP_DATA, aes_enc(ke, pt))
                    except Exception as ex:                       # noqa: BLE001
                        log("[%s] %s decrypt/relay error: %s" % (tag, direction, ex))
                        break
                else:
                    log("[%s] %s passthrough op=%s len=%d"
                        % (tag, direction, op, len(payload)))
                    send_frame(dst, op, payload)
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass

        t1 = threading.Thread(target=pump, args=(client, up, k1, k2, "C->S"),
                              daemon=True)
        t2 = threading.Thread(target=pump, args=(up, client, k2, k1, "S->C"),
                              daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        client.close(); up.close()
        log("[%s] connection closed" % tag)
    except Exception as ex:                                        # noqa: BLE001
        log("[%s] error: %s" % (tag, ex))
        try: client.close()
        except OSError: pass


def serve(listen_port, real_host, real_port, tag):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port)); srv.listen(8)
    log("listening 127.0.0.1:%d (%s) -> 127.0.0.1:%d" % (listen_port, tag, real_port))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=mitm, args=(c, real_host, real_port, tag),
                         daemon=True).start()


def selftest():
    # Our PUBLICKEYBLOB header must match the real client's op-1 prefix (the
    # 20-byte header seen in the capture): 06 02 00 00 | CALG_RSA_KEYX | "RSA1"
    # | bitlen=1024 | pubexp=65537.
    captured_prefix = bytes.fromhex(
        "06020000" "00a40000" "52534131" "00040000" "01000100")
    priv = RSA.generate(1024)
    blob = make_publickeyblob(priv.publickey())
    assert blob[:20] == captured_prefix, blob[:20].hex()
    pub2, bits2 = parse_publickeyblob(blob)
    assert bits2 == 1024 and pub2.e == 65537 and pub2.n == priv.n
    # SIMPLEBLOB: header must match the captured op-2 prefix
    # (01 02 00 00 | CALG_AES_256 | CALG_RSA_KEYX), and round-trip the key.
    key = os.urandom(32)
    sb = make_simpleblob(key, priv.publickey())
    assert sb[:12] == bytes.fromhex("01020000" "10660000" "00a40000"), sb[:12].hex()
    assert parse_simpleblob(sb, priv) == key
    # AES-256-CBC (IV=0, PKCS7) round-trip.
    msg = b'{"initialize":{"x":1}}'
    assert aes_dec(key, aes_enc(key, msg)) == msg
    print("selftest OK: PUBLICKEYBLOB + SIMPLEBLOB headers match the capture; "
          "RSA/AES round-trips pass")


def main(argv):
    global _out
    ap = argparse.ArgumentParser(description="Decrypting AndApp IPC MITM")
    ap.add_argument("--cfg")
    ap.add_argument("--out", default="mitm.log")
    ap.add_argument("--delta", type=int, default=1000)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv[1:])
    if args.selftest:
        selftest(); return 0
    if not args.cfg:
        ap.print_help(); return 1

    _out = open(args.out, "w", encoding="utf-8")
    log("# andapp_mitm %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    cfg_path = os.path.expandvars(args.cfg)
    original = json.load(open(cfg_path, encoding="utf-8"))
    ck = "standard.tcp.command.ipv4.port"; nk = "standard.tcp.notification.ipv4.port"
    rc, rn = int(original[ck]), int(original[nk])
    lc, ln = rc + args.delta, rn + args.delta
    threading.Thread(target=serve, args=(lc, "127.0.0.1", rc, "cmd"), daemon=True).start()
    threading.Thread(target=serve, args=(ln, "127.0.0.1", rn, "ntf"), daemon=True).start()
    time.sleep(0.3)
    rewritten = dict(original); rewritten[ck] = lc; rewritten[nk] = ln
    rewritten.pop("standard.command.pipe.name", None)
    json.dump(rewritten, open(cfg_path, "w", encoding="utf-8"),
              separators=(",", ":"), ensure_ascii=False)
    log("# cfg -> proxy cmd=%d ntf=%d (real %d/%d)" % (lc, ln, rc, rn))
    print("MITM up. Launch the game. Ctrl-C to stop and restore the cfg.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        json.dump(original, open(cfg_path, "w", encoding="utf-8"),
                  separators=(",", ":"), ensure_ascii=False)
        print("\ncfg restored. Plaintext capture in", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
