#!/usr/bin/env python3
"""
ipc_capture.py - Capture the FFBE SDK <-> AndAppHelper handshake/traffic.

The SDK connects to 127.0.0.1 on the ports listed in
    %LOCALAPPDATA%\\AndApp\\AndAppHelper.cfg
      standard.tcp.command.ipv4.port      = <cmd>
      standard.tcp.notification.ipv4.port = <ntf>
This tool sits in the middle: it listens on NEW loopback ports, rewrites the cfg
so the SDK connects to it, forwards every byte to the REAL helper's original
ports, and writes an annotated hex dump of both directions. That gives you the
exact wire bytes of the encrypted handshake to reconstruct SessionCrypto.

TWO MODES
---------
1) Auto (recommended) - discover real ports from the cfg, proxy in front of it:

     python ipc_capture.py --cfg "%LOCALAPPDATA%\\AndApp\\AndAppHelper.cfg" \
                           --out handshake.log

   Order of operations on Windows:
     a. Start the real AndApp client so its helper starts and writes the cfg.
     b. Run this tool (it reads the real ports, starts proxies on real+1000,
        and rewrites the cfg to the proxy ports). Leave it running.
     c. Launch FF_EXVIUS.exe (directly is fine - the handshake happens before any
        payload/session rejection, so you still capture it; launch via AndApp to
        also capture a fully successful initialize).
     d. Watch handshake.log fill. Ctrl-C restores the original cfg.

2) Manual - you already know the real port and pick a listen port:

     python ipc_capture.py --listen 52100 --target 51100 --tag cmd --out h.log
     python ipc_capture.py --listen 52101 --target 51101 --tag ntf --out h.log
   (then point AndAppHelper.cfg at 52100/52101 yourself)

Stdlib only. Works on Windows/macOS/Linux.
"""
import argparse
import os
import socket
import sys
import threading
import time

_lock = threading.Lock()
_out = None


def log(line):
    with _lock:
        _out.write(line + "\n")
        _out.flush()


def hexdump(data, prefix="    "):
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%s%04x  %-47s  %s" % (prefix, i, hexs, asci))
    return "\n".join(out)


def pump(src, dst, tag, direction):
    """Copy src->dst, logging each chunk."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            ts = time.strftime("%H:%M:%S")
            log("\n[%s] %s %s  (%d bytes)" % (ts, tag, direction, len(data)))
            log(hexdump(data))
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client, target_host, target_port, tag):
    try:
        upstream = socket.create_connection((target_host, target_port))
    except OSError as e:
        log("!! %s could not reach real helper %s:%d (%s)"
            % (tag, target_host, target_port, e))
        client.close()
        return
    log("== %s connection opened -> %s:%d ==" % (tag, target_host, target_port))
    t1 = threading.Thread(target=pump, args=(client, upstream, tag, "C->S"),
                          daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, tag, "S->C"),
                          daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()
    client.close(); upstream.close()
    log("== %s connection closed ==" % tag)


def serve(listen_port, target_host, target_port, tag):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(8)
    log("listening 127.0.0.1:%d  (%s) -> 127.0.0.1:%d"
        % (listen_port, tag, target_port))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle_client,
                         args=(c, target_host, target_port, tag),
                         daemon=True).start()


def parse_cfg(path):
    ports = {}
    for line in open(path, "r", encoding="utf-8", errors="replace"):
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            ports[k.strip()] = v.strip()
    return ports


def write_cfg(path, ports):
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        for k, v in ports.items():
            f.write("%s=%s\n" % (k, v))


def main(argv):
    global _out
    ap = argparse.ArgumentParser(description="FFBE SDK<->AndAppHelper capture proxy")
    ap.add_argument("--out", default="handshake.log")
    ap.add_argument("--cfg", help="AndAppHelper.cfg to read/rewrite (auto mode)")
    ap.add_argument("--delta", type=int, default=1000,
                    help="listen_port = real_port + delta (auto mode)")
    ap.add_argument("--listen", type=int, help="manual: local listen port")
    ap.add_argument("--target", type=int, help="manual: real helper port")
    ap.add_argument("--tag", default="cmd", help="manual: label for the log")
    args = ap.parse_args(argv[1:])

    _out = open(args.out, "w", encoding="utf-8")
    log("# ipc_capture started %s" % time.strftime("%Y-%m-%d %H:%M:%S"))

    if args.cfg:
        cfg_path = os.path.expandvars(args.cfg)
        original = parse_cfg(cfg_path)
        log("# original cfg: %s" % original)
        cmd_key = "standard.tcp.command.ipv4.port"
        ntf_key = "standard.tcp.notification.ipv4.port"
        real_cmd = int(original[cmd_key]); real_ntf = int(original[ntf_key])
        new_cmd = real_cmd + args.delta; new_ntf = real_ntf + args.delta
        threading.Thread(target=serve,
                         args=(new_cmd, "127.0.0.1", real_cmd, "cmd"),
                         daemon=True).start()
        threading.Thread(target=serve,
                         args=(new_ntf, "127.0.0.1", real_ntf, "ntf"),
                         daemon=True).start()
        time.sleep(0.3)
        rewritten = dict(original)
        rewritten[cmd_key] = str(new_cmd)
        rewritten[ntf_key] = str(new_ntf)
        for k in ("standard.tcp.command.ipv6.port",
                  "standard.tcp.notification.ipv6.port"):
            if k in rewritten:
                rewritten[k] = str(int(original[k]) + args.delta)
        write_cfg(cfg_path, rewritten)
        log("# cfg rewritten to proxy ports cmd=%d ntf=%d" % (new_cmd, new_ntf))
        print("Proxy up. cfg points the SDK at %d/%d -> real %d/%d."
              % (new_cmd, new_ntf, real_cmd, real_ntf))
        print("Launch the game now. Ctrl-C to stop and restore the cfg.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            write_cfg(cfg_path, original)
            log("# cfg restored")
            print("\ncfg restored. Capture in", args.out)
        return 0

    if args.listen and args.target:
        print("Proxying 127.0.0.1:%d -> :%d (%s). Ctrl-C to stop."
              % (args.listen, args.target, args.tag))
        try:
            serve(args.listen, "127.0.0.1", args.target, args.tag)
        except KeyboardInterrupt:
            pass
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
