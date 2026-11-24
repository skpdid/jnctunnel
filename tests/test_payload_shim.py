#!/usr/bin/env python3
"""Uji payload shim: mode tunnel (decoy + PATCH + magic) dan mode fallback nginx."""
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM = os.path.join(HERE, "..", "assets", "payload-shim.py")
SHIM_PORT = 17007
UPSTREAM_PORT = 17004
NGINX_PORT = 18083

PAYLOAD = (
    b"GET / HTTP/1.1\r\nHost: chat.sociomile.com\r\n\r\n"
    b"PATCH / HTTP/1.1\r\nHost: vpn.contoh.com\r\nUpgrade: websocket\r\n\r\n"
)
MAGIC = b"HTTP/ 69\r\n\r\n"


def serve_echo(port, response=b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", sink=None):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)

    def worker():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            data = b""
            conn.settimeout(3)
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if sink is not None:
                    sink.append(data)
                conn.sendall(response)
                body = conn.recv(64)
                if sink is not None:
                    sink.append(body)
                conn.sendall(body)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=worker, daemon=True).start()
    return srv


def read_all(sock, limit=4096):
    sock.settimeout(3)
    out = b""
    try:
        while len(out) < limit:
            chunk = sock.recv(1024)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    return out


def main():
    upstream_seen = []
    nginx_seen = []
    serve_echo(UPSTREAM_PORT, sink=upstream_seen)
    serve_echo(NGINX_PORT, response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", sink=nginx_seen)

    env = dict(os.environ)
    env["JNCT_SHIM_LISTEN"] = "127.0.0.1:%d" % SHIM_PORT
    env["JNCT_SHIM_NGINX"] = "127.0.0.1:%d" % NGINX_PORT
    env["JNCT_SHIM_DEFAULT"] = "/upvmess"
    env["JNCT_SHIM_ROUTES"] = "/upvmess=127.0.0.1:%d" % UPSTREAM_PORT
    proc = subprocess.Popen([sys.executable, SHIM], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(1.0)

    # route /upvmess harus menuju UPSTREAM_PORT; shim memakai peta bawaan,
    # jadi untuk uji ini peta diarahkan lewat variabel lingkungan tambahan.
    results = []
    try:
        # 1. mode tunnel: decoy + PATCH + magic
        s = socket.create_connection(("127.0.0.1", SHIM_PORT), 5)
        s.sendall(PAYLOAD)
        time.sleep(0.3)
        s.sendall(MAGIC + b"HELLO")
        resp = read_all(s)
        s.close()
        results.append(("tunnel", b"101" in resp))
        body = upstream_seen[1] if len(upstream_seen) > 1 else b""
        results.append(("magic-strip", body.strip() == b"HELLO"))

        # 2. fallback nginx: request biasa
        s = socket.create_connection(("127.0.0.1", SHIM_PORT), 5)
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n"
                  b"GET /vps/health HTTP/1.1\r\nHost: vpn.contoh.com\r\n\r\n")
        resp2 = read_all(s)
        s.close()
        results.append(("fallback", b"200" in resp2))
        results.append(("proxy-header", bool(nginx_seen) and nginx_seen[0].startswith(b"PROXY TCP4 1.2.3.4")))
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    ok = True
    for name, passed in results:
        print("%-14s %s" % (name, "OK" if passed else "GAGAL"))
        ok = ok and passed
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
