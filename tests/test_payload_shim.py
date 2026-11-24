#!/usr/bin/env python3
"""Uji payload shim: decoy, tunnel (PATCH + magic), dan fallback nginx."""
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

DECOY = b"GET / HTTP/1.1\r\nHost: chat.sociomile.com\r\n\r\n"
UPGRADE = b"PATCH / HTTP/1.1\r\nHost: vpn.contoh.com\r\nUpgrade: websocket\r\n\r\n"
MAGIC = b"HTTP/ 69\r\n\r\n"
NGINX_BODY = b"<!DOCTYPE html><h3>Config by 1FTunnel</h3>"
NGINX_RESP = (b"HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nContent-Length: %d\r\n"
              b"Connection: keep-alive\r\nLocation: https://chat.sociomile.com/\r\n\r\n" % len(NGINX_BODY))
UPGRADE_RESP = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"


def serve(port, response, sink, echo):
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
            try:
                conn.settimeout(3)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                sink.append(data)
                conn.sendall(response)
                if echo:
                    body = conn.recv(64)
                    sink.append(body)
                    conn.sendall(body)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=worker, daemon=True).start()
    return srv


def read_some(sock, limit=4096):
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
    serve(UPSTREAM_PORT, UPGRADE_RESP, upstream_seen, echo=True)
    serve(NGINX_PORT, NGINX_RESP + NGINX_BODY, nginx_seen, echo=False)

    env = dict(os.environ)
    env["JNCT_SHIM_LISTEN"] = "127.0.0.1:%d" % SHIM_PORT
    env["JNCT_SHIM_NGINX"] = "127.0.0.1:%d" % NGINX_PORT
    env["JNCT_SHIM_DEFAULT"] = "/upvmess"
    env["JNCT_SHIM_ROUTES"] = "/upvmess=127.0.0.1:%d" % UPSTREAM_PORT
    proc = subprocess.Popen([sys.executable, SHIM], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(1.0)

    results = []
    try:
        # 1. decoy saja -> respons nginx (301) diteruskan, koneksi tetap hidup
        s = socket.create_connection(("127.0.0.1", SHIM_PORT), 5)
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n" + DECOY)
        resp = read_some(s)
        results.append(("decoy-301", b"301" in resp and NGINX_BODY in resp))
        results.append(("proxy-header", bool(nginx_seen) and nginx_seen[0].startswith(b"PROXY TCP4 1.2.3.4")))

        # 2. pola 1FTunnel: tunggu respons decoy, lalu kirim upgrade + magic
        s.sendall(UPGRADE)
        time.sleep(0.2)
        s.sendall(MAGIC + b"HELLO")
        resp2 = read_some(s)
        s.close()
        results.append(("tunnel-101", b"101" in resp2))
        body = upstream_seen[1] if len(upstream_seen) > 1 else b""
        results.append(("magic-strip", body.strip() == b"HELLO"))

        # 3. decoy + upgrade dikirim sekaligus
        s = socket.create_connection(("127.0.0.1", SHIM_PORT), 5)
        s.sendall(DECOY + UPGRADE)
        time.sleep(0.2)
        s.sendall(MAGIC + b"BULK")
        resp3 = read_some(s)
        s.close()
        results.append(("bulk-101", b"101" in resp3))

        # 4. proxy di depan membuang header Upgrade: PATCH tetap dianggap tunnel
        s = socket.create_connection(("127.0.0.1", SHIM_PORT), 5)
        s.sendall(b"PATCH / HTTP/1.1\r\nHost: vpn.contoh.com\r\n\r\n")
        resp4 = read_some(s)
        s.close()
        results.append(("patch-tanpa-upgrade", b"101" in resp4))
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
