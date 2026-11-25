#!/usr/bin/env python3
"""payload-shim - inti dukungan "HTTP upgrade + payload" untuk autoscript tunnel.

Tanpa dependensi (Python 3 stdlib). Taruh di depan Xray, bukan di belakang nginx,
karena nginx mem-parse HTTP dan tidak bisa melewati request umpan (decoy).

Alur yang ditangani:

    GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]        <- umpan, dijawab 301/404
    PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]
    [split] HTTP/ 69[crlf][crlf]                              <- penanda, dibuang

Shim akan:
  1. membaca request satu per satu (umpan diteruskan ke nginx / dijawab sendiri),
  2. menemukan request ber-Upgrade (atau method PATCH/PUT) -> mode tunnel,
  3. mengirim ulang sebagai `GET <path>` bersih ke inbound Xray,
  4. meneruskan 101 apa adanya, lalu membuang satu penanda magic di awal stream.

Contoh pemakaian:

    python3 payload-shim.py \
        --listen 127.0.0.1:10007 \
        --route /upvmess=127.0.0.1:10004 \
        --route /upvless=127.0.0.1:10005 \
        --route /uptrojan=127.0.0.1:10006 \
        --default /upvmess \
        --fallback 127.0.0.1:8083 \
        --proxy-protocol

  --route      path -> alamat inbound Xray (boleh berkali-kali)
  --default    path yang dipakai kalau payload memakai path lain (mis. "PATCH /")
  --fallback   alamat nginx untuk request non-tunnel (API, ACME, 301)
  --proxy-protocol  terima header PROXY v1 dari haproxy dan teruskan ke fallback
  --magic      penanda yang dibuang setelah 101 (default "HTTP/ 69\\r\\n\\r\\n")
"""
import argparse
import socket
import sys
import threading
import time

HEADER_LIMIT = 64 * 1024
TIMEOUT = 8.0
MAX_CONN = 2048
TUNNEL_METHODS = {"GET", "POST", "PATCH", "PUT", "HEAD", "OPTIONS"}
FORCE_METHODS = {"PATCH", "PUT"}


def read_proxy_header(sock):
    try:
        peek = sock.recv(6, socket.MSG_PEEK)
    except OSError:
        return None
    if not peek.startswith(b"PROXY "):
        return None
    line = b""
    while b"\r\n" not in line and len(line) < 108:
        try:
            chunk = sock.recv(1)
        except OSError:
            return None
        if not chunk:
            return None
        line += chunk
    parts = line.strip().split()
    if len(parts) >= 6 and parts[0] == b"PROXY":
        return parts[2].decode(), parts[3].decode(), parts[4].decode(), parts[5].decode()
    return None


def proxy_header(src):
    if not src:
        return b"PROXY UNKNOWN\r\n"
    return ("PROXY TCP4 %s %s %s %s\r\n" % src).encode()


def parse_block(head):
    lines = head.split(b"\r\n")
    if not lines:
        return None
    try:
        method, target, _ver = lines[0].decode("latin-1").split(" ", 2)
    except (UnicodeDecodeError, ValueError):
        return None
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers.setdefault(name.strip().lower(), []).append(value.strip())
    return {"method": method.upper(), "path": target.split("?", 1)[0], "headers": headers}


def hget(req, name):
    return ", ".join(req["headers"].get(name, []))


def is_upgrade(req):
    if req["method"] not in TUNNEL_METHODS:
        return False
    if "upgrade" in hget(req, "connection").lower() or hget(req, "upgrade").lower() == "websocket":
        return True
    # PATCH/PUT adalah penanda payload umum. Tetap dianggap tunnel supaya
    # proxy di depan yang membuang header Upgrade tidak mematikan koneksi.
    return req["method"] in FORCE_METHODS and not hget(req, "content-length")


def build_upstream_request(req, path):
    host = hget(req, "host") or "localhost"
    lines = ["GET %s HTTP/1.1" % path, "Host: %s" % host,
             "Connection: Upgrade", "Upgrade: websocket"]
    for name in ("sec-websocket-key", "sec-websocket-version", "user-agent",
                 "accept-language", "x-forwarded-for", "x-real-ip"):
        value = hget(req, name)
        if value:
            lines.append("%s: %s" % ("-".join(p.capitalize() for p in name.split("-")), value))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def pump(src, dst, magic=None):
    try:
        if magic:
            prefix = b""
            matched = True
            for expected in magic:
                try:
                    chunk = src.recv(1)
                except OSError:
                    chunk = b""
                if not chunk:
                    matched = False
                    break
                prefix += chunk
                if chunk[0] != expected:
                    matched = False
                    break
            if not matched and prefix:
                dst.sendall(prefix)
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def read_head(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > HEADER_LIMIT:
            return None, b""
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None, b""
        if not chunk:
            return None, b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def read_response(sock):
    head, rest = read_head(sock)
    if head is None:
        return None, b""
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                length = 0
    body = rest
    while len(body) < length:
        try:
            chunk = sock.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        body += chunk
    return head, body[:length] if length else body


class Shim:
    def __init__(self, routes, default_path, fallback, magic, use_proxy, unknown_upgrade="tunnel"):
        self.routes = routes
        self.default_path = default_path
        self.fallback = fallback
        self.magic = magic
        self.use_proxy = use_proxy
        self.unknown_upgrade = unknown_upgrade

    def tunnel(self, downstream, req, leftover):
        path = req["path"] if req["path"] in self.routes else self.default_path
        addr = self.routes.get(path) or self.routes.get(self.default_path)
        if not addr:
            downstream.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        host, _, port = addr.partition(":")
        try:
            upstream = socket.create_connection((host, int(port)), TIMEOUT)
        except OSError:
            downstream.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        try:
            upstream.settimeout(TIMEOUT)
            upstream.sendall(build_upstream_request(req, path))
            head, rest = read_head(upstream)
            if head is None:
                return
            downstream.sendall(head + b"\r\n\r\n")
            if b" 101 " not in head.split(b"\r\n", 1)[0]:
                if rest:
                    downstream.sendall(rest)
                return
            downstream.settimeout(None)
            upstream.settimeout(None)
            if leftover:
                upstream.sendall(leftover)
            if rest:
                downstream.sendall(rest)
            upload = threading.Thread(target=pump, args=(downstream, upstream, self.magic), daemon=True)
            upload.start()
            pump(upstream, downstream)
            upload.join(timeout=1.0)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def is_tunnel(self, req):
        if req["path"] in self.routes:
            return True
        if req["method"] in FORCE_METHODS:
            return True
        # GET/POST ber-Upgrade ke path yang tidak dikenal: bisa jadi SSH-WS
        # atau layanan lain di belakang nginx, jadi bisa dialihkan ke fallback.
        return self.unknown_upgrade == "tunnel"

    def forward(self, downstream, raw, src):
        if not self.fallback:
            downstream.sendall(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
            return True
        host, _, port = self.fallback.partition(":")
        try:
            upstream = socket.create_connection((host, int(port)), TIMEOUT)
        except OSError:
            downstream.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return False
        try:
            upstream.settimeout(TIMEOUT)
            upstream.sendall((proxy_header(src) if self.use_proxy else b"") + raw)
            head, body = read_response(upstream)
            if head is None:
                return False
            downstream.sendall(head + b"\r\n\r\n" + body)
            return True
        except OSError:
            return False
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def handle(self, downstream, slots):
        try:
            downstream.settimeout(TIMEOUT)
            src = read_proxy_header(downstream) if self.use_proxy else None
            buf = b""
            deadline = time.time() + TIMEOUT
            while True:
                while b"\r\n\r\n" not in buf:
                    if len(buf) > HEADER_LIMIT or time.time() > deadline:
                        return
                    try:
                        chunk = downstream.recv(8192)
                    except (socket.timeout, OSError):
                        return
                    if not chunk:
                        return
                    buf += chunk

                head, _, rest = buf.partition(b"\r\n\r\n")
                req = parse_block(head)
                if req is None:
                    return

                length = 0
                for value in req["headers"].get("content-length", []):
                    try:
                        length = int(value)
                    except ValueError:
                        length = 0
                while len(rest) < length:
                    try:
                        chunk = downstream.recv(65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    rest += chunk
                body, rest = rest[:length], rest[length:]

                if is_upgrade(req) and self.is_tunnel(req):
                    self.tunnel(downstream, req, rest)
                    return
                if not self.forward(downstream, head + b"\r\n\r\n" + body, src):
                    return
                buf = rest
                deadline = time.time() + TIMEOUT
        except OSError:
            pass
        finally:
            try:
                downstream.close()
            except OSError:
                pass
            slots.release()

    def serve(self, listen):
        host, _, port = listen.partition(":")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, int(port)))
        server.listen(512)
        slots = threading.Semaphore(MAX_CONN)
        print("payload-shim %s | default=%s fallback=%s" % (listen, self.default_path, self.fallback), flush=True)
        while True:
            try:
                conn, _addr = server.accept()
            except OSError:
                continue
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=self.handle, args=(conn, slots), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="HTTP upgrade + payload shim")
    ap.add_argument("--listen", default="127.0.0.1:10007")
    ap.add_argument("--route", action="append", default=[], metavar="PATH=HOST:PORT")
    ap.add_argument("--default", default="/upvmess")
    ap.add_argument("--fallback", default="")
    ap.add_argument("--proxy-protocol", action="store_true")
    ap.add_argument("--magic", default="HTTP/ 69\\r\\n\\r\\n")
    ap.add_argument("--unknown-upgrade", choices=("tunnel", "fallback"), default="tunnel",
                    help="path Upgrade yang tidak terdaftar: kirim ke default (tunnel) "
                         "atau ke nginx (fallback)")
    args = ap.parse_args()

    routes = {}
    for item in args.route:
        path, _, addr = item.partition("=")
        routes[path.strip()] = addr.strip()
    magic = args.magic.encode().decode("unicode_escape").encode("latin-1")

    Shim(routes, args.default, args.fallback, magic, args.proxy_protocol,
         args.unknown_upgrade).serve(args.listen)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
