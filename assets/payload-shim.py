#!/usr/bin/env python3
"""jnctunnel payload shim - penerjemah handshake HTTPUpgrade/WebSocket ber-payload.

Banyak klien (HTTP Custom, HTTP Injector, dsb) mengirim payload seperti ini
sebelum tunnel benar-benar mulai:

    GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]
    PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]
    [split] HTTP/ 69[crlf][crlf]

Artinya: satu request umpan (decoy) dikirim lebih dulu, lalu request upgrade
dengan method bukan GET, lalu penanda "HTTP/ 69" dikirim setelah handshake.
Xray hanya menerima `GET <path>` yang rapi, jadi tanpa perantara ini koneksi
selalu putus (400/502) walau akun benar.

Shim ini:
  1. menerima koneksi dari haproxy (PROXY protocol v1),
  2. membaca satu atau beberapa request; request umpan dilewati,
  3. menemukan request ber-`Upgrade: websocket` -> mode tunnel,
  4. mengirim ulang sebagai `GET <path>` bersih ke inbound Xray terkait,
  5. meneruskan respons 101 apa adanya, lalu membuang satu penanda "HTTP/ 69",
  6. kalau bukan tunnel (API /vps/, ACME, 404) diteruskan apa adanya ke nginx.

Hanya modul standar Python 3. Listen 127.0.0.1:10007.
"""
import os
import socket
import sys
import threading
import time

LISTEN = os.environ.get("JNCT_SHIM_LISTEN", "127.0.0.1:10007")
NGINX = os.environ.get("JNCT_SHIM_NGINX", "127.0.0.1:8083")
DEFAULT_ROUTE = os.environ.get("JNCT_SHIM_DEFAULT", "/upvmess")
MAGIC = b"HTTP/ 69\r\n\r\n"
HEADER_LIMIT = 64 * 1024
HANDSHAKE_TIMEOUT = 8.0
MAX_CONNECTIONS = int(os.environ.get("JNCT_SHIM_MAX_CONN", "2048"))

ROUTES = {
    "/upvmess": "127.0.0.1:10004",
    "/upvless": "127.0.0.1:10005",
    "/uptrojan": "127.0.0.1:10006",
    "/vmess": "127.0.0.1:10001",
    "/vless": "127.0.0.1:10002",
    "/trojan": "127.0.0.1:10003",
}

TUNNEL_METHODS = {"GET", "POST", "PATCH", "PUT", "HEAD", "OPTIONS"}
# Method yang tetap dianggap percobaan tunnel walau proxy di depan (mis.
# Cloudflare Worker) membuang header Upgrade/Connection.
FORCE_METHODS = {m.strip().upper() for m in (os.environ.get("JNCT_SHIM_FORCE_METHODS")
                                             or "PATCH,PUT").split(",") if m.strip()}

# Penimpaan rute untuk pengujian: JNCT_SHIM_ROUTES="/upvmess=127.0.0.1:17004,..."
for _item in (os.environ.get("JNCT_SHIM_ROUTES") or "").split(","):
    if "=" in _item:
        _path, _addr = _item.split("=", 1)
        ROUTES[_path.strip()] = _addr.strip()


# ------------------------------------------------------------------ PROXY v1
def read_proxy_header(sock):
    """Baca PROXY protocol v1 bila ada. Kembalikan (src_ip, dst_ip, sport, dport)."""
    try:
        peek = sock.recv(6, socket.MSG_PEEK)
    except OSError:
        return None
    # "PATCH ..." juga dimulai dengan P - hanya "PROXY " yang dianggap header.
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
    s_ip, d_ip, s_port, d_port = src
    return ("PROXY TCP4 %s %s %s %s\r\n" % (s_ip, d_ip, s_port, d_port)).encode()


# ------------------------------------------------------------------- parsing
def split_requests(buf):
    """Daftar (head, index_setelah_header) untuk tiap blok header yang utuh."""
    blocks = []
    pos = 0
    while True:
        idx = buf.find(b"\r\n\r\n", pos)
        if idx < 0:
            break
        blocks.append((buf[pos:idx], idx + 4))
        pos = idx + 4
    return blocks


def parse_block(head):
    lines = head.split(b"\r\n")
    if not lines:
        return None
    try:
        method, target, _version = lines[0].decode("latin-1").split(" ", 2)
    except (UnicodeDecodeError, ValueError):
        return None
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep:
            continue
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return {"method": method.upper(), "path": target.split("?", 1)[0], "headers": headers}


def hget(req, name):
    return ", ".join(req["headers"].get(name, []))


def is_upgrade(req):
    if req["method"] not in TUNNEL_METHODS:
        return False
    if "upgrade" in hget(req, "connection").lower() or hget(req, "upgrade").lower() == "websocket":
        return True
    # PATCH/PUT adalah penanda payload umum; tetap dianggap tunnel supaya
    # perantara (Cloudflare Worker) yang menghapus header Upgrade tidak
    # membuat koneksi mati dengan 301/400.
    if req["method"] in FORCE_METHODS and not hget(req, "content-length"):
        return True
    return False


def build_upstream_request(req, path):
    host = hget(req, "host") or "localhost"
    lines = ["GET %s HTTP/1.1" % path, "Host: %s" % host,
             "Connection: Upgrade", "Upgrade: websocket"]
    for name in ("sec-websocket-key", "sec-websocket-version", "user-agent",
                 "accept-language", "x-forwarded-for", "x-real-ip"):
        value = hget(req, name)
        if value:
            lines.append("%s: %s" % ("-".join(p.capitalize() for p in name.split("-")), value))
    for name, values in req["headers"].items():
        if name.startswith("x-jnct-") and len(values) == 1:
            lines.append("%s: %s" % (name, values[0]))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


# --------------------------------------------------------------------- relay
def pump(src, dst, strip_magic=False):
    try:
        if strip_magic:
            prefix = b""
            matched = True
            for expected in MAGIC:
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


def read_response_head(sock):
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


def handle_tunnel(downstream, req, leftover):
    target = ROUTES.get(req["path"], ROUTES[DEFAULT_ROUTE])
    path = req["path"] if req["path"] in ROUTES else DEFAULT_ROUTE
    host, _, port = target.partition(":")
    try:
        upstream = socket.create_connection((host, int(port)), HANDSHAKE_TIMEOUT)
    except OSError:
        downstream.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    try:
        upstream.settimeout(HANDSHAKE_TIMEOUT)
        upstream.sendall(build_upstream_request(req, path))
        response_head, response_rest = read_response_head(upstream)
        if response_head is None:
            return
        downstream.sendall(response_head + b"\r\n\r\n")
        if b" 101 " not in response_head.split(b"\r\n", 1)[0]:
            if response_rest:
                downstream.sendall(response_rest)
            return
        downstream.settimeout(None)
        upstream.settimeout(None)
        if leftover:
            upstream.sendall(leftover)
        if response_rest:
            downstream.sendall(response_rest)
        upload = threading.Thread(target=pump, args=(downstream, upstream, True), daemon=True)
        upload.start()
        pump(upstream, downstream)
        upload.join(timeout=1.0)
    finally:
        try:
            upstream.close()
        except OSError:
            pass


def read_response(sock):
    """Baca satu respons HTTP: header + body sesuai Content-Length."""
    head, rest = read_response_head(sock)
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


def forward_http_once(downstream, raw, src):
    """Teruskan satu request (umpan/normal) ke nginx, balikan responsnya.

    Koneksi klien TIDAK ditutup: setelah respons umpan terkirim, shim tetap
    membaca request berikutnya di koneksi yang sama - di situlah request
    upgrade (PATCH/GET + Upgrade: websocket) biasanya menyusul.
    """
    host, _, port = NGINX.partition(":")
    try:
        upstream = socket.create_connection((host, int(port)), HANDSHAKE_TIMEOUT)
    except OSError:
        downstream.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return False
    try:
        upstream.settimeout(HANDSHAKE_TIMEOUT)
        upstream.sendall(proxy_header(src) + raw)
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


def handle(downstream, slots):
    try:
        downstream.settimeout(HANDSHAKE_TIMEOUT)
        src = read_proxy_header(downstream)

        buf = b""
        deadline = time.time() + HANDSHAKE_TIMEOUT
        while True:
            while b"\r\n\r\n" not in buf:
                if len(buf) > HEADER_LIMIT or time.time() > deadline:
                    return
                try:
                    chunk = downstream.recv(8192)
                except socket.timeout:
                    return
                except OSError:
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

            if is_upgrade(req):
                handle_tunnel(downstream, req, rest)
                return

            if not forward_http_once(downstream, head + b"\r\n\r\n" + body, src):
                return
            buf = rest
            deadline = time.time() + HANDSHAKE_TIMEOUT
    except OSError:
        pass
    finally:
        try:
            downstream.close()
        except OSError:
            pass
        slots.release()


def main():
    host, _, port = LISTEN.partition(":")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, int(port)))
    server.listen(512)
    slots = threading.Semaphore(MAX_CONNECTIONS)
    print("jnctunnel payload shim %s -> nginx %s" % (LISTEN, NGINX), flush=True)
    while True:
        try:
            conn, _addr = server.accept()
        except OSError:
            continue
        if not slots.acquire(blocking=False):
            try:
                conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            conn.close()
            continue
        threading.Thread(target=handle, args=(conn, slots), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
