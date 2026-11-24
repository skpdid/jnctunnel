#!/usr/bin/env python3
"""jnctunnel sshws - jembatan SSH di atas WebSocket / TLS.

Mendengarkan di 127.0.0.1:2082 (di belakang haproxy) dan meneruskan byte
ke dropbear 127.0.0.1:109. Tiga bentuk koneksi didukung:

  1. WebSocket  (GET ... Upgrade: websocket)  -> balas 101 lalu tunnel mentah
  2. CONNECT    (HTTP CONNECT tunnel)         -> balas 200 lalu tunnel mentah
  3. SSH langsung (banner "SSH-...")          -> tunnel mentah tanpa handshake

Header PROXY v1 dari haproxy ("PROXY TCP4 ip ip port port") dibuang lebih dulu,
jadi IP asli klien tetap tercatat di log dropbear.

Tanpa dependensi eksternal: hanya modul standar Python 3.
"""
import argparse
import base64
import hashlib
import socket
import socketserver
import sys
import threading

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"CONNECT ")


def log(msg):
    sys.stderr.write("sshws: %s\n" % msg)
    sys.stderr.flush()


def read_head(conn, first):
    """Kumpulkan header HTTP sampai \r\n\r\n (maks 16 KiB)."""
    buf = first
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def strip_proxy_header(buf):
    """Buang baris PROXY v1 kalau ada. Kembalikan sisa byte."""
    if not buf.startswith(b"PROXY "):
        return buf
    end = buf.find(b"\r\n")
    if end == -1:
        return b""
    return buf[end + 2:]


def ws_accept(key):
    digest = hashlib.sha1((key + WS_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def header_value(head, name):
    target = name.lower().encode() + b":"
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(target):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return ""


def pipe(src, dst, leftover=b""):
    """Salin dua arah sampai salah satu sisi menutup."""
    try:
        if leftover:
            dst.sendall(leftover)
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class Handler(socketserver.BaseRequestHandler):
    target: tuple[str, int] = ("127.0.0.1", 109)

    def handle(self):
        conn = self.request
        # Klien WS/CONNECT mengirim permintaan lebih dulu; klien SSH menunggu
        # banner. Tunggu sebentar: kalau tidak ada data, anggap SSH langsung.
        conn.settimeout(2.5)
        try:
            buf = conn.recv(4096)
        except socket.timeout:
            buf = b""
        except OSError:
            return

        buf = strip_proxy_header(buf) if buf else b""

        mode = "raw"
        leftover = buf
        if buf.startswith(HTTP_METHODS):
            head = read_head(conn, buf)
            if not head:
                return
            leftover = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
            if buf.startswith(b"CONNECT "):
                mode = "connect"
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            elif "websocket" in header_value(head, "Upgrade").lower():
                key = header_value(head, "Sec-WebSocket-Key")
                if not key:
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    return
                mode = "websocket"
                resp = (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: %s\r\n\r\n" % ws_accept(key)
                )
                conn.sendall(resp.encode())
            else:
                # Permintaan HTTP biasa: jawab singkat, jangan diteruskan ke SSH.
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return

        try:
            upstream = socket.create_connection(self.target, timeout=10)
        except OSError as exc:
            log("gagal konek ke %s:%s (%s)" % (self.target[0], self.target[1], exc))
            conn.close()
            return

        upstream.settimeout(None)
        conn.settimeout(None)
        log("terhubung (%s)" % mode)
        thread = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
        thread.start()
        pipe(conn, upstream, leftover)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="jnctunnel sshws")
    parser.add_argument("--listen", default="127.0.0.1:2082")
    parser.add_argument("--target", default="127.0.0.1:109")
    args = parser.parse_args()

    host, _, port = args.listen.rpartition(":")
    thost, _, tport = args.target.rpartition(":")
    Handler.target = (thost or "127.0.0.1", int(tport))
    server = Server((host or "127.0.0.1", int(port)), Handler)
    log("listen %s -> %s:%s" % (args.listen, Handler.target[0], Handler.target[1]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
