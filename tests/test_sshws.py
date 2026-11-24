#!/usr/bin/env python3
"""Uji fungsional sshws.py: raw SSH, PROXY v1, WebSocket, CONNECT.

Jalankan: python3 tests/test_sshws.py
Semua koneksi hanya ke 127.0.0.1, tidak menyentuh layanan sistem.
"""
import base64
import hashlib
import os
import socket
import subprocess
import sys
import threading
import time

LISTEN = ("127.0.0.1", 22082)
TARGET = ("127.0.0.1", 22109)
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fake_ssh():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(TARGET)
    srv.listen(8)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-fake\r\n")
            try:
                while True:
                    d = c.recv(4096)
                    if not d:
                        break
                    c.sendall(d)
            except OSError:
                pass
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def read_until(sock, done, timeout=6):
    """Baca terus sampai done(buffer) benar; kembalikan seluruh buffer.

    Buffer utuh dikembalikan supaya data yang datang menyatu (banner + echo
    dalam satu segmen TCP) tidak hilang.
    """
    sock.settimeout(timeout)
    buf = b""
    while not done(buf):
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf


def case_raw():
    s = socket.create_connection(LISTEN, timeout=6)
    s.sendall(b"SSH-2.0-client\r\n")
    buf = read_until(s, lambda b: b.count(b"\r\n") >= 2)
    s.close()
    assert b"SSH-2.0-fake" in buf, buf
    assert b"SSH-2.0-client" in buf, buf
    return "raw SSH + echo"


def case_proxy():
    s = socket.create_connection(LISTEN, timeout=6)
    s.sendall(b"PROXY TCP4 203.0.113.9 10.0.0.1 51234 109\r\nSSH-2.0-client\r\n")
    buf = read_until(s, lambda b: b.count(b"\r\n") >= 2)
    s.close()
    assert b"PROXY" not in buf, buf
    assert b"SSH-2.0-fake" in buf, buf
    assert b"SSH-2.0-client" in buf, buf
    return "PROXY v1 dibuang, banner tetap"


def case_ws():
    s = socket.create_connection(LISTEN, timeout=6)
    key = base64.b64encode(b"0123456789abcdef").decode()
    s.sendall((
        "GET /ssh-ws HTTP/1.1\r\n"
        "Host: test.local\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n" % key
    ).encode())
    head = read_until(s, lambda b: b"\r\n\r\n" in b)
    expect = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    assert b"101" in head.split(b"\r\n")[0], head
    assert expect.encode() in head, head
    s.sendall(b"ping-ws\r\n")
    buf = read_until(s, lambda b: b"SSH-2.0-fake" in b and b"ping-ws" in b)
    s.close()
    assert b"SSH-2.0-fake" in buf, buf
    assert b"ping-ws" in buf, buf
    return "WebSocket 101 + tunnel"


def case_connect():
    s = socket.create_connection(LISTEN, timeout=6)
    s.sendall(b"CONNECT test.local:443 HTTP/1.1\r\nHost: test.local\r\n\r\n")
    head = read_until(s, lambda b: b"\r\n\r\n" in b)
    assert b"200" in head.split(b"\r\n")[0], head
    buf = read_until(s, lambda b: b"SSH-2.0-fake" in b)
    s.close()
    assert b"SSH-2.0-fake" in buf, buf
    return "CONNECT 200 + tunnel"


def case_reject_plain_http():
    s = socket.create_connection(LISTEN, timeout=6)
    s.sendall(b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n")
    buf = read_until(s, lambda b: b"\r\n\r\n" in b)
    s.close()
    assert b"400" in buf.split(b"\r\n")[0], buf
    return "HTTP biasa ditolak 400"


def main():
    fake_ssh()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "assets", "sshws.py"),
         "--listen", "%s:%d" % LISTEN, "--target", "%s:%d" % TARGET],
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.2)
    failed = 0
    try:
        for fn in (case_raw, case_proxy, case_ws, case_connect, case_reject_plain_http):
            try:
                print("OK   " + fn())
            except AssertionError as exc:
                failed += 1
                print("FAIL %s: %r" % (fn.__name__, exc))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
