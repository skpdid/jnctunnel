#!/usr/bin/env python3
"""Uji fungsional sshws.py: raw SSH, PROXY v1, WebSocket, CONNECT."""
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


def recv_until(sock, marker, limit=4096):
    data = b""
    while marker not in data and len(data) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


def case_raw():
    s = socket.create_connection(LISTEN, timeout=5)
    banner = recv_until(s, b"\r\n")
    assert banner.startswith(b"SSH-2.0-fake"), banner
    s.sendall(b"SSH-2.0-client\r\n")
    assert recv_until(s, b"\r\n") == b"SSH-2.0-client\r\n"
    s.close()
    return "raw SSH + echo"


def case_proxy():
    s = socket.create_connection(LISTEN, timeout=5)
    s.sendall(b"PROXY TCP4 203.0.113.9 10.0.0.1 51234 109\r\nSSH-2.0-client\r\n")
    banner = recv_until(s, b"\r\n")
    assert banner.startswith(b"SSH-2.0-fake"), banner
    assert recv_until(s, b"\r\n") == b"SSH-2.0-client\r\n"
    s.close()
    return "PROXY v1 dibuang, banner tetap"


def case_ws():
    s = socket.create_connection(LISTEN, timeout=5)
    key = base64.b64encode(b"0123456789abcdef").decode()
    req = (
        "GET /ssh-ws HTTP/1.1\r\n"
        "Host: test.local\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n" % key
    )
    s.sendall(req.encode())
    head = recv_until(s, b"\r\n\r\n")
    assert b"101" in head.split(b"\r\n")[0], head
    expect = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    assert expect.encode() in head, head
    banner = recv_until(s, b"\r\n")
    assert banner.startswith(b"SSH-2.0-fake"), banner
    s.sendall(b"ping-ws\r\n")
    assert recv_until(s, b"\r\n") == b"ping-ws\r\n"
    s.close()
    return "WebSocket 101 + tunnel"


def case_connect():
    s = socket.create_connection(LISTEN, timeout=5)
    s.sendall(b"CONNECT test.local:443 HTTP/1.1\r\nHost: test.local\r\n\r\n")
    head = recv_until(s, b"\r\n\r\n")
    assert b"200" in head.split(b"\r\n")[0], head
    banner = recv_until(s, b"\r\n")
    assert banner.startswith(b"SSH-2.0-fake"), banner
    s.close()
    return "CONNECT 200 + tunnel"


def main():
    fake_ssh()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "sshws.py"),
         "--listen", "%s:%d" % LISTEN, "--target", "%s:%d" % TARGET],
        stderr=subprocess.PIPE,
    )
    time.sleep(1.2)
    try:
        for fn in (case_raw, case_proxy, case_ws, case_connect):
            print("OK  " + fn())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
