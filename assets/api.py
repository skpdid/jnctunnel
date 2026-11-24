#!/usr/bin/env python3
"""jnctunnel API - pengelolaan akun lewat HTTP untuk bot/panel.

Listen di 127.0.0.1:8088 (di belakang nginx, path /vps/). Semua endpoint
butuh header `Authorization: Bearer <API_AUTH_TOKEN>` (atau `X-API-Key`).

Tidak ada dependensi luar: hanya modul standar Python 3.
"""
import base64
import json
import os
import re
import subprocess
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

CONF = os.environ.get("JNCT_CONF", "/etc/jnctunnel/config.env")
ACC = os.environ.get("JNCT_ACC", "/etc/jnctunnel/accounts")
APPLY = os.environ.get("JNCT_APPLY", "/usr/local/sbin/jnctunnel-apply")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,19}$")

PROTO_DIRS = ("vmess", "vless", "trojan")
TAG_PROTO = {
    "vmess-ws": "vmess", "vmess-up": "vmess", "vmess-grpc": "vmess",
    "vless-ws": "vless", "vless-up": "vless", "vless-grpc": "vless",
    "vless-xhttp": "vless",
    "trojan-ws": "trojan", "trojan-up": "trojan", "trojan-grpc": "trojan",
}


def load_conf():
    conf = {}
    if os.path.exists(CONF):
        with open(CONF, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                conf[key.strip()] = val.strip().strip('"').strip("'")
    return conf


CONF_MAP = load_conf()
TOKEN = CONF_MAP.get("API_AUTH_TOKEN", "")
DOMAIN = CONF_MAP.get("DOMAIN", "")
PORT = int(os.environ.get("JNCT_PORT") or CONF_MAP.get("API_PORT") or "8088")
DEFAULT_DAYS = int(CONF_MAP.get("DEFAULT_DAYS") or "30")


def run(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def days_to_epoch(days):
    return int(time.time()) + days * 86400


def epoch_to_date(epoch):
    if not epoch:
        return "selamanya"
    return time.strftime("%Y-%m-%d", time.localtime(int(epoch)))


def server_host():
    return DOMAIN or "127.0.0.1"


# ---------------------------------------------------------------- akun SSH
def ssh_meta(name):
    return os.path.join(ACC, "ssh", name + ".exp")


def ssh_exp(name):
    try:
        with open(ssh_meta(name), "r", encoding="utf-8") as fh:
            return int((fh.read().strip() or "0") or 0)
    except (OSError, ValueError):
        return None


def ssh_create(name, password, days):
    if ssh_exp(name) is not None or run(["id", name])[0] == 0:
        return False, "user sudah ada"
    expire_date = time.strftime("%Y-%m-%d", time.localtime(days_to_epoch(days)))
    rc, out = run(["useradd", "-m", "-s", "/bin/bash", "-e", expire_date, name])
    if rc != 0:
        return False, "gagal membuat user: " + out.strip()[:120]
    proc = subprocess.run(["chpasswd"], input="%s:%s\n" % (name, password),
                          capture_output=True, text=True)
    if proc.returncode != 0:
        run(["userdel", "-r", name])
        return False, "gagal set password"
    os.makedirs(os.path.dirname(ssh_meta(name)), exist_ok=True)
    with open(ssh_meta(name), "w", encoding="utf-8") as fh:
        fh.write(str(days_to_epoch(days)))
    return True, "ok"


def ssh_delete(name):
    if ssh_exp(name) is None:
        return False, "akun tidak ada"
    run(["pkill", "-KILL", "-u", name])
    run(["userdel", "-r", name])
    try:
        os.unlink(ssh_meta(name))
    except OSError:
        pass
    return True, "ok"


def ssh_renew(name, days):
    if ssh_exp(name) is None:
        return False, "akun tidak ada"
    with open(ssh_meta(name), "w", encoding="utf-8") as fh:
        fh.write(str(days_to_epoch(days)))
    run(["chage", "-E", time.strftime("%Y-%m-%d", time.localtime(days_to_epoch(days))), name])
    return True, "ok"


# --------------------------------------------------------------- akun Xray
def xray_meta(proto, name):
    return os.path.join(ACC, "xray", proto, name)


def xray_read(proto, name):
    data = {}
    try:
        with open(xray_meta(proto, name), "r", encoding="utf-8") as fh:
            for line in fh:
                key, _, val = line.strip().partition("=")
                if key:
                    data[key] = val
    except OSError:
        return None
    return data or None


def xray_create(proto, name, days):
    if proto not in PROTO_DIRS:
        return False, "protokol tidak dikenal", None
    if xray_read(proto, name):
        return False, "akun sudah ada", None
    uid = str(uuid.uuid4())
    os.makedirs(os.path.dirname(xray_meta(proto, name)), exist_ok=True)
    with open(xray_meta(proto, name), "w", encoding="utf-8") as fh:
        fh.write("uuid=%s\nexp=%d\ncreated=%d\n" % (uid, days_to_epoch(days), int(time.time())))
    rc, out = run(["bash", APPLY, "add", proto, name])
    if rc != 0:
        return False, "gagal menerapkan config: " + out.strip()[:160], None
    return True, "ok", uid


def xray_delete(proto, name):
    if not xray_read(proto, name):
        return False, "akun tidak ada"
    try:
        os.unlink(xray_meta(proto, name))
    except OSError:
        pass
    run(["bash", APPLY, "remove", proto, name])
    return True, "ok"


def xray_renew(proto, name, days):
    meta = xray_read(proto, name)
    if not meta:
        return False, "akun tidak ada"
    meta["exp"] = str(days_to_epoch(days))
    with open(xray_meta(proto, name), "w", encoding="utf-8") as fh:
        for key in ("uuid", "exp", "created"):
            if key in meta:
                fh.write("%s=%s\n" % (key, meta[key]))
    run(["bash", APPLY, "renew", proto, name])
    return True, "ok"


# -------------------------------------------------------------------- link
def link_for(proto, name, uid):
    host = server_host()
    if proto == "vmess":
        payload = {
            "v": "2", "ps": name, "add": host, "port": "443", "id": uid,
            "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": host, "path": "/vmess", "tls": "tls", "sni": host,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return "vmess://" + base64.b64encode(raw).decode()
    if proto == "vless":
        return ("vless://%s@%s:443?encryption=none&security=tls&sni=%s"
                "&type=ws&host=%s&path=%%2Fvless#%s" % (uid, host, host, host, name))
    return ("trojan://%s@%s:443?security=tls&sni=%s&type=ws&host=%s&path=%%2Ftrojan#%s"
            % (uid, host, host, host, name))


def account_payload(proto, name, uid, exp):
    return {
        "username": name,
        "protocol": proto,
        "uuid": uid,
        "expired": exp,
        "expired_at": epoch_to_date(exp),
        "link": link_for(proto, name, uid),
    }


# ------------------------------------------------------------------- server
class Handler(BaseHTTPRequestHandler):
    server_version = "jnctunnel/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 - samakan signature induk
        pass

    # -- util
    def send_json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if not TOKEN:
            return False
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:].strip() == TOKEN:
            return True
        return self.headers.get("X-API-Key", "") == TOKEN

    def body_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def int_param(self, value, default):
        try:
            num = int(value)
        except (TypeError, ValueError):
            return default
        return max(1, min(3650, num))

    # -- dispatch
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/vps/health":
            return self.send_json(200, {"ok": True, "service": "jnctunnel",
                                        "domain": DOMAIN, "time": int(time.time())})
        if not self.authorized():
            return self.send_json(401, {"ok": False, "message": "unauthorized"})

        try:
            return self.dispatch(method, path, query)
        except Exception as exc:  # jangan matikan server karena satu request
            return self.send_json(500, {"ok": False, "message": str(exc)[:200]})

    def dispatch(self, method, path, query):
        # --- daftar akun
        if path in ("/vps/accounts", "/vps/my-accounts") and method == "GET":
            return self.list_accounts(query)

        # --- SSH
        if path in ("/vps/sshvpn", "/vps/trialsshvpn") and method == "POST":
            return self.create_ssh(self.body_json(), trial=path.endswith("trialsshvpn"))
        m = re.match(r"^/vps/deletesshvpn/([a-z0-9_-]+)$", path)
        if m and method in ("POST", "DELETE"):
            ok, msg = ssh_delete(m.group(1))
            return self.send_json(200 if ok else 400, {"ok": ok, "message": msg})
        m = re.match(r"^/vps/renewsshvpn/([a-z0-9_-]+)/(\d+)$", path)
        if m and method == "POST":
            ok, msg = ssh_renew(m.group(1), self.int_param(m.group(2), DEFAULT_DAYS))
            return self.send_json(200 if ok else 400, {"ok": ok, "message": msg})

        # --- Xray
        m = re.match(r"^/vps/(?:trial)?(vmess|vless|trojan)all$", path)
        if m and method == "POST":
            proto = m.group(1)
            return self.create_xray(proto, self.body_json(), trial="trial" in path)
        m = re.match(r"^/vps/delete(vmess|vless|trojan)/([a-z0-9_-]+)$", path)
        if m and method in ("POST", "DELETE"):
            ok, msg = xray_delete(m.group(1), m.group(2))
            return self.send_json(200 if ok else 400, {"ok": ok, "message": msg})
        m = re.match(r"^/vps/renew(vmess|vless|trojan)/([a-z0-9_-]+)/(\d+)$", path)
        if m and method == "POST":
            ok, msg = xray_renew(m.group(1), m.group(2), self.int_param(m.group(3), DEFAULT_DAYS))
            return self.send_json(200 if ok else 400, {"ok": ok, "message": msg})

        # --- kapasitas
        if path == "/vps/capacity" and method == "GET":
            return self.capacity()

        return self.send_json(404, {"ok": False, "message": "endpoint tidak ada"})

    # -- handlers
    def create_ssh(self, body, trial=False):
        name = str(body.get("username") or "").strip().lower()
        if trial and not name:
            name = "trial" + str(int(time.time()))[-6:]
        if not NAME_RE.match(name):
            return self.send_json(400, {"ok": False, "message": "username tidak valid"})
        days = self.int_param(body.get("expired"), 1 if trial else DEFAULT_DAYS)
        password = str(body.get("password") or "").strip() or uuid.uuid4().hex[:10]
        ok, msg = ssh_create(name, password, days)
        if not ok:
            return self.send_json(400, {"ok": False, "message": msg})
        return self.send_json(200, {
            "ok": True, "message": "akun SSH dibuat",
            "data": {
                "username": name, "password": password,
                "host": server_host(), "port": 109, "alt_port": 143,
                "expired_at": epoch_to_date(days_to_epoch(days)),
            },
        })

    def create_xray(self, proto, body, trial=False):
        name = str(body.get("username") or "").strip().lower()
        if trial and not name:
            name = "trial" + str(int(time.time()))[-6:]
        if not NAME_RE.match(name):
            return self.send_json(400, {"ok": False, "message": "username tidak valid"})
        days = self.int_param(body.get("expired"), 1 if trial else DEFAULT_DAYS)
        ok, msg, uid = xray_create(proto, name, days)
        if not ok:
            return self.send_json(400, {"ok": False, "message": msg})
        return self.send_json(200, {
            "ok": True, "message": "akun %s dibuat" % proto,
            "data": account_payload(proto, name, uid, days_to_epoch(days)),
        })

    def list_accounts(self, query):
        wanted = (query.get("username") or [""])[0].strip().lower()
        data = {"ssh": [], "vmess": [], "vless": [], "trojan": []}
        ssh_dir = os.path.join(ACC, "ssh")
        if os.path.isdir(ssh_dir):
            for fname in sorted(os.listdir(ssh_dir)):
                if not fname.endswith(".exp"):
                    continue
                name = fname[:-4]
                if wanted and name != wanted:
                    continue
                exp = ssh_exp(name) or 0
                data["ssh"].append({"username": name, "expired_at": epoch_to_date(exp)})
        for proto in PROTO_DIRS:
            folder = os.path.join(ACC, "xray", proto)
            if not os.path.isdir(folder):
                continue
            for name in sorted(os.listdir(folder)):
                if wanted and name != wanted:
                    continue
                meta = xray_read(proto, name) or {}
                data[proto].append({
                    "username": name, "uuid": meta.get("uuid", ""),
                    "expired_at": epoch_to_date(meta.get("exp", 0)),
                })
        return self.send_json(200, {"ok": True, "data": data})

    def capacity(self):
        out = {}
        try:
            with open("/proc/loadavg", "r", encoding="utf-8") as fh:
                out["load"] = fh.read().split()[:3]
            with open("/proc/meminfo", "r", encoding="utf-8") as fh:
                info = dict(line.split(":", 1) for line in fh if ":" in line)
            total = int(info["MemTotal"].split()[0])
            avail = int(info["MemAvailable"].split()[0])
            out["memory"] = {"total_mb": total // 1024,
                             "used_mb": (total - avail) // 1024}
            st = os.statvfs("/")
            out["disk"] = {"total_gb": round(st.f_blocks * st.f_frsize / 1e9, 1),
                           "free_gb": round(st.f_bavail * st.f_frsize / 1e9, 1)}
        except (OSError, KeyError, ValueError):
            pass
        return self.send_json(200, {"ok": True, "data": out})


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("jnctunnel-api listen 127.0.0.1:%d" % PORT, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
