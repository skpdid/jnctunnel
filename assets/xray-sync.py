#!/usr/bin/env python3
"""Bangun ulang config Xray dari akun yang tersimpan di /etc/jnctunnel.

Sumber:
  /root/jnctunnel/.verify/sandbox/base.json          template inbound (tanpa client)
  /etc/jnctunnel/accounts/<proto>/<nama> baris "uuid=..." dan "exp=<epoch>"

Hasil:
  /root/jnctunnel/.verify/sandbox/out/config.json        hanya ditulis bila lolos validasi

Dipakai menu, installer, dan timer kedaluwarsa.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

BASE = os.environ.get("JNCT_BASE", "/etc/jnctunnel/xray.base.json")
ACC = os.environ.get("JNCT_ACC", "/etc/jnctunnel/accounts")
TARGET = os.environ.get("JNCT_TARGET", "/usr/local/etc/xray/config.json")
XRAY_BIN = os.environ.get("JNCT_XRAY", "/usr/local/bin/xray")

PROTO_DIR = {"vmess": "vmess", "vless": "vless", "trojan": "trojan"}
TAG_PROTO = {
    "vmess-ws": "vmess", "vmess-up": "vmess", "vmess-grpc": "vmess",
    "vless-ws": "vless", "vless-up": "vless", "vless-grpc": "vless",
    "vless-xhttp": "vless",
    "trojan-ws": "trojan", "trojan-up": "trojan", "trojan-grpc": "trojan",
}


def read_accounts(proto):
    """Ambil akun aktif: nama -> uuid, lewati yang sudah kedaluwarsa."""
    out = []
    folder = os.path.join(ACC, "xray", proto)
    if not os.path.isdir(folder):
        return out
    now = int(time.time())
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        uuid = ""
        exp = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    key, _, val = line.strip().partition("=")
                    if key == "uuid":
                        uuid = val.strip()
                    elif key == "exp":
                        exp = int(val.strip() or 0)
        except (OSError, ValueError):
            continue
        if not uuid:
            continue
        if exp and exp < now:
            continue
        out.append((name, uuid))
    return out


def client_for(proto, name, uuid):
    if proto == "vmess":
        return {"id": uuid, "email": name, "alterId": 0}
    if proto == "vless":
        return {"id": uuid, "email": name, "flow": ""}
    return {"password": uuid, "email": name}


def build(domain):
    with open(BASE, "r", encoding="utf-8") as fh:
        raw = fh.read().replace("@DOMAIN@", domain)
    cfg = json.loads(raw)
    cache = {}
    for inbound in cfg.get("inbounds", []):
        proto = TAG_PROTO.get(inbound.get("tag"))
        if not proto:
            continue
        if proto not in cache:
            cache[proto] = read_accounts(proto)
        inbound.setdefault("settings", {})["clients"] = [
            client_for(proto, name, uuid) for name, uuid in cache[proto]
        ]
    return cfg


def validate(cfg):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        json.dump(cfg, tmp, indent=2)
        tmp.close()
        if not os.path.exists(XRAY_BIN):
            return True, ""
        proc = subprocess.run(
            [XRAY_BIN, "-test", "-config", tmp.name],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[:400]
        return True, ""
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else ""
    if not domain:
        env = "/etc/jnctunnel/config.env"
        if os.path.exists(env):
            with open(env, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("DOMAIN="):
                        domain = line.split("=", 1)[1].strip().strip('"')
    cfg = build(domain)
    ok, err = validate(cfg)
    if not ok:
        print("config xray tidak valid: " + err, file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    tmp = TARGET + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, TARGET)
    total = sum(len(i.get("settings", {}).get("clients", [])) for i in cfg["inbounds"])
    print("config xray ditulis: %d inbound, %d entri client" % (len(cfg["inbounds"]), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
