#!/usr/bin/env bash
# jnctunnel - uninstall
#   bash uninstall.sh          : lepas layanan & konfigurasi, akun SSH tetap ada
#   bash uninstall.sh --purge  : hapus juga akun SSH yang dibuat jnctunnel
set -uo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "jalankan sebagai root"; exit 1; }

echo "[jnctunnel] menghentikan layanan"
for s in jnctunnel-xray jnctunnel-sshws jnctunnel-api jnctunnel-apiguard jnctunnel-shim \
         jnctunnel-backup.timer jnctunnel-expire.timer jnctunnel-expire.service \
         jnctunnel-backup.service jnctunnel-udpgw@7200 jnctunnel-udpgw@7300; do
  systemctl disable --now "${s}" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/jnctunnel-*.service /etc/systemd/system/jnctunnel-*.timer
systemctl daemon-reload

echo "[jnctunnel] melepas nginx & haproxy"
rm -f /etc/nginx/sites-enabled/jnctunnel.conf /etc/nginx/sites-available/jnctunnel.conf
if [ -f /etc/haproxy/haproxy.cfg.bak ]; then
  mv -f /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
fi
nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
systemctl restart haproxy >/dev/null 2>&1 || true

if [ "${PURGE}" = "1" ]; then
  echo "[jnctunnel] menghapus akun SSH buatan jnctunnel"
  for meta in /etc/jnctunnel/accounts/ssh/*.exp; do
    [ -e "${meta}" ] || continue
    u="$(basename "${meta}" .exp)"
    pkill -KILL -u "${u}" 2>/dev/null || true
    userdel -r "${u}" >/dev/null 2>&1 || true
  done
fi

echo "[jnctunnel] menghapus berkas"
rm -rf /etc/jnctunnel /usr/local/etc/xray/config.json
rm -f /usr/local/sbin/sshws.py /usr/local/sbin/xray-sync.py \
      /usr/local/sbin/jnctunnel-expire /usr/local/sbin/jnctunnel-apply \
      /usr/local/sbin/jnctunnel-apiguard /usr/local/sbin/jnctunnel-backup \
      /usr/local/sbin/jnctunnel-api.py /usr/local/sbin/jnctunnel-shim.py \
      /usr/local/sbin/menu-jnctunnel
rm -f /usr/local/sbin/menu
rm -f /usr/local/bin/xray

if iptables -w 5 -C OUTPUT -o lo -p tcp -d 127.0.0.1 --dport 10085 \
     -m owner ! --uid-owner 0 -j REJECT --reject-with tcp-reset >/dev/null 2>&1; then
  iptables -w 5 -D OUTPUT -o lo -p tcp -d 127.0.0.1 --dport 10085 \
    -m owner ! --uid-owner 0 -j REJECT --reject-with tcp-reset >/dev/null 2>&1 || true
  echo "[jnctunnel] rule guard port 10085 dihapus"
fi

echo "[jnctunnel] selesai. Paket (nginx, haproxy, dropbear, xray geo) tidak dihapus."
