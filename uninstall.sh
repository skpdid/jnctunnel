#!/usr/bin/env bash
# jnctunnel - uninstall
#   bash uninstall.sh          : lepas layanan & konfigurasi, akun SSH tetap ada
#   bash uninstall.sh --purge  : hapus juga akun SSH yang dibuat jnctunnel
set -uo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "jalankan sebagai root"; exit 1; }

echo "[jnctunnel] menghentikan layanan"
for s in jnctunnel-xray jnctunnel-sshws jnctunnel-expire.timer jnctunnel-expire.service; do
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
      /usr/local/sbin/jnctunnel-expire /usr/local/sbin/menu-jnctunnel
rm -f /usr/local/sbin/menu
rm -f /usr/local/bin/xray

echo "[jnctunnel] selesai. Paket (nginx, haproxy, dropbear, xray geo) tidak dihapus."
