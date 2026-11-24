#!/usr/bin/env bash
# jnctunnel - installer utama
# Memasang: dropbear (SSH), nginx, haproxy (TLS 443), Xray (VMess/VLESS/Trojan),
# jembatan SSH-over-WebSocket, menu CLI, dan timer kedaluwarsa akun.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSETS="${REPO_DIR}/assets"
CONF_DIR="/etc/jnctunnel"
ACC_DIR="${CONF_DIR}/accounts"
TLS_DIR="${CONF_DIR}/tls"
XRAY_CFG_DIR="/usr/local/etc/xray"
PEM="${TLS_DIR}/jnctunnel.pem"

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
ASSUME_YES="${ASSUME_YES:-0}"

C_OK="\033[1;32m"; C_ERR="\033[1;31m"; C_INFO="\033[1;36m"; C_OFF="\033[0m"
say()  { printf "${C_INFO}[jnctunnel]${C_OFF} %s\n" "$*"; }
ok()   { printf "${C_OK}[ ok ]${C_OFF} %s\n" "$*"; }
die()  { printf "${C_ERR}[fail]${C_OFF} %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Pemakaian: bash jnctunnel.sh [--domain contoh.com] [--email admin@contoh.com] [--yes]

  --domain   domain yang dipakai TLS (kosong = pakai IP publik, sertifikat sendiri)
  --email    email untuk Let's Encrypt
  --yes      jangan bertanya, pakai nilai yang ada
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email)  EMAIL="${2:-}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "argumen tidak dikenal: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "jalankan sebagai root"

# ------------------------------------------------------------------ OS & deps
. /etc/os-release 2>/dev/null || true
case "${ID:-}${VERSION_ID:-}" in
  debian1[2-9]*|ubuntu2[0-9]*) : ;;
  *) say "peringatan: OS ${PRETTY_NAME:-tidak dikenal}; skrip diuji di Debian 12 / Ubuntu 22.04" ;;
esac

install_deps() {
  say "memasang paket dasar"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends \
    curl unzip ca-certificates nginx haproxy dropbear-bin python3 openssl \
    iproute2 procps iptables >/dev/null
  ok "paket dasar siap"
}

# --------------------------------------------------------------------- udpgw
# badvpn-udpgw: gateway UDP untuk sesi SSH/SSHWS (VC, game, DNS).
# Debian 12 tidak lagi menyediakan paket badvpn, jadi dicoba apt lalu build
# dari source (butuh cmake + gcc + git saat install).
install_udpgw() {
  local bin="/usr/local/bin/badvpn-udpgw" p tmp
  if [ -x "${bin}" ]; then
    ok "udpgw sudah ada"
    return 0
  fi

  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends badvpn >/dev/null 2>&1 || true
  for p in /usr/bin/badvpn-udpgw /usr/sbin/badvpn-udpgw /usr/local/bin/badvpn-udpgw; do
    if [ -x "${p}" ]; then
      install -m 755 "${p}" "${bin}"
      ok "udpgw dari paket sistem"
      return 0
    fi
  done

  say "badvpn tidak ada di repo, build dari source (sekali saja)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    cmake build-essential git >/dev/null 2>&1 || true

  tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/ambrop72/badvpn.git "${tmp}/src" >/dev/null 2>&1; then
    mkdir -p "${tmp}/src/build"
    if ( cd "${tmp}/src/build" \
         && cmake .. -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DBUILD_NOTHING_BY_DEFAULT=1 \
              -DBUILD_UDPGW=1 -DCMAKE_C_FLAGS=-fcommon >/dev/null 2>&1 \
         && make -j"$(nproc)" >/dev/null 2>&1 \
         && install -m 755 udpgw/badvpn-udpgw "${bin}" ); then
      ok "udpgw dibangun: $("${bin}" --version 2>&1 | head -1)"
    fi
  fi
  rm -rf "${tmp}"

  if [ -x "${bin}" ]; then
    return 0
  fi
  warn "udpgw gagal disiapkan, port 7200/7300 dilewati"
  return 1
}

setup_udpgw() {
  local port
  [ -x /usr/local/bin/badvpn-udpgw ] || { warn "udpgw tidak ada, unit tidak diaktifkan"; return 0; }
  for port in ${UDPGW_PORTS:-7200 7300}; do
    systemctl enable --now "jnctunnel-udpgw@${port}" >/dev/null 2>&1 \
      || systemctl restart "jnctunnel-udpgw@${port}" >/dev/null 2>&1 || true
  done
  ok "udpgw aktif di port ${UDPGW_PORTS:-7200 7300}"
}

# ---------------------------------------------------------------------- Xray
xray_asset() {
  case "$(uname -m)" in
    x86_64|amd64) echo "Xray-linux-64.zip" ;;
    aarch64|arm64) echo "Xray-linux-arm64-v8a.zip" ;;
    armv7l) echo "Xray-linux-arm32-v7a.zip" ;;
    *) die "arsitektur $(uname -m) belum didukung" ;;
  esac
}

install_xray() {
  if [ -x /usr/local/bin/xray ]; then
    ok "Xray sudah ada: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
    return 0
  fi
  say "mengunduh Xray-core"
  local asset tmp tag
  asset="$(xray_asset)"
  tmp="$(mktemp -d)"
  tag="$(curl -4fsS --max-time 20 https://api.github.com/repos/XTLS/Xray-core/releases/latest \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "${tag}" ] || die "gagal membaca versi Xray dari GitHub"

  if ! curl -4fsSL --max-time 120 \
      "https://github.com/XTLS/Xray-core/releases/download/${tag}/${asset}" -o "${tmp}/x.zip"; then
    rm -rf "${tmp}"; die "gagal mengunduh ${asset} (${tag})"
  fi
  unzip -q "${tmp}/x.zip" -d "${tmp}/x" || { rm -rf "${tmp}"; die "arsip Xray rusak"; }
  install -m 755 "${tmp}/x/xray" /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  for f in geoip.dat geosite.dat; do
    [ -f "${tmp}/x/${f}" ] && install -m 644 "${tmp}/x/${f}" "/usr/local/share/xray/${f}"
  done
  rm -rf "${tmp}"
  ok "Xray ${tag} terpasang"
}

# ------------------------------------------------------------------- konfig
write_configs() {
  say "menulis konfigurasi"

  install -d -m 755 "${CONF_DIR}" "${ACC_DIR}/ssh" "${ACC_DIR}/xray/vmess" \
    "${ACC_DIR}/xray/vless" "${ACC_DIR}/xray/trojan" "${TLS_DIR}" \
    "${XRAY_CFG_DIR}" /var/www/html
  install -d -m 700 "${TLS_DIR}"

  if [ ! -f "${CONF_DIR}/config.env" ]; then
    install -m 600 "${ASSETS}/config.env" "${CONF_DIR}/config.env"
  fi
  sed -i "s|^DOMAIN=.*|DOMAIN=\"${DOMAIN}\"|; s|^EMAIL=.*|EMAIL=\"${EMAIL}\"|" "${CONF_DIR}/config.env"
  if ! grep -q '^API_AUTH_TOKEN="[^"]\+' "${CONF_DIR}/config.env"; then
    token="$(openssl rand -hex 24)"
    sed -i "s|^API_AUTH_TOKEN=.*|API_AUTH_TOKEN=\"${token}\"|" "${CONF_DIR}/config.env"
  fi
  # muat port & default dari config.env
  # shellcheck disable=SC1090
  . "${CONF_DIR}/config.env"

  install -m 644 "${ASSETS}/xray.base.json" "${CONF_DIR}/xray.base.json"
  install -m 644 "${ASSETS}/banner.txt" "${CONF_DIR}/banner.txt"
  install -m 755 "${ASSETS}/sshws.py" /usr/local/sbin/sshws.py
  install -m 755 "${ASSETS}/xray-sync.py" /usr/local/sbin/xray-sync.py
  install -m 755 "${REPO_DIR}/jnctunnel-expire" /usr/local/sbin/jnctunnel-expire
  install -m 755 "${REPO_DIR}/jnctunnel-apply" /usr/local/sbin/jnctunnel-apply
  install -m 755 "${REPO_DIR}/jnctunnel-apiguard" /usr/local/sbin/jnctunnel-apiguard
  install -m 755 "${REPO_DIR}/jnctunnel-backup" /usr/local/sbin/jnctunnel-backup
  install -m 755 "${ASSETS}/api.py" /usr/local/sbin/jnctunnel-api.py
  install -m 755 "${ASSETS}/payload-shim.py" /usr/local/sbin/jnctunnel-shim.py
  install -m 755 "${REPO_DIR}/menu.sh" /usr/local/sbin/menu-jnctunnel
  ln -sf /usr/local/sbin/menu-jnctunnel /usr/local/sbin/menu

  # systemd
  install -m 644 "${ASSETS}/systemd/jnctunnel-xray.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-sshws.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-expire.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-expire.timer" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-api.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-apiguard.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-backup.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-backup.timer" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-udpgw@.service" /etc/systemd/system/
  install -m 644 "${ASSETS}/systemd/jnctunnel-shim.service" /etc/systemd/system/

  # nginx
  sed "s|@DOMAIN@|${DOMAIN}|g" "${ASSETS}/nginx-jnctunnel.conf" \
    > /etc/nginx/sites-available/jnctunnel.conf
  ln -sf /etc/nginx/sites-available/jnctunnel.conf /etc/nginx/sites-enabled/jnctunnel.conf
  rm -f /etc/nginx/sites-enabled/default

  # dropbear
  cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=${SSH_MAIN_PORT:-109}
DROPBEAR_EXTRA_ARGS="-p ${SSH_ALT_PORT:-143}"
DROPBEAR_BANNER="${CONF_DIR}/banner.txt"
DROPBEAR_RECEIVE_WINDOW=65536
EOF
  ok "konfigurasi tertulis di ${CONF_DIR}"
}

# --------------------------------------------------------------------- TLS
is_ip() {
  case "$1" in
    ""|*[!0-9.]*) return 1 ;;
    *.*.*.*) return 0 ;;
    *) return 1 ;;
  esac
}

self_signed() {
  say "membuat sertifikat sendiri (self-signed)"
  local cn="${DOMAIN}"
  [ -n "${cn}" ] || cn="$(hostname -f 2>/dev/null || echo jnctunnel)"
  local san
  if is_ip "${cn}"; then san="IP:${cn}"; else san="DNS:${cn}"; fi
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "${TLS_DIR}/privkey.pem" -out "${TLS_DIR}/fullchain.pem" \
    -subj "/CN=${cn}" -addext "subjectAltName=${san}" >/dev/null 2>&1
  ok "sertifikat sendiri dibuat untuk ${cn}"
}

setup_cert() {
  local have_le=0
  if [ -n "${DOMAIN}" ] && ! is_ip "${DOMAIN}" && [ -n "${EMAIL}" ]; then
    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
      have_le=1
      say "memakai sertifikat Let's Encrypt yang sudah ada"
    else
      say "meminta sertifikat Let's Encrypt untuk ${DOMAIN}"
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends certbot >/dev/null 2>&1 || true
      # port 80 harus bebas: haproxy & nginx dilepas sementara, certbot memakai
      # --standalone supaya tidak bergantung pada vhost yang belum siap.
      systemctl stop haproxy >/dev/null 2>&1 || true
      systemctl stop nginx >/dev/null 2>&1 || true
      if command -v certbot >/dev/null 2>&1 && \
         certbot certonly --standalone -d "${DOMAIN}" \
           --non-interactive --agree-tos -m "${EMAIL}" --keep-until-expiring >/dev/null 2>&1; then
        have_le=1
        ok "sertifikat Let's Encrypt siap"
      else
        say "Let's Encrypt gagal (cek DNS/port 80), memakai sertifikat sendiri"
      fi
    fi
  fi

  if [ "${have_le}" = "1" ]; then
    install -m 600 "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${TLS_DIR}/privkey.pem"
    install -m 644 "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${TLS_DIR}/fullchain.pem"
  else
    self_signed
  fi

  cat "${TLS_DIR}/fullchain.pem" "${TLS_DIR}/privkey.pem" > "${PEM}"
  chmod 600 "${PEM}"
}

# ------------------------------------------------------------------ layanan
setup_haproxy() {
  say "menyiapkan haproxy"
  [ -f /etc/haproxy/haproxy.cfg.bak ] || cp -a /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak 2>/dev/null || true
  sed "s|@PEM@|${PEM}|g" "${ASSETS}/haproxy.cfg" > /etc/haproxy/haproxy.cfg
  haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1 || die "konfigurasi haproxy tidak valid"
  ok "haproxy siap"
}

start_services() {
  say "menjalankan layanan"
  python3 /usr/local/sbin/xray-sync.py >/dev/null || die "gagal membuat config Xray"
  nginx -t >/dev/null 2>&1 || die "konfigurasi nginx tidak valid"

  systemctl daemon-reload
  # guard port API Xray harus aktif sebelum xray naik
  systemctl enable --now jnctunnel-apiguard >/dev/null 2>&1 || /usr/local/sbin/jnctunnel-apiguard || true
  systemctl enable --now dropbear >/dev/null 2>&1 || systemctl restart dropbear
  systemctl enable --now nginx >/dev/null 2>&1 || systemctl restart nginx
  systemctl enable --now jnctunnel-shim >/dev/null 2>&1 || systemctl restart jnctunnel-shim
  systemctl enable --now haproxy >/dev/null 2>&1 || systemctl restart haproxy
  systemctl enable --now jnctunnel-xray >/dev/null 2>&1 || systemctl restart jnctunnel-xray
  systemctl enable --now jnctunnel-sshws >/dev/null 2>&1 || systemctl restart jnctunnel-sshws
  systemctl enable --now jnctunnel-api >/dev/null 2>&1 || systemctl restart jnctunnel-api
  systemctl enable --now jnctunnel-expire.timer >/dev/null 2>&1 || true
  systemctl enable --now jnctunnel-backup.timer >/dev/null 2>&1 || true
  setup_udpgw
  ok "semua layanan aktif"
}

# Deteksi IP lokal VPS tanpa memanggil layanan luar (tidak ada paket keluar).
detect_public_ipv4() {
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
  [ -n "${ip}" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "${ip}"
}

summary() {
  local ip
  ip="$(detect_public_ipv4)"
  cat <<EOF

$(printf "${C_OK}")jnctunnel terpasang$(printf "${C_OFF}")

  Host / domain : ${DOMAIN:-${ip}}
  IP publik     : ${ip}
  SSH           : ${SSH_MAIN_PORT:-109} dan ${SSH_ALT_PORT:-143}
  SSH WS/TLS    : 443 path /ssh-ws
  VMess WS      : 443 path /vmess
  VLESS WS      : 443 path /vless
  Trojan WS     : 443 path /trojan
  HTTPUpgrade   : /upvmess /upvless /uptrojan
  gRPC          : /vmess-grpc /vless-grpc /trojan-grpc
  XHTTP         : /xhvless
  API akun      : http://127.0.0.1:${API_PORT:-8088}/vps/health (token di ${CONF_DIR}/config.env)
  Menu          : ketik "menu" atau "menu-jnctunnel"

  Tambah akun: menu > 1 (SSH) atau 3 (Xray)
  Status     : systemctl status jnctunnel-xray jnctunnel-sshws haproxy nginx dropbear
EOF
}

# --------------------------------------------------------------------- main
install_deps
install_udpgw || true
install_xray
write_configs
systemctl daemon-reload
setup_cert
systemctl enable --now nginx >/dev/null 2>&1 || systemctl restart nginx
setup_haproxy
start_services
summary
