#!/usr/bin/env bash
# jnctunnel - menu CLI
# Kelola akun SSH dan Xray (VMess/VLESS/Trojan) tanpa API.
set -uo pipefail

CONF="${JNCT_CONF:-/etc/jnctunnel/config.env}"
ACC="${JNCT_ACC:-/etc/jnctunnel/accounts}"
APPLY="${JNCT_APPLY:-/usr/local/sbin/jnctunnel-apply}"
BACKUP="${JNCT_BACKUP_BIN:-/usr/local/sbin/jnctunnel-backup}"

# shellcheck disable=SC1090
[ -f "${CONF}" ] && . "${CONF}"
: "${DOMAIN:=}"
: "${DEFAULT_DAYS:=30}"

C_OK="\033[1;32m"; C_ERR="\033[1;31m"; C_WARN="\033[1;33m"; C_INFO="\033[1;36m"; C_OFF="\033[0m"

[ "$(id -u)" -eq 0 ] || { echo "jalankan sebagai root"; exit 1; }

hr()   { printf '%s\n' "------------------------------------------------------------"; }
pause(){ printf '\nTekan Enter untuk kembali...'; read -r _ || true; }
msg()  { printf "${C_OK}%s${C_OFF}\n" "$*"; }
warn() { printf "${C_WARN}%s${C_OFF}\n" "$*"; }
err()  { printf "${C_ERR}%s${C_OFF}\n" "$*"; }

# IP lokal VPS tanpa panggilan ke luar (ip route tidak mengirim paket).
local_ipv4() {
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
  [ -n "${ip}" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "${ip}"
}

server_host() {
  if [ -n "${DOMAIN}" ]; then echo "${DOMAIN}"; else local_ipv4; fi
}

days_to_epoch() { date -d "+$1 days" +%s 2>/dev/null || echo 0; }
epoch_to_date() {
  case "${1:-0}" in ""|0) echo "selamanya" ;; *) date -d "@$1" +%Y-%m-%d 2>/dev/null || echo "-" ;; esac
}

# Terapkan perubahan akun ke proses Xray yang sedang jalan.
# mode: add | renew (hot-add, tanpa putus) atau remove | sync (restart).
apply_change() {
  local mode="$1" proto="${2:-}" name="${3:-}" out
  if out="$(bash "${APPLY}" "${mode}" ${proto:+"${proto}"} ${name:+"${name}"} 2>&1)"; then
    case "${out}" in
      *"hot-add"*) printf "${C_OK}%s${C_OFF}\n" "${out}" ;;
    esac
    return 0
  fi
  err "gagal menerapkan config Xray: ${out}"
  return 1
}

ask_days() {
  local d
  printf "Masa aktif (hari) [%s]: " "${DEFAULT_DAYS}" >&2
  read -r d || true
  [ -n "${d}" ] || d="${DEFAULT_DAYS}"
  case "${d}" in *[!0-9]*|"") err "angka tidak valid"; return 1 ;; esac
  echo "${d}"
}

# ------------------------------------------------------------------ SSH
add_ssh() {
  hr; echo "TAMBAH AKUN SSH"; hr
  local user pass days
  printf "Username: "; read -r user || true
  [ -n "${user}" ] || { err "username kosong"; return; }
  id "${user}" >/dev/null 2>&1 && { err "user sudah ada"; return; }
  printf "Password (kosong = acak): "; read -r pass || true
  [ -n "${pass}" ] || pass="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10)"
  days="$(ask_days)" || return
  useradd -m -s /bin/bash "${user}" >/dev/null 2>&1 || { err "gagal membuat user"; return; }
  printf '%s:%s\n' "${user}" "${pass}" | chpasswd >/dev/null 2>&1 || { err "gagal set password"; return; }
  mkdir -p "${ACC}/ssh"
  echo "$(days_to_epoch "${days}")" > "${ACC}/ssh/${user}.exp"
  msg "akun SSH dibuat"
  printf "  host     : %s\n  port     : %s / %s\n  username : %s\n  password : %s\n  expired  : %s\n" \
    "$(server_host)" "${SSH_MAIN_PORT:-109}" "${SSH_ALT_PORT:-143}" "${user}" "${pass}" "$(epoch_to_date "$(days_to_epoch "${days}")")"
}

del_ssh() {
  hr; echo "HAPUS AKUN SSH"; hr
  local user
  printf "Username: "; read -r user || true
  [ -n "${user}" ] || return
  id "${user}" >/dev/null 2>&1 || { err "user tidak ada"; return; }
  pkill -KILL -u "${user}" 2>/dev/null || true
  userdel -r "${user}" >/dev/null 2>&1 || true
  rm -f "${ACC}/ssh/${user}.exp"
  msg "akun ${user} dihapus"
}

# ------------------------------------------------------------------ Xray
pick_proto() {
  {
    echo "Pilih protokol:"
    echo "  1) VMess"
    echo "  2) VLESS"
    echo "  3) Trojan"
    printf "Pilihan [1]: "
  } >&2
  read -r p || true
  case "${p:-1}" in
    1) echo vmess ;; 2) echo vless ;; 3) echo trojan ;; *) echo "" ;;
  esac
}

add_xray() {
  hr; echo "TAMBAH AKUN XRAY"; hr
  local proto name days uuid exp
  proto="$(pick_proto)"; [ -n "${proto}" ] || { err "pilihan salah"; return; }
  printf "Nama akun: "; read -r name || true
  [ -n "${name}" ] || { err "nama kosong"; return; }
  [ -f "${ACC}/xray/${proto}/${name}" ] && { err "akun sudah ada"; return; }
  days="$(ask_days)" || return
  uuid="$(cat /proc/sys/kernel/random/uuid)"
  exp="$(days_to_epoch "${days}")"
  mkdir -p "${ACC}/xray/${proto}"
  printf 'uuid=%s\nexp=%s\ncreated=%s\n' "${uuid}" "${exp}" "$(date +%s)" \
    > "${ACC}/xray/${proto}/${name}"
  apply_change add "${proto}" "${name}" || return
  msg "akun ${proto} dibuat"
  printf "  nama    : %s\n  uuid    : %s\n  expired : %s\n" "${name}" "${uuid}" "$(epoch_to_date "${exp}")"
  echo
  show_link "${proto}" "${name}" "${uuid}"
}

del_xray() {
  hr; echo "HAPUS AKUN XRAY"; hr
  local proto name
  proto="$(pick_proto)"; [ -n "${proto}" ] || return
  printf "Nama akun: "; read -r name || true
  [ -f "${ACC}/xray/${proto}/${name}" ] || { err "akun tidak ada"; return; }
  rm -f "${ACC}/xray/${proto}/${name}"
  apply_change remove "${proto}" "${name}" && msg "akun ${proto}/${name} dihapus"
}

# ------------------------------------------------------------------ daftar
list_all() {
  hr; echo "DAFTAR AKUN"; hr
  echo "SSH:"
  local found=0 f u e
  for f in "${ACC}"/ssh/*.exp; do
    [ -e "${f}" ] || continue
    u="$(basename "${f}" .exp)"; e="$(tr -cd '0-9' < "${f}")"
    printf "  %-16s expired %s\n" "${u}" "$(epoch_to_date "${e}")"
    found=1
  done
  [ "${found}" = 1 ] || echo "  (kosong)"
  for proto in vmess vless trojan; do
    echo "${proto^^}:"
    found=0
    for f in "${ACC}/xray/${proto}"/*; do
      [ -f "${f}" ] || continue
      u="$(basename "${f}")"
      e="$(awk -F= '$1=="exp"{print $2}' "${f}")"
      printf "  %-16s expired %s\n" "${u}" "$(epoch_to_date "${e:-0}")"
      found=1
    done
    [ "${found}" = 1 ] || echo "  (kosong)"
  done
}

# ------------------------------------------------------------------ renew
renew() {
  hr; echo "PERPANJANG AKUN"; hr
  echo "  1) SSH"
  echo "  2) Xray"
  printf "Pilihan [1]: "; read -r t || true
  local name days
  if [ "${t:-1}" = "2" ]; then
    local proto
    proto="$(pick_proto)"; [ -n "${proto}" ] || return
    printf "Nama akun: "; read -r name || true
    [ -f "${ACC}/xray/${proto}/${name}" ] || { err "akun tidak ada"; return; }
    days="$(ask_days)" || return
    sed -i "s/^exp=.*/exp=$(days_to_epoch "${days}")/" "${ACC}/xray/${proto}/${name}"
    apply_change renew "${proto}" "${name}" && msg "akun ${proto}/${name} diperpanjang sampai $(epoch_to_date "$(days_to_epoch "${days}")")"
  else
    printf "Username: "; read -r name || true
    [ -f "${ACC}/ssh/${name}.exp" ] || { err "akun tidak ada"; return; }
    days="$(ask_days)" || return
    echo "$(days_to_epoch "${days}")" > "${ACC}/ssh/${name}.exp"
    chage -E "$(date -d "+${days} days" +%Y-%m-%d)" "${name}" 2>/dev/null || true
    msg "akun ${name} diperpanjang sampai $(epoch_to_date "$(days_to_epoch "${days}")")"
  fi
}

# ------------------------------------------------------------------ link
show_link() {
  local proto="$1" name="$2" uuid="${3:-}" host
  [ -n "${uuid}" ] || uuid="$(awk -F= '$1=="uuid"{print $2}' "${ACC}/xray/${proto}/${name}" 2>/dev/null)"
  host="$(server_host)"
  case "${proto}" in
    vmess)
      python3 - "$name" "${host}" "${uuid}" <<'PY'
import base64, json, sys
name, host, uuid = sys.argv[1:4]
data = {
    "v": "2", "ps": name, "add": host, "port": "443", "id": uuid,
    "aid": "0", "scy": "auto", "net": "ws", "type": "none",
    "host": host, "path": "/vmess", "tls": "tls", "sni": host,
}
print("vmess://" + base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode())
PY
      ;;
    vless)
      echo "vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2Fvless#${name}"
      ;;
    trojan)
      echo "trojan://${uuid}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2Ftrojan#${name}"
      ;;
  esac
}

link_menu() {
  hr; echo "LINK KONEKSI"; hr
  local proto name
  proto="$(pick_proto)"; [ -n "${proto}" ] || return
  printf "Nama akun: "; read -r name || true
  [ -f "${ACC}/xray/${proto}/${name}" ] || { err "akun tidak ada"; return; }
  show_link "${proto}" "${name}"
}

# ------------------------------------------------------------------ lain
online() {
  hr; echo "USER SSH ONLINE"; hr
  who 2>/dev/null | awk '{print $1, $2, $5}' | sort -u
  echo
  echo "Koneksi ke port SSH:"
  ss -tn state established 2>/dev/null | awk -v p1="${SSH_MAIN_PORT:-109}" -v p2="${SSH_ALT_PORT:-143}" \
    'NR>1 && ($3 ~ ":"p1"$" || $3 ~ ":"p2"$") {print "  " $4 " <- " $5}'
}

restart_all() {
  hr; echo "RESTART LAYANAN"; hr
  for s in dropbear nginx haproxy jnctunnel-apiguard jnctunnel-xray jnctunnel-sshws jnctunnel-api \
           jnctunnel-udpgw@7200 jnctunnel-udpgw@7300; do
    if systemctl restart "${s}" 2>/dev/null; then msg "${s} ok"; else err "${s} gagal"; fi
  done
}

status_all() {
  hr; echo "STATUS LAYANAN"; hr
  local st
  for s in dropbear nginx haproxy jnctunnel-apiguard jnctunnel-xray jnctunnel-sshws \
           jnctunnel-api jnctunnel-udpgw@7200 jnctunnel-udpgw@7300 \
           jnctunnel-expire.timer jnctunnel-backup.timer; do
    st="$(systemctl is-active "${s}" 2>/dev/null)"
    printf "  %-22s %s\n" "${s}" "${st:-unknown}"
  done
}

backup_now() {
  hr; echo "BACKUP KONFIGURASI"; hr
  bash "${BACKUP}" backup || err "backup gagal"
}

backup_list() {
  hr; echo "DAFTAR BACKUP"; hr
  bash "${BACKUP}" list
}

show_token() {
  hr; echo "TOKEN API"; hr
  printf "  %s\n" "${API_AUTH_TOKEN:-(belum diset)}"
  echo
  echo "  Endpoint : http://127.0.0.1:${API_PORT:-8088}/vps/health"
  echo "  Header   : Authorization: Bearer <token>"
}

# ------------------------------------------------------------------ main
while true; do
  clear 2>/dev/null || true
  printf "${C_INFO}"
  cat <<'BANNER'
============================================================
                     jnctunnel
             SSH + Xray (VMess / VLESS / Trojan)
============================================================
BANNER
  printf "${C_OFF}"
  printf "  %-28s %s\n" "1) Tambah akun SSH" "5) Daftar akun"
  printf "  %-28s %s\n" "2) Hapus akun SSH" "6) Perpanjang akun"
  printf "  %-28s %s\n" "3) Tambah akun Xray" "7) Link koneksi"
  printf "  %-28s %s\n" "4) Hapus akun Xray" "8) User SSH online"
  printf "  %-28s %s\n" "9) Restart layanan" "10) Status layanan"
  printf "  %-28s %s\n" "11) Backup sekarang" "12) Daftar backup"
  printf "  %-28s %s\n" "13) Token API" ""
  printf "  %-28s %s\n" "0) Keluar" ""
  hr
  printf "Pilihan: "
  read -r choice || break
  case "${choice}" in
    1) add_ssh; pause ;;
    2) del_ssh; pause ;;
    3) add_xray; pause ;;
    4) del_xray; pause ;;
    5) list_all; pause ;;
    6) renew; pause ;;
    7) link_menu; pause ;;
    8) online; pause ;;
    9) restart_all; pause ;;
    10) status_all; pause ;;
    11) backup_now; pause ;;
    12) backup_list; pause ;;
    13) show_token; pause ;;
    0|q|Q) break ;;
    *) ;;
  esac
done
