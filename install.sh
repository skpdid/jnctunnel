#!/usr/bin/env bash
# jnctunnel - pemasang satu langkah
# Contoh:
#   bash install.sh --domain vpn.contoh.com --email admin@contoh.com
#   bash install.sh --yes            (pakai IP publik + sertifikat sendiri)
set -euo pipefail

REPO="${JNCTUNNEL_REPO:-https://github.com/skpdid/jnctunnel.git}"
BRANCH="${JNCTUNNEL_BRANCH:-main}"
SRC_DIR="/opt/jnctunnel-src"

[ "$(id -u)" -eq 0 ] || { echo "jalankan sebagai root"; exit 1; }

self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${self_dir}/jnctunnel.sh" ] && [ -d "${self_dir}/assets" ]; then
  work="${self_dir}"
  echo "[jnctunnel] memakai berkas lokal: ${work}"
else
  echo "[jnctunnel] mengunduh repo ${REPO} (${BRANCH})"
  command -v curl >/dev/null 2>&1 || {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl ca-certificates >/dev/null
  }
  slug="${REPO#https://github.com/}"
  slug="${slug%.git}"
  tmp="$(mktemp -d)"
  curl -4fsSL --max-time 120 "https://codeload.github.com/${slug}/tar.gz/refs/heads/${BRANCH}" \
    | tar -xz -C "${tmp}" || { echo "gagal mengunduh repo"; exit 1; }
  work="$(find "${tmp}" -maxdepth 1 -mindepth 1 -type d | head -1)"
  [ -n "${work}" ] || { echo "isi repo tidak dikenali"; exit 1; }
fi

exec bash "${work}/jnctunnel.sh" "$@"
