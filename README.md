# jnctunnel

Skrip tunnel sederhana: **SSH** (dropbear + SSH-over-WebSocket) dan **Xray**
(VMess / VLESS / Trojan via WebSocket, HTTPUpgrade, gRPC, dan XHTTP) di satu
port TLS 443. Tanpa lisensi, tanpa panggilan ke server pihak lain, tanpa panel
berat — semua kode bisa dibaca dalam beberapa menit.

## Fitur

- **SSH** port 109 dan 143 (dropbear), plus SSH-over-WebSocket di `/ssh-ws`
- **Xray** satu port 443:
  - WS: `/vmess`, `/vless`, `/trojan`
  - HTTPUpgrade: `/upvmess`, `/upvless`, `/uptrojan`
  - gRPC: `/vmess-grpc`, `/vless-grpc`, `/trojan-grpc`
  - XHTTP: `/xhvless`
- **TLS** di haproxy (Let's Encrypt bila domain + email diisi, kalau tidak
  sertifikat sendiri), nginx sebagai backend HTTP
- **Menu CLI** untuk tambah/hapus/perpanjang akun, daftar akun, link koneksi,
  cek user online, restart & status layanan
- **Kedaluwarsa otomatis** lewat systemd timer 5 menit
- **Uninstaller** yang mengembalikan konfigurasi nginx/haproxy

## Pemasangan

```bash
bash install.sh --domain vpn.contoh.com --email admin@contoh.com
```

Tanpa domain (pakai IP publik + sertifikat sendiri):

```bash
bash install.sh --yes
```

Setelah selesai, jalankan `menu`.

## Peta port

| Port | Layanan | Keterangan |
|---|---|---|
| 80 | nginx | ACME + redirect ke HTTPS |
| 443 | haproxy | TLS, pemilah trafik |
| 109, 143 | dropbear | SSH langsung |
| 2082 | sshws.py | SSH-over-WS (lokal) |
| 8083 | nginx | HTTP/1.1 + WS (lokal, proxy_protocol) |
| 8081 | nginx | HTTP/2 + gRPC (lokal, proxy_protocol) |
| 10001-10003 | Xray | WS VMess/VLESS/Trojan |
| 10004-10006 | Xray | HTTPUpgrade |
| 11001-11003 | Xray | gRPC |
| 12002 | Xray | XHTTP |

Semua port 2082/8083/8081/10001-12002 hanya listen di `127.0.0.1`.

## Struktur repo

```
install.sh                 pemasang satu langkah (unduh repo lalu jalankan)
jnctunnel.sh               installer utama
menu.sh                    menu CLI
jnctunnel-expire           pembersih akun kedaluwarsa (timer)
uninstall.sh               pelepas layanan
assets/
  nginx-jnctunnel.conf     vhost nginx
  haproxy.cfg              TLS + pemilah trafik
  xray.base.json           template inbound Xray
  xray-sync.py             pembangun config dari akun
  sshws.py                 jembatan SSH-over-WS (stdlib Python)
  config.env               konfigurasi utama (/etc/jnctunnel/config.env)
  banner.txt               banner SSH
  systemd/                 unit & timer
docs/CONFIG.md             detail alur dan cara kerja
```

## Alur trafik

```
client :443 ─ haproxy (TLS)
   ├─ "PRI * HTTP/2.0" ─ nginx :8081 ─ gRPC Xray 11001-11003
   ├─ "CONNECT ..."    ─ sshws :2082 ─ dropbear 109
   ├─ HTTP biasa       ─ nginx :8083 ─ /vmess /vless /trojan /up* /xhvless
   │                                └─ /ssh-ws ─ sshws :2082
   └─ lainnya (SSH)    ─ sshws :2082 ─ dropbear 109
client :109 / :143 ─ dropbear
```

## Keamanan & batasan

- Tidak ada lisensi, tidak ada heartbeat, tidak ada update paksa dari server luar.
- Tidak ada API HTTP publik: akun dikelola dari menu (root).
- Sertifikat sendiri hanya untuk uji coba; klien akan memperingatkan TLS.
- Tidak mengatur firewall. Buka port 80, 443, 109, 143 di firewall/panel VPS.
- Root login SSH tidak diubah — pastikan kredensial root kuat.

## Pengujian

```bash
bash -n install.sh jnctunnel.sh menu.sh uninstall.sh jnctunnel-expire
python3 tests/test_sshws.py        # raw SSH, PROXY v1, WS, CONNECT, HTTP ditolak
python3 -c "import json;json.load(open('assets/xray.base.json'))"
```

## Lisensi

MIT.
