# Detail konfigurasi jnctunnel

## 1. Peran tiap komponen

| Komponen | Berkas | Tugas |
|---|---|---|
| haproxy | `/etc/haproxy/haproxy.cfg` | Menerima TLS 443, memilah trafik berdasarkan byte pertama |
| nginx | `/etc/nginx/sites-available/jnctunnel.conf` | HTTP/1.1 + WS di 8083, HTTP/2 + gRPC di 8081, ACME di 80 |
| dropbear | `/etc/default/dropbear` | SSH port 109 dan 143 |
| sshws.py | `/usr/local/sbin/sshws.py` | Jembatan SSH ↔ WebSocket/CONNECT di 2082 |
| Xray | `/usr/local/bin/xray` + `/usr/local/etc/xray/config.json` | 10 inbound, semua di 127.0.0.1 |
| xray-sync.py | `/usr/local/sbin/xray-sync.py` | Menyusun ulang config dari akun |
| menu | `/usr/local/sbin/menu-jnctunnel` | CRUD akun |
| jnctunnel-expire | `/usr/local/sbin/jnctunnel-expire` | Hapus akun kedaluwarsa |

## 2. Pemilahan di haproxy

haproxy tidak memakai SNI atau Host, cukup isi paket pertama:

| Kondisi | Backend |
|---|---|
| 14 byte pertama `PRI * HTTP/2.0` | nginx 8081 (gRPC) |
| 8 byte pertama `CONNECT ` | sshws 2082 |
| diawali metode HTTP (GET/POST/…) | nginx 8083 |
| sisanya (banner `SSH-2.0-…`) | sshws 2082 |

Semua backend memakai `send-proxy`, jadi nginx dan sshws menerima header
`PROXY TCP4 …` dan IP klien asli tidak hilang.

## 3. Path nginx

| Path | Tujuan |
|---|---|
| `/vmess` `/vless` `/trojan` | Xray WS 10001-10003 |
| `/upvmess` `/upvless` `/uptrojan` | Xray HTTPUpgrade 10004-10006 |
| `/xhvless` | Xray XHTTP 12002 |
| `/ssh-ws` `/ws` `/ws-ssh` `/ssh` | sshws 2082 |
| `/` (fallback) | sshws 2082 |
| `/vmess-grpc` `/vless-grpc` `/trojan-grpc` | Xray gRPC 11001-11003 (di listener 8081) |

Tidak ada path `/vps/` — jnctunnel tidak menyediakan API HTTP.

## 4. Penyimpanan akun

```
/etc/jnctunnel/accounts/ssh/<user>.exp        isi: epoch kedaluwarsa
/etc/jnctunnel/accounts/xray/<proto>/<nama>   isi: uuid=, exp=, created=
```

`xray-sync.py` membaca folder itu, membuang akun yang `exp` sudah lewat,
lalu menulis `/usr/local/etc/xray/config.json`. Sebelum menimpa, config diuji
dengan `xray -test`; kalau gagal, file lama dipertahankan.

Client per protokol:

- VMess: `{"id": uuid, "email": nama, "alterId": 0}`
- VLESS: `{"id": uuid, "email": nama, "flow": ""}`
- Trojan: `{"password": uuid, "email": nama}`

## 5. Sertifikat

1. Domain + email diisi → `certbot certonly --webroot` (port 80 harus bisa
   diakses dari internet dan DNS domain sudah mengarah ke VPS).
2. Domain = IP atau kosong → sertifikat sendiri 10 tahun (SAN IP/DNS).
3. Hasil digabung jadi `/etc/jnctunnel/tls/jnctunnel.pem` (fullchain + privkey)
   dan dipakai haproxy sebagai `crt`.

Perpanjangan Let's Encrypt mengikuti timer certbot bawaan; setelah renew,
jalankan `systemctl restart haproxy` (atau tambahkan hook deploy yang menyalin
PEM lalu restart).

## 6. Perintah harian

```bash
menu                                  # kelola akun
systemctl status jnctunnel-xray jnctunnel-sshws haproxy nginx dropbear
journalctl -u jnctunnel-xray -n 50    # log Xray
journalctl -u jnctunnel-sshws -n 50   # log jembatan SSH
python3 /usr/local/sbin/xray-sync.py  # bangun ulang config Xray
/usr/local/sbin/jnctunnel-expire      # jalankan pembersihan manual
```

## 7. Menambah protokol lain

1. Tambahkan inbound baru di `/etc/jnctunnel/xray.base.json` (listen 127.0.0.1).
2. Tambahkan `location` yang sesuai di vhost nginx.
3. Jalankan `python3 /usr/local/sbin/xray-sync.py && systemctl restart jnctunnel-xray`.

## 8. Tidak ada panggilan keluar setelah terpasang

- Tidak ada lisensi/lease/aktivasi, tidak ada kunci atau tanda tangan vendor.
- Tidak ada heartbeat, callback instalasi, atau notifikasi ke pihak mana pun.
- Tidak ada unit/timer yang menghubungi internet; `jnctunnel-expire` hanya
  membaca `/etc/jnctunnel/accounts`.
- IP server ditampilkan dari `ip -4 route get` (lokal, tanpa paket keluar).

## 9. Yang sengaja tidak ada

- Lisensi / lease / kill switch
- Update paksa dari server luar (god mode)
- API HTTP untuk bot, panel web, backup otomatis, SlowDNS, UDP Custom/ZIVPN
- Telemetri apa pun
