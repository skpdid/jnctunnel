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

## 6. Hot-add user (tanpa memutus pengguna lain)

Xray tidak punya reload config, jadi perubahan daftar user biasanya berarti
restart dan semua sesi VMess/VLESS/Trojan putus. `jnctunnel-apply` menghindari
itu untuk penambahan:

1. Tulis file akun, lalu `xray-sync.py` membangun ulang `config.json`.
2. Bandingkan hash config sebelum/sesudah. **Sama → layanan tidak disentuh.**
3. Bila berubah dan mode `add`/`renew`: panggil
   `xray api adu --server=127.0.0.1:10085` untuk user itu saja.
4. Hitung balasan `Added N user(s) in total`. Harus sama dengan jumlah inbound
   protokol itu (VMess 3, VLESS 4, Trojan 3). Kalau tidak → fallback restart.
5. Mode `remove` selalu restart, supaya sesi user yang dicabut benar-benar mati.

Pengaman: `HandlerService` hanya dipakai kalau rule iptables

```
OUTPUT -o lo -p tcp -d 127.0.0.1 --dport 10085 -m owner ! --uid-owner 0 \
  -j REJECT --reject-with tcp-reset
```

terpasang **dan** Xray berjalan sebagai `nobody`. Tanpa itu, `jnctunnel-apply`
langsung restart (perilaku aman).

## 7. API akun

`jnctunnel-api.py` (Python stdlib) listen di `127.0.0.1:8088`, dipublikasikan
nginx lewat `location /vps/`. Token `API_AUTH_TOKEN` dibuat otomatis saat
install (`openssl rand -hex 24`) dan disimpan di `/etc/jnctunnel/config.env`.

- `/vps/health` tanpa token; sisanya wajib `Authorization: Bearer <token>`
  atau `X-API-Key`.
- Username divalidasi `^[a-z0-9][a-z0-9_-]{1,19}$`.
- Masa aktif dibatasi 1-3650 hari.
- Aksi tulis memanggil `jnctunnel-apply`, jadi aturan hot-add di atas berlaku.

## 8. Backup

`jnctunnel-backup` mencadangkan `/etc/jnctunnel`, config Xray, vhost nginx, dan
`haproxy.cfg` ke `/var/backups/jnctunnel` (mode 600, simpan 7 arsip terakhir).
Timer harian 03:30. Restore otomatis membuat arsip pengaman dulu, lalu memuat
ulang layanan.

## 9. Payload shim

`jnctunnel-shim.py` menerima seluruh trafik HTTP dari haproxy (port 80 dan 443
setelah TLS dilepas) dan memutuskan:

| Isi stream | Aksi |
|---|---|
| ada request `Upgrade: websocket` (method apa pun) | mode tunnel → `GET <path>` ke inbound Xray |
| request biasa (API `/vps/`, ACME, 404) | diteruskan apa adanya ke nginx 8083 |
| tidak ada data / bukan HTTP | koneksi ditutup |

Detail penting:

- Request umpan (`GET /` tanpa upgrade) dilewati; shim menunggu sampai 1,5
  detik untuk request kedua sebelum memutuskan meneruskan ke nginx.
- Method `PATCH`/`POST` diterima lalu dinormalisasi menjadi `GET` karena Xray
  hanya menerima GET pada transport HTTPUpgrade/WS.
- Penanda `HTTP/ 69\r\n\r\n` dibuang satu kali tepat setelah respons 101.
- IP klien dari PROXY protocol diteruskan ulang ke nginx dalam bentuk PROXY v1.
- nginx tidak lagi memegang port 80; ACME dilayani di blok 8083 dan certbot
  memakai `--standalone` saat instalasi (haproxy/nginx dilepas sementara).

## 10. udpgw (badvpn)

`jnctunnel-udpgw@<port>.service` adalah unit template; dua instance aktif:
`7200` dan `7300` (`UDPGW_PORTS` di `config.env`). ExecStart:

```
/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:<port> \
  --max-clients 256 --max-connections-for-client 32 \
  --client-socket-sndbuf 1048576 --loglevel none
```

- Listen di semua interface karena klien menyambung langsung ke port itu.
  Batasi lewat firewall kalau hanya ingin dipakai dari jaringan tertentu.
- Biner dicari di `/usr/bin`, `/usr/sbin`, `/usr/local/bin`; kalau tidak ada,
  installer build dari `github.com/ambrop72/badvpn` dengan
  `-DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DCMAKE_C_FLAGS=-fcommon`.
- Tambah port lain: `systemctl enable --now jnctunnel-udpgw@7500`.
- Tidak ada autentikasi di udpgw (memang begitu desain badvpn); siapa pun yang
  bisa menjangkau port itu bisa memakainya sebagai gateway UDP.

## 11. Perintah harian

```bash
menu                                  # kelola akun
systemctl status jnctunnel-xray jnctunnel-sshws haproxy nginx dropbear
journalctl -u jnctunnel-xray -n 50    # log Xray
journalctl -u jnctunnel-sshws -n 50   # log jembatan SSH
python3 /usr/local/sbin/xray-sync.py        # bangun ulang config Xray
jnctunnel-apply add vmess budi              # tambah user tanpa restart
jnctunnel-apply remove vmess budi           # hapus user (restart)
jnctunnel-backup backup                     # backup manual
jnctunnel-backup list                       # daftar arsip
jnctunnel-apiguard                          # pasang ulang rule pengaman
systemctl status jnctunnel-udpgw@7200       # status udpgw
systemctl status jnctunnel-shim             # status payload shim
/usr/local/sbin/jnctunnel-expire            # pembersihan manual
```

## 12. Menambah protokol lain

1. Tambahkan inbound baru di `/etc/jnctunnel/xray.base.json` (listen 127.0.0.1).
2. Tambahkan `location` yang sesuai di vhost nginx.
3. Jalankan `python3 /usr/local/sbin/xray-sync.py && systemctl restart jnctunnel-xray`.

## 13. Tidak ada panggilan keluar setelah terpasang

- Tidak ada lisensi/lease/aktivasi, tidak ada kunci atau tanda tangan vendor.
- Tidak ada heartbeat, callback instalasi, atau notifikasi ke pihak mana pun.
- Tidak ada unit/timer yang menghubungi internet; `jnctunnel-expire` hanya
  membaca `/etc/jnctunnel/accounts`.
- IP server ditampilkan dari `ip -4 route get` (lokal, tanpa paket keluar).

## 14. Yang sengaja tidak ada

- Lisensi / lease / kill switch
- Update paksa dari server luar (god mode)
- Panel web, bot Telegram bawaan, SlowDNS, UDP Custom/ZIVPN, kuota/limit-IP
  (udpgw badvpn sudah ada)
- Lisensi, heartbeat, telemetri, update paksa dari luar
