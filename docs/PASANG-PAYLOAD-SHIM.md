# Memasang dukungan "HTTP upgrade + payload" di autoscript lain

Target: `wsxd.conf` (nginx `127.0.0.1:10100` HTTP/1.1 + `10200` h2/gRPC) dan
Xray dengan inbound `*-upgrade` di port 20013-20016.

## Kenapa konfigurasi sekarang belum bisa

Tiga hal di `wsxd.conf` memblokir klien ber-payload:

1. **Path payload (`PATCH /`) tidak pernah masuk ke inbound Xray.**
   `location ~ /` menangkap semua path `/`, jadi `PATCH /` diteruskan ke
   `127.0.0.1:10015`, bukan ke `20014`. Inbound `*-upgrade` hanya tercapai kalau
   path-nya persis `/vmess-upgrade` dst.

2. **Tidak ada yang membuang `HTTP/ 69` setelah `101`.**
   Klien mengirim penanda itu setelah handshake (`[split]`). nginx meneruskan
   byte apa adanya, sehingga Xray membacanya sebagai awal frame VMess/VLESS →
   auth gagal, koneksi ditutup. Ini yang tidak bisa diselesaikan nginx.

3. **Request umpan (`GET /`) harus dijawab ramah.**
   Kalau `location ~ /` → `10015` menjawab `400`, klien berhenti sebelum sempat
   mengirim `PATCH`. Harus `200`/`301`/`302`.

Kesimpulan: Xray sudah benar (path saja, tanpa `host`), nginx tidak bisa
menggantikan shim. Perlu satu proses TCP mentah di antara pintu masuk dan Xray.

## Alur yang dituju

```
klien --80/443--> haproxy --> shim:10007 --> Xray 20013-20016   (jalur tunnel)
                                  |
                                  +---------> nginx:10100 --> 10015 (umpan/API)
```

Shim hanya butuh satu port masuk (10007). Semua keputusan (umpan vs tunnel)
dilakukan di sana.

## Langkah 1 - pasang shim

```bash
install -m 755 payload-shim-standalone.py /usr/local/sbin/payload-shim.py
```

`/etc/systemd/system/payload-shim.service`:

```ini
[Unit]
Description=payload shim (HTTP upgrade + payload)
After=network-online.target
Before=haproxy.service

[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/payload-shim.py \
  --listen 127.0.0.1:10007 \
  --route /vmess-upgrade=127.0.0.1:20014 \
  --route /vless-upgrade=127.0.0.1:20013 \
  --route /trojan-upgrade=127.0.0.1:20015 \
  --route /shadowsocks-upgrade=127.0.0.1:20016 \
  --route /vmess=127.0.0.1:20002 \
  --route /vless=127.0.0.1:20001 \
  --route /trojan=127.0.0.1:20003 \
  --route /shadowsocks=127.0.0.1:20004 \
  --default /vmess-upgrade \
  --fallback 127.0.0.1:10100 \
  --proxy-protocol
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now payload-shim
```

Catatan: `--fallback 10100` memakai `--proxy-protocol` karena nginx Anda
`listen 127.0.0.1:10100 proxy_protocol`. Shim akan mengirim header PROXY v1
ke nginx, sama seperti haproxy sekarang.

Kalau klien Anda VLESS, ganti `--default /vless-upgrade`; Trojan →
`/trojan-upgrade`.

## Langkah 2 - haproxy mengarahkan HTTP/1.1 ke shim

Bagian yang sekarang meneruskan ke `127.0.0.1:10100` diganti ke `10007`:

```haproxy
backend bk_http
    server shim 127.0.0.1:10007 send-proxy
```

Yang **tidak** berubah:

- `bk_grpc` → `127.0.0.1:10200 send-proxy` (HTTP/2, ACL `PRI * HTTP/2.0`)
- SSH-WS / CONNECT → port sshws Anda
- TLS termination tetap di haproxy (`bind *:443 ssl crt ...`), karena shim
  bekerja pada HTTP polos.

Kalau port 80 dipegang nginx langsung (bukan haproxy), pindahkan nginx ke
`127.0.0.1:10100` (sudah begitu) dan pasang haproxy/stream di :80 → shim.

## Langkah 3 - nginx: dua penyesuaian kecil

`10100` tetap dipakai sebagai fallback, jadi blok `location` yang ada boleh
dibiarkan. Yang perlu dirapikan:

1. **Catch-all jangan menjawab 400.** Kalau `10015` bukan situs umpan yang ramah,
   ganti:

   ```nginx
   location = / {
       return 301 https://$host$request_uri;
   }
   ```

2. **Perbaiki regex yang saling menimpa.** `location ~ /vmess` juga cocok untuk
   `/vmess-upgrade`; sekarang selamat karena urutannya, tapi rapuh. Pakai
   pencocokan pasti:

   ```nginx
   location = /vmess-upgrade   { proxy_pass http://127.0.0.1:20014; ... }
   location = /vless-upgrade   { proxy_pass http://127.0.0.1:20013; ... }
   location = /trojan-upgrade  { proxy_pass http://127.0.0.1:20015; ... }
   location = /shadowsocks-upgrade { proxy_pass http://127.0.0.1:20016; ... }
   ```

   Blok ini sebenarnya tidak lagi dilewati jalur tunnel (shim yang menangani),
   tapi berguna kalau ada klien tanpa payload.

Jangan lupa `proxy_http_version 1.1` + `Upgrade`/`Connection` tetap ada untuk
klien WS tanpa payload.

## Langkah 4 - payload di klien

```
GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]
PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]
[split]HTTP/ 69[crlf][crlf]
```

Path Xray di aplikasi: `/vmess-upgrade` (sesuai inbound 20014), network
`httpupgrade`, security `none`.

`PATCH /` boleh tetap `/` - shim yang mengarahkan ke `--default`.

## Langkah 5 - tes tanpa aplikasi

```bash
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(b"GET / HTTP/1.1\r\nHost: bug.example\r\n\r\n"
          b"PATCH / HTTP/1.1\r\nHost: vpn.contoh.com\r\nUpgrade: websocket\r\n\r\n"
          b"HTTP/ 69\r\n\r\n")
s.settimeout(4)
print(s.recv(300))
PY
```

Harus `301` (umpan) lalu `101 Switching Protocols` (Xray).

Cek juga SSH-WS tidak ikut rusak:

```bash
curl -sS -m 3 -o /dev/null -w '%{http_code}\n' \
  -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
  http://127.0.0.1/ssh-ws
```

Kalau port SSH-WS Anda bukan `/ssh-ws`, tambahkan `--route /path-nya=127.0.0.1:PORT_SSHWS`.

## Ringkasan yang berubah

| Komponen | Perubahan |
|---|---|
| Xray `config.json` | tidak ada (sudah path saja) |
| shim | baru, port 10007 |
| haproxy | backend HTTP/1.1 → 10007 |
| nginx `wsxd.conf` | catch-all jadi 301, location `=` untuk path upgrade |
| klien | payload + `[split]HTTP/ 69`, path `/vmess-upgrade` |
