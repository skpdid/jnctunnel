# Inti dukungan "HTTP upgrade + payload"

Ada empat bagian yang harus ada. Kalau salah satu hilang, klien ber-payload akan
selalu berakhir `301`/`400` walau akun, UUID, dan path benar.

## 1. Inbound Xray: HTTPUpgrade tanpa `host`

```json
{
  "tag": "vmess-up",
  "listen": "127.0.0.1",
  "port": 10004,
  "protocol": "vmess",
  "settings": { "clients": [] },
  "streamSettings": {
    "network": "httpupgrade",
    "httpupgradeSettings": { "path": "/upvmess" }
  }
}
```

Jangan isi `host`. Kalau diisi, Xray menolak request yang header `Host`-nya beda
(pakai IP, bug host, atau Host dari payload). Cukup `path`.

Xray hanya mau `GET <path>` + `Connection: Upgrade` + `Upgrade: websocket`.
Method `PATCH` atau request umpan di depannya akan ditolak 400.

## 2. Routing: port 80/443 masuk ke shim, bukan nginx

nginx mem-parse HTTP. Begitu request umpan masuk, nginx menjawab sendiri dan
request kedua (yang ber-`Upgrade`) tidak pernah sampai ke Xray. Karena itu
trafik HTTP harus masuk ke shim dulu (TCP mentah), baru shim memutuskan.

haproxy contoh (TLS dilepas di sini, jadi shim melihat HTTP polos):

```haproxy
frontend ft_tls
    bind *:443 ssl crt /etc/jnctunnel/tls/jnctunnel.pem alpn h2,http/1.1
    tcp-request inspect-delay 5s
    tcp-request content accept if HTTP
    acl is_h2      req.payload(0,14) -m str "PRI * HTTP/2.0"
    acl is_connect req.payload(0,8)  -m str "CONNECT "
    use_backend bk_grpc  if is_h2
    use_backend bk_sshws if is_connect
    default_backend bk_shim

frontend ft_http
    bind *:80
    default_backend bk_shim

backend bk_shim
    server shim 127.0.0.1:10007 send-proxy
```

Kalau autoscript Anda memakai nginx langsung di port 80, pindahkan nginx ke
`127.0.0.1:8083 proxy_protocol` dan pasang haproxy (atau shim) di depan.

## 3. Shim: bagian yang benar-benar "menerjemahkan"

`payload-shim-standalone.py` melakukan ini per koneksi:

1. baca request satu per satu;
2. request umpan (tanpa `Upgrade`) diteruskan ke nginx → klien tetap dapat
   `301` seperti biasa, koneksi tidak ditutup;
3. request ber-`Upgrade` (atau `PATCH`/`PUT` — penanda payload umum, walau
   proxy di depan membuang header `Upgrade`) → mode tunnel;
4. kirim ulang sebagai `GET <path>` bersih ke inbound Xray;
5. teruskan `101` apa adanya, lalu buang **satu** penanda `HTTP/ 69\r\n\r\n`
   di awal stream sebelum data diteruskan;
6. request non-tunnel (API, ACME) diteruskan ke nginx.

Jalankan:

```bash
python3 payload-shim-standalone.py \
    --listen 127.0.0.1:10007 \
    --route /upvmess=127.0.0.1:10004 \
    --route /upvless=127.0.0.1:10005 \
    --route /uptrojan=127.0.0.1:10006 \
    --default /upvmess \
    --fallback 127.0.0.1:8083 \
    --proxy-protocol
```

`--default` penting: payload yang memakai `PATCH /` (path `/`) diarahkan ke
`/upvmess`. Kalau klien Anda VLESS/Trojan, ganti ke `/upvless` / `/uptrojan`.

Unit systemd:

```ini
[Unit]
Description=payload shim
After=network-online.target
Before=haproxy.service

[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/payload-shim.py --listen 127.0.0.1:10007 \
  --route /upvmess=127.0.0.1:10004 --default /upvmess --fallback 127.0.0.1:8083 --proxy-protocol
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

## 4. Payload di sisi klien

```
GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]
PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]
[split]HTTP/ 69[crlf][crlf]
```

- Bagian sebelum `[split]` = request umpan + request upgrade.
- Bagian sesudah `[split]` dikirim setelah handshake; di sinilah `HTTP/ 69`
  berada dan harus dibuang shim (kalau tidak, server membacanya sebagai
  request rusak → `400`).

## Tes cepat (tanpa aplikasi)

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

Harus `HTTP/1.1 301` lalu `HTTP/1.1 101 Switching Protocols`.

## Catatan

- `HTTPUpgrade` mengirim data mentah setelah `101`. Proxy/CDN yang hanya
  meneruskan WebSocket asli (mis. Cloudflare Worker) bisa memutus di titik itu.
  Kalau begitu, ganti `network` klien ke `ws` dengan `path` yang sesuai — shim
  ini juga menangani path WS (`/vmess`, `/vless`, `/trojan`).
- Shim tidak melakukan autentikasi; autentikasi tetap di Xray (UUID/password).
- Jangan taruh shim di belakang nginx: nginx akan menelan request umpan.
