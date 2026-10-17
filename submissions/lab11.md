# Lab 11 — Edge Hardening with a Reverse Proxy

Branch: `feature/lab11`. Executed on 2026-10-16. Task 1, Task 2 and the bonus
are all done.

| Component | Version | How it ran |
| --- | --- | --- |
| nginx | **1.30.6**, built with OpenSSL 3.5.8, running with **OpenSSL 3.5.9** | `nginx:stable-alpine`, ports 80 and 443 |
| Juice Shop | **20.0.0** | `bkimminich/juice-shop:v20.0.0`, `expose: 3000` only |
| testssl.sh | **3.2.4** (own OpenSSL 1.0.2-bad, so it can still speak SSLv3 to TLS 1.1) | `drwetter/testssl.sh:3.2 --network host` |
| WAF | **ModSecurity v3.0.17**, ModSecurity-nginx v1.0.4, **OWASP CRS 4.30.0** (858 rules loaded) | `owasp/modsecurity-crs:4.30.0-nginx-alpine-202610051210`, port 8443 |
| Headless browser | Chromium 124 | `zenika/alpine-chrome:124` on the compose network |
| Client side | OpenSSL 3.2.1 (Git for Windows), curl 8.7.1, Python 3.11 | Windows 11 host |
| Docker | Engine 29.7.2, Compose 5.5.1 | Docker Desktop (WSL2) |

Deliverables:

- `labs/lab11/reverse-proxy/nginx.conf`: the hardened proxy (Task 1 and Task 2)
- `labs/lab11/waf/docker-compose.override.yml`: the CRS WAF (bonus)
- `labs/lab11/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`: path-scoped exclusions for the three false positives the bonus turned up

Raw outputs are in `labs/lab11/results/`. They, `labs/lab11/logs/` and
`labs/lab11/reverse-proxy/certs/` are git-ignored and not committed.

### Where this run departs from the lab text

1. **Git Bash path conversion.** MSYS rewrites `-subj '/CN=localhost'` into a
   Windows path. `openssl req` and every `docker run` ran with
   `MSYS_NO_PATHCONV=1`. The certificate command is otherwise as given.
2. **The 11.2 wait loop returns too early.** `until curl -sk -o /dev/null ...`
   only fails on transport errors, so a 502 from nginx while Juice Shop is still
   booting ends the loop. Here it exited after 0.3 s. I waited until
   `-w '%{http_code}'` printed 200 instead.
3. **`openssl s_client -connect localhost:443` stopped connecting mid-run.**
   The first runs (the 11.3 TLS 1.3 proof) reached `127.0.0.1`. Later ones
   printed nothing and hung. `-connect [::1]:443` hangs the same way,
   `-connect 127.0.0.1:443` works, and `curl -6 https://localhost` fails with
   code `000`. So OpenSSL had started trying `::1` first, and Docker Desktop's
   IPv6 forward of the published port hangs. curl falls back to IPv4, so it is
   unaffected. The Task 2 openssl proofs use
   `-connect 127.0.0.1:443`, and `</dev/null` in place of `echo |`, because the
   Git Bash pipe combined with `timeout` also hung.
4. **The desktop browser pane refuses the self-signed certificate**, so every
   real-browser check (CSP reports, the WAF false-positive hunt) ran in headless
   Chromium inside the compose network, against `https://nginx/` and
   `https://waf:8443/` with `--ignore-certificate-errors`.
5. **Changes to the starter beyond the TODOs.** Each one is explained where it
   matters below:
   - `proxy_hide_header Content-Security-Policy` is removed, because it was
     stripping the only *enforcing* CSP Juice Shop has.
   - `Feature-Policy` from the app is hidden. It contradicts `Permissions-Policy`.
   - `X-Forwarded-For` is overwritten with `$remote_addr` instead of appended.
   - The `map` now sends an empty `Connection` header instead of `close`, so
     `keepalive 32` to the upstream actually works.
   - HSTS has no `preload` and `max-age` is two years.
   - The report-only CSP is the policy I actually want to enforce, and it has a
     report sink.
   - The TLS 1.2 list is cut down to ECDHE + AES-GCM.
   - Session tickets are off.
   - The login rate limit uses a case-insensitive regex location instead of the
     exact match, because the exact match was bypassable.

## Task 1

### 11.1 What the proxy does

All line numbers below are in `labs/lab11/reverse-proxy/nginx.conf`.

| Requirement | Where |
| --- | --- |
| Port 80 → HTTPS, permanent | `return 308 https://$host$request_uri;` (line 96) |
| TLS 1.2 and 1.3 only | `ssl_protocols TLSv1.2 TLSv1.3;` (line 119) |
| Six headers, each with `always` | lines 142–150 (443). The port-80 server carries the four that make sense on a redirect, and HSTS is left off it: servers must not send it over plain HTTP and browsers must ignore it there (RFC 6797 §7.2, §8.1) |
| Proxy to `juice:3000` with the real client address | `upstream juice { server juice:3000; }`, `X-Real-IP $remote_addr`, `X-Forwarded-For $remote_addr` (lines 53–55) |

### Redirect

```text
$ curl -sI http://localhost | head -2
HTTP/1.1 308 Permanent Redirect
Server: nginx
...
Location: https://localhost/
```

```text
$ curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' 'http://localhost/some/path?a=1&b=2'
308 https://localhost/some/path?a=1&b=2

$ curl -sk -L -o /dev/null -w 'final %{http_code}  method %{method}  %{url_effective}  redirects=%{num_redirects}\n' \
    -H 'Content-Type: application/json' -d '{"comment":"x","rating":1}' http://localhost/api/Feedbacks
final 500  method POST  https://localhost/api/Feedbacks  redirects=1
```

**308, not 301.** Both are permanent and cacheable. The difference is that a
client may turn a POST into a GET when it follows a 301 (RFC 9110 §15.4.2, and
browsers and curl do). This app's important requests are JSON POSTs
(`/rest/user/login`, `/api/Feedbacks`, `/api/Users`). After a 301, an old
`http://` form or a misconfigured client would arrive at HTTPS as a bodyless
GET and fail in a confusing way. A 308 replays the same method and body, as the
second command shows (the 500 is Juice Shop rejecting the dummy feedback, after
the POST arrived). The cost: a few very old clients (IE11 on Windows 7) do not
understand 308. Neither code protects the first plaintext request; HSTS covers
every request after that.

### TLS 1.3

```text
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

The rest of the `-brief` output: `Peer certificate: CN=localhost`,
`Signature type: RSA-PSS`, `Server Temp Key: X25519, 253 bits`, and
`verification error: self-signed certificate`, which is expected. X25519 is
there because the Git-for-Windows OpenSSL 3.2 client does not offer ML-KEM.
testssl does offer it, and its cipher table below shows `ECDH/MLKEM` for TLS
1.3, so the server (OpenSSL 3.5) negotiates the hybrid post-quantum group with
clients that support it.

### What the server offers, from a scanner

```text
$ docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 https://localhost
 Testing protocols via sockets except NPN+ALPN

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

**Control: the scanner can see TLS 1.0 and 1.1 when they are on.** "Not
offered" only means something if the scanner would have spotted them. I ran a
throwaway `nginx:stable-alpine` on port 9443 with
`ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; ssl_ciphers DEFAULT:@SECLEVEL=0;`
and scanned it with the same command:

```text
 TLS 1      offered (deprecated)
 TLS 1.1    offered (deprecated)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
```

Locally, `openssl s_client -tls1_1` fails before it sends anything, as the lab
text warns:
`error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available`.

### The six headers

```text
$ curl -skI https://localhost | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=(), payment=(), usb=()
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; report-uri /csp-report
```

`always` works: the same grep counts **6 of 6** on a 429 from the login rate
limit, a 403 from nginx (`GET /csp-report`), and a 500 from Juice Shop
(`/rest/nope`). The full response is in `results/headers.txt`. It also carries
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Resource-Policy: same-origin`, kept from the starter.

Choices that differ from the starter:

- **HSTS without `preload`.** Preload is effectively irreversible, and this host
  is `localhost` with a self-signed certificate. HSTS is per host, not per
  port, so a browser that has seen this header will also upgrade every other
  `http://localhost:<port>` dev server. That is worth knowing before running the
  lab in a daily-driver browser.
- **`Feature-Policy` from Juice Shop is hidden.** The app sends
  `Feature-Policy: payment 'self'`, which contradicts our `payment=()`. Two
  policies that disagree help nobody, and the edge owns this one.
- **Juice Shop's own `Content-Security-Policy` is passed through.** The starter
  hid it. `routes/userProfile.js` sets an *enforcing* CSP on `/profile`. Hiding
  it at the proxy swapped an enforced policy for our report-only one, which is a
  regression. With a logged-in test user:

  ```text
  # starter config (proxy_hide_header Content-Security-Policy)
  HTTP/1.1 200 OK
  Content-Security-Policy-Report-Only: default-src 'self'; ...

  # this config
  HTTP/1.1 200 OK
  Content-Security-Policy: img-src 'self' /assets/public/images/uploads/default.svg; script-src 'self' 'unsafe-eval'
  Content-Security-Policy-Report-Only: default-src 'self'; ...
  ```

  The browser enforces the app's policy and reports against ours. The two do
  not interfere.

### Why Report-Only, and the road to enforcement

The report-only header points at `/csp-report`. nginx accepts POSTs there
(capped at 16 KB and 30/min per address), proxies them to an internal 204 sink
so the body is read, and logs `$request_body` as JSON lines. Loading the home
page once in headless Chromium produced these reports
(`results/csp-violations.txt`):

```text
script-src-elem | inline                                    | https://nginx/ line 17
script-src-attr | inline                                    | https://nginx/ line 29
font-src        | https://fonts.gstatic.com/.../pxiKyp0ihIEF2isQFJXGdg.woff2
font-src        | https://fonts.gstatic.com/.../pxiKyp0ihIEF2isRFJXGdg.woff2
font-src        | https://fonts.gstatic.com/.../pxiKyp0ihIEF2isfFJU.woff2
```

Opening Juice Shop's DOM-XSS URL,
``/#/search?q=<iframe src="javascript:alert(`xss`)">``, added two more
`script-src-elem` reports, one from `chunk-GJJPXCX3.js` and one from the
`about:` frame. The `alert()` still ran, because headless Chrome hung on the
dialog. Report-only reports and does not block.

**Answer.** If I enforced this policy today, the Juice Shop home page would
break three ways:

- The inline `<script>` on line 17 that initialises the cookie-consent banner
  would not run.
- The Angular build's `<link rel="stylesheet" href="styles.css" media="print" onload="this.media='all'">`
  trick on line 29 would never fire. `styles.css` would stay print-only, and
  the app would render with only the inlined critical CSS. The `<noscript>`
  fallback does not help, because JavaScript is on.
- The VT323 font from `fonts.gstatic.com` would not load.

It would also block the search-page DOM XSS, which is the one break we want.
The way to enforcement:

1. Ship the policy as Report-Only first and collect reports from real traffic
   for at least one release cycle.
2. Fix each report at its source: move the inline script to a file or allow it
   by `sha256-` hash, build with Angular's `inlineCritical` off, self-host the
   font or add `https://fonts.gstatic.com` to `font-src` on purpose.
3. Once the only reports left are attacks and browser-extension noise, rename
   the header to `Content-Security-Policy`.
4. Keep `report-uri` on in enforcing mode and alert on spikes. Run the next,
   stricter policy (nonces, Trusted Types) as a new Report-Only header beside it.

## Task 2

### Rate limit on the login endpoint

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;   # http block
limit_req_status 429;
location ~* ^/rest/user/login/?$ {   # not "= /rest/user/login", see the bypass section
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

**Rate 10 requests/minute per client address (one token every 6 s), burst 5,
`nodelay`, answering 429.** Only the login location has it; the rest of the
site is not limited. I started with the starter's exact match,
`location = /rest/user/login`, and changed it after the bypass test below.

```text
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login \
    -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'; done; echo
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

Six 401s (one at the rate plus the burst of five), then eight 429s. From
`logs/error.log`:

```text
[warn] 53#53: *145 limiting requests, excess: 5.405 by zone "login", client: 172.21.0.1, server: _, request: "POST /rest/user/login HTTP/1.1", host: "localhost"
```

The 429 carries all six security headers. Right after the burst, five searches
from the same address answered `200 200 200 200 200`, so the limit does not
spill over onto other endpoints. The client address is `172.21.0.1`, Docker
Desktop's NAT gateway. Every client on this host shares one bucket, which
matters for the bypass question below.

### Connection limit per client address

```nginx
limit_conn_zone $binary_remote_addr zone=perip:10m;   # http block, applies to every server
limit_conn perip 20;
limit_conn_status 429;
```

nginx counts a connection only while a request is in progress. Idle TLS
connections are not counted, and under HTTP/2 each in-flight stream counts as
one connection. To make the limit bite, a short Python client opened 30 TLS
connections from one address. Each sent a complete `POST /api/Feedbacks`
header with `Content-Length: 100` and then held the body back:

```text
## 30 concurrent POSTs from one address, each holding its connection (body never sent), limit_conn perip 20
 20 x held (no response within 3s)
 10 x HTTP/1.1 429 Too Many Requests
[warn] 59#59: *232 limiting connections by zone "perip", client: 172.21.0.1, server: _, request: "POST /api/Feedbacks HTTP/1.1", host: "localhost"
```

### Cipher configuration

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
# TLS 1.2: ECDHE + AES-GCM only
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
# TLS 1.3: AES-GCM only (CHACHA20-POLY1305 removed)
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
```

Proof (`results/ciphers.txt`):

```text
$ openssl s_client -connect 127.0.0.1:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 </dev/null  (outside the list)
...:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:...:SSL alert number 40
New, (NONE), Cipher is (NONE)
... | grep -icE "alert|failure"  => 1
$ ... -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -brief  (in the list)
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
$ ... -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -brief  (in the list)
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
$ ... -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305  (TLS 1.2, outside the list)
...:error:0A000410:...:ssl/tls alert handshake failure:...:SSL alert number 40
$ ... -tls1_2 -cipher ECDHE-RSA-AES128-SHA  (TLS 1.2 CBC, outside the list)
...:error:0A000410:...:ssl/tls alert handshake failure:...:SSL alert number 40
$ ... -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -brief  (TLS 1.2, in the list)
Protocol version: TLSv1.2
Ciphersuite: ECDHE-RSA-AES128-GCM-SHA256
$ ... -tls1_3 -cipher TLS_AES_256_GCM_SHA384  (the test bug from the lab text: never leaves the client)
...:error:0A0000B9:SSL routines:SSL_CTX_set_cipher_list:no cipher match:...
```

Alert 40 (`handshake_failure`) comes from the server: the ClientHello offered
only suites the server will not use. The last line is the trap from the lab
text: `-cipher` is TLS 1.2-only, so OpenSSL rejects the name itself and never
connects. Server side, as enumerated by testssl
(`--cipher-per-proto`, `results/ciphers-per-proto.txt`):

```text
TLSv1.2
 xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 256   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 256   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLSv1.3
 x1302   TLS_AES_256_GCM_SHA384            ECDH/MLKEM AESGCM      256      TLS_AES_256_GCM_SHA384
 x1301   TLS_AES_128_GCM_SHA256            ECDH/MLKEM AESGCM      128      TLS_AES_128_GCM_SHA256
```

The two ECDSA suites in `ssl_ciphers` cannot be negotiated with an RSA
certificate. They are there so an ECDSA certificate can be added later without
touching the list.

### Timeouts

| Directive | Value | What it protects against |
| --- | --- | --- |
| `proxy_connect_timeout` | 5s | A backend that is down or black-holing SYNs. The default is 60 s, during which the client waits and the connection stays held. At 5 s the client gets a 504 quickly, and the failure counts against the upstream (`max_fails`). |
| `proxy_send_timeout` | 30s | A backend that stops reading the request (stuck event loop, full socket buffer). It bounds the gap between two writes of the request to the upstream. |
| `proxy_read_timeout` | 30s | A backend that accepted the request and hangs (slow query, deadlock). It bounds the gap between two reads of the response, frees the connection, and returns 504. It is longer than socket.io's default 25 s ping interval, so an idle WebSocket survives. |
| `client_header_timeout` | 10s | Slowloris: the header trickles in a few bytes at a time and holds a connection open. |
| `client_body_timeout` | 10s | Slow POST (R.U.D.Y.): a large Content-Length followed by a body that never comes. |
| `send_timeout` | 10s | A client that stops reading the response (slow read), pinning buffers and the connection. |
| `keepalive_timeout` | 10s | Idle keep-alive connections tying up `worker_connections`. |

**A timeout firing, not just configured.** `docker compose pause` freezes the
Juice Shop container's processes with the cgroup freezer. The kernel's TCP
stack keeps working, so connections and requests are accepted and never
answered:

```text
$ docker compose -f labs/lab11/docker-compose.yml pause juice
$ curl -sk -o /dev/null -w "%{http_code} after %{time_total}s\n" https://localhost/rest/products/search?q=apple
504 after 30.248356s
$ docker compose -f labs/lab11/docker-compose.yml unpause juice

[error] 56#56: *199 upstream timed out (110: Operation timed out) while reading response header from upstream, client: 172.21.0.1, ... upstream: "http://172.21.0.2:3000/rest/products/search?q=apple"
"GET /rest/products/search?q=apple HTTP/1.1" 504 160 "-" "curl/8.7.1" rt=30.029 uct=0.000 urt=30.030
```

`uct=0.000` shows the connect succeeded (from the keepalive pool) and
`urt=30.030` shows the read gave up at 30 s, so this is `proxy_read_timeout`.
After `unpause` the same request answers 200.

The client-side timeouts were triggered over raw TLS with a short Python
script (`results/timeouts-client.txt`):

```text
## client_header_timeout 10s
partial header sent; server closed after 10.0s; bytes received: 0
## client_body_timeout 10s
10 of 100 body bytes sent; after 10.0s: <no response, connection closed>
"GET / HTTP/1.1" 408 0 "-" "-" rt=10.003 uct=- urt=-
"POST /api/Feedbacks HTTP/1.1" 408 0 "-" "-" rt=10.010 uct=- urt=-
```

I did not trigger `proxy_connect_timeout`. Black-holing SYNs to the Juice Shop
container would need `NET_ADMIN` and `iptables` inside a distroless image.
Stopping the container would test connection refused or no route to host,
which are different code paths from a connect timeout.

### OCSP stapling

Stapling saves the client a separate request to the CA's OCSP responder during
the handshake. That is one fewer round trip on the critical path and one fewer
party (the CA) learning which site the user is visiting. It also lets the
client get a revocation answer when the responder is slow or blocked. I left it
off. The certificate is self-signed, so there is no issuer to verify a response
against and no OCSP URL to fetch from: `openssl x509 -noout -ocsp_uri` prints
nothing, and the certificate has no Authority Information Access extension. In
production I would still not plan around it: Let's Encrypt removed OCSP URLs
from its certificates and shut its responders down in 2025 in favour of CRLs,
and Chrome never queried OCSP live anyway. Stapling is only worth enabling for
a CA that still runs OCSP, and never with must-staple unless the resolver path
is monitored.

### Certificate rotation runbook (executed)

nginx reads the certificate and key only at start and on reload. A graceful
reload starts new workers on the new files while the old workers finish their
in-flight connections. That is what makes zero failed requests possible; a
container restart would drop them.

1. **Monitor expiry.** Alert at 30 days, page at 7. Record the serial and
   `notAfter` of the live certificate.
2. **Stage the new pair next to the live one** (`localhost.crt.new`,
   `localhost.key.new`), readable by the nginx worker. Never edit the live
   files in place.
3. **Validate offline.** The key matches the certificate (same public-key
   hash). `notBefore` is in the past and `notAfter` is where you expect. The SAN
   covers every served name. For a CA certificate, the chain verifies:
   `openssl verify -CAfile chain.pem new.crt`.
4. **Keep the current pair for rollback** (`*.prev`).
5. **Swap by rename** (`mv`, same directory, so it is atomic). The order of the
   two renames does not matter because nginx reads nothing until step 6. The
   certs directory is bind-mounted as a *directory*. A single-file bind mount
   pins the old inode, and a rename on the host would be invisible in the
   container.
6. **`nginx -t && nginx -s reload`.** `nginx -t` catches a key/cert mismatch or
   an unreadable file. If it fails, the old workers keep serving the old
   certificate; fix the files or roll back (step 4).
7. **Verify over the wire:**
   `openssl s_client -connect host:443 -servername host </dev/null | openssl x509 -noout -serial -enddate`
   must print the new serial. Run testssl for the full posture, and check
   `error.log` for handshake errors.
8. **Watch, then clean up.** Watch error rates for a while. To roll back, move
   `*.prev` back and repeat step 6. Log the old and new serial and expiry in the
   change record. Delete `*.prev` after about 7 days.

The run, with a loop of 250 sequential requests running throughout. Each
request was a new curl process, so every one did a full TLS handshake.
(`results/cert-rotation.txt`)

```text
# 0. live before: serial=5C1D406E4532009C3EA6FA8427D0085915A85322 notAfter=Nov 15 13:59:07 2026 GMT
# 1. stage new key+cert next to the live ones
# 2. validate: key matches cert, dates, SAN
   cert pubkey sha256: 958009c99e2c616afa0e801b924f7d1ffc5f557d332f5d557a789b61fa636a86
   key  pubkey sha256: 958009c99e2c616afa0e801b924f7d1ffc5f557d332f5d557a789b61fa636a86
   serial=46A114A5A31C8D7439B3F32B167AC44F947D2D7F
   notBefore=Oct 16 14:18:51 2026 GMT
   notAfter=Jan 14 14:18:51 2027 GMT
   X509v3 Subject Alternative Name:
       DNS:localhost, IP Address:127.0.0.1
# 3. keep the current pair for rollback
# 4. swap the files (rename), then test config and graceful reload
   nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
   nginx: configuration file /etc/nginx/nginx.conf test is successful
# 5. verify the new certificate is the one served
   live after: serial=46A114A5A31C8D7439B3F32B167AC44F947D2D7F notAfter=Jan 14 14:18:51 2027 GMT
# 6. requests during rotation: 250 total
       250 200
```

The access log puts the 250 requests between 14:18:48 and 14:19:58. The
reload (`signal process started`) is at 14:18:52, inside that window. The new
certificate also fixes a gap in the lab's original one: it has a SAN, which
browsers require (they ignore the CN).

### Getting around a per-address rate limit

**Answer.** The first way around it is to spread the attempts over many
addresses. A botnet or residential-proxy pool works, and so does a single IPv6
`/64`, which gives one host 2^64 distinct `$binary_remote_addr` keys.
Credential stuffing at a few tries per address never reaches the burst. The
second way is to reach the login handler by a path the limit does not cover.
On this stack that worked before I fixed it: `/rest/user/login/` and
`/REST/user/login` reach the same Express handler but missed nginx's exact,
case-sensitive `location =` (14 × 401, never a 429). The WAF on 8443 is a
second path to Juice Shop with no limit at all. Keying the limit on a
client-controlled `X-Forwarded-For` would be the same mistake, since every
request could carry a fresh value and get a fresh bucket. At this layer I
would:

- key IPv6 clients by `/64`, not by full address;
- add a global ceiling on the login endpoint, not only a per-address one;
- keep a single entry point (the WAF chained with nginx, not beside it);
- trust `real_ip` only from the known load balancer's addresses.

Above this layer, the control that follows the attacker's actual goal is per
account: failed-login counters with progressive delays or a CAPTCHA keyed on
the target username in the app, breached-password checks and MFA, and bot
detection at the CDN.

The path-variant test. A Python client sent 14 POSTs per variant and waited
40 s between variants so the bucket refilled (`results/ratelimit-bypass.txt`
and `results/ratelimit-bypass-fixed.txt`):

```text
# location = /rest/user/login   (exact match, as in the starter)
/rest/user/login       401 401 401 401 401 401 429 429 429 429 429 429 429 429
/rest/user/login/      401 401 401 401 401 401 401 401 401 401 401 401 401 401   <- bypass
/REST/user/login       401 401 401 401 401 401 401 401 401 401 401 401 401 401   <- bypass
/Rest/User/Login       401 401 401 401 401 401 401 401 401 401 401 401 401 401   <- bypass
/rest/user/login?x=1   401 401 401 401 401 401 429 429 429 429 429 429 429 429
//rest/user/login      401 401 401 401 401 401 429 429 429 429 429 429 429 429   (merge_slashes)
/rest/user/logi%6E     500 500 500 500 500 500 429 429 429 429 429 429 429 429   (nginx decodes before matching)

# location ~* ^/rest/user/login/?$   (this config)
/rest/user/login       401 401 401 401 401 401 429 429 429 429 429 429 429 429
/rest/user/login/      401 401 401 401 401 401 429 429 429 429 429 429 429 429
/REST/user/login       401 401 401 401 401 401 429 429 429 429 429 429 429 429
/Rest/User/Login/      401 401 401 401 401 401 429 429 429 429 429 429 429 429

# the WAF port, which has no rate limit
$ for i in $(seq 1 14); do curl ... -X POST https://localhost:8443/rest/user/login ...; done
401 401 401 401 401 401 401 401 401 401 401 401 401 401
```

The bypassed requests are real login attempts: each 401 is Juice Shop
checking the credentials. Express's default router is case-insensitive and
non-strict about a trailing slash, while nginx `location =` is exact and
case-sensitive. The regex location now covers what Express accepts. The
`logi%6E` variant shows that nginx normalises percent-encoding before matching,
so encoding is not a way around it.

## Bonus

### The WAF

`labs/lab11/waf/docker-compose.override.yml` adds a `waf` service to the same
compose project:

- **Image:** `owasp/modsecurity-crs:4.30.0-nginx-alpine-202610051210`.
- **Backend:** `BACKEND=http://juice:3000`, so the WAF sits beside nginx, not
  behind it.
- **Mode:** `MODSEC_RULE_ENGINE=On` (blocking; `DetectionOnly` is the
  one-variable switch), with `BLOCKING_PARANOIA=1` and an inbound anomaly
  threshold of 5.
- **TLS:** it serves the lab certificate on `8443:8443` only. The container's
  plain-HTTP 8080 is not published.

Juice Shop keeps `expose` only, and the override pins `juice: ports: !reset []`
so that a later edit to the base file cannot publish it.

Running the WAF beside nginx is right for this comparison and wrong for
production. Port 8443 is a second way into the app that skips everything in
`nginx.conf`: the login limit (14 × 401 through it, see Task 2), the
connection limit, and the security headers. In a real deployment the WAF goes
in series with the proxy, or inside it as the ModSecurity nginx module, so
there is only one entry point.

```bash
docker compose -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml up -d
```

```text
SERVICE   STATUS          PORTS
juice     Up 19 minutes   3000/tcp
nginx     Up 19 minutes   0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
waf       Up 3 seconds    0.0.0.0:8443->8443/tcp

$ curl -s -o /dev/null --max-time 5 -w '%{http_code}' http://localhost:3000/   # the app directly
000 (curl exit 7: failed to connect)
```

### The same request through both paths

```text
## GET /?q=%27%20OR%201%3D1--                                 (the lab's payload, ' OR 1=1--)
  plain proxy https://localhost       -> 200  (Juice Shop index.html)
  WAF         https://localhost:8443  -> 403  (403 Forbidden)
## GET /rest/products/search?q=%27%20OR%201%3D1--             (same payload, at the vulnerable endpoint)
  plain proxy https://localhost       -> 500  (Error: SQLITE_ERROR: incomplete input)
  WAF         https://localhost:8443  -> 403
## GET /rest/products/search?q=%27))%20OR%201%3D1--           (the variant that closes the parentheses)
  plain proxy https://localhost       -> 200  ({"status":"success","data":[...]})
  WAF         https://localhost:8443  -> 403
## GET /rest/products/search?q=apple                          (control)
  plain proxy -> 200     WAF -> 200
```

The plain proxy forwards a working exploit. Through it, the `'))` variant
returns **56 products, against 46 for an empty search**. The injection
comments out the query's `AND deletedAt IS NULL` and leaks the 10 soft-deleted
products.

### The rule that fired

From the WAF's JSON audit log (`results/waf-rules.txt`):

```text
403 GET /?q=%27%20OR%201%3D1--
    id 942100  sev 2  SQL Injection Attack Detected via libinjection  | data: Matched Data: s&1c found within ARGS:q: ' OR 1=1--
    id 949110  sev 0  Inbound Anomaly Score Exceeded (Total Score: 5)
```

and from its error log:

```text
ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [ver "OWASP_CRS/4.30.0"] ... [uri "/"]
```

**Rule 942100** (REQUEST-942-APPLICATION-ATTACK-SQLI, paranoia level 1) runs
libinjection's SQL tokenizer over every argument, cookie and argument name. It
does not pattern-match keywords. It lexes the input as SQL and compares the
resulting token "fingerprint" with a list of fingerprints known to come from
injections. `' OR 1=1--` lexes to `s&1c`: a string-terminating quote, a logical
operator, a number, and a comment. That is a classic tautology. The rule is
CRITICAL, so it adds 5 to the inbound anomaly score. **949110** is not a
detection: it is the blocking evaluation at the end of phase 2, which denies
the request once the score reaches the threshold (5 at PL1). One critical
match is therefore enough.

### False-positive hunt: found four

I drove Juice Shop through the WAF the way a user would, then sent realistic
inputs through both paths (`results/waf-fp-hunt.txt`):

- a headless-browser page load
- searches with apostrophes, `&`, `<3`, `select`, `drop`
- product reviews with apostrophes, `--`, `;`, `<b>`, `1=1`
- the authenticated GETs the SPA makes

Three classes of legitimate traffic were blocked:

| What the user does | Request | Rule | Why |
| --- | --- | --- | --- |
| Just loads the page | `POST /socket.io/?EIO=4&transport=polling&sid=…` with `Content-Type: text/plain;charset=UTF-8` | **920420** Request content type is not allowed by policy | socket.io's long-polling transport POSTs `text/plain`, which CRS 4 removed from the default allowed list. 7 of these got 403 in one page load. The WebSocket upgrade (101) still worked, so the page looked fine, but the polling fallback that clients behind WebSocket-hostile proxies need was dead. |
| Writes any product review | `PUT /rest/products/1/reviews` | **911100** Method is not allowed by policy | CRS 4 allows only `GET HEAD POST OPTIONS` by default. Juice Shop's API uses PUT, PATCH and DELETE (reviews, basket items, addresses). All 7 review texts got 403 because of the method, not their content. |
| Is logged in (the navbar calls it on every page) | `GET /rest/user/whoami` | **932260** Remote Command Execution: Direct Unix Command Execution | `Matched Data: /rest/user/whoami found within REQUEST_FILENAME`. The endpoint's *name* is a Unix command. It is blocked even with no auth header. |

The review texts themselves are clean at PL1. Sent as `POST /api/Feedbacks`
comments, a method the WAF allows, all 7 passed the WAF; the 401s came from
Juice Shop's captcha check. A non-finding worth recording: searching for
`O'Reilly` or `rock 'n' roll` returns **500 on both paths**. That is Juice
Shop's own SQL injection bug breaking on a legitimate apostrophe. libinjection
did not flag those inputs, so the WAF neither caused the failure nor fixed it.

**Tuning.** `labs/lab11/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` fixes
each false positive on the path where it was seen only:

- **id 1000:** allows PUT, PATCH and DELETE under `/rest/` and `/api/`.
- **id 1001:** CRS's default content-type list plus `text/plain`, on
  `/socket.io/` only.
- **id 1002:** `ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME` on
  `/rest/user/whoami` only.

After recreating the WAF:

```text
socket.io during a page load:  GET 101 x1, GET 200 x3, POST 200 x2   (before: POST 403 x7)
review PUTs:                   201 x7                                 (before: 403 x7)
GET /rest/user/whoami:         200                                    (before: 403)

still blocked:
  /?q=' OR 1=1--                              403  [942100, 949110]
  /rest/products/search?q=')) OR 1=1--        403  [942100, 949110]
  /rest/user/whoami?x=;whoami                 403  [932235, 932260, 932340, 932380, 949110]
  /rest/products/search?q=<script>alert(1)</script>  403  [941100, 941110, 941160, 941390, 949110]
  PUT /rest/products/1/reviews  message: x' OR 1=1--   403  [942100, 949110]
```

**A cost of the socket.io exclusion, measured.** A `text/plain` POST to
`/socket.io/` carrying `' UNION SELECT password FROM Users--` got 400 from
socket.io with **no rule match**. ModSecurity has no body parser for
`text/plain`, so the CRS rules that inspect `ARGS` never see that body. This is
why CRS 4 dropped `text/plain` from the defaults. The exposure is the same as
the WebSocket channel, whose frames no ModSecurity inspects at all, and it is
limited to one path. The alternative is to configure socket.io for WebSocket
transport only and drop exclusion 1001.

### Rolling CRS out in front of a real application

CRS in blocking mode on day one fails exactly as shown above: the first real
page load produced 403s on the app's own API.

1. **Weeks 1–2: watch only.** Deploy with `MODSEC_RULE_ENGINE=DetectionOnly` at
   paranoia level 1, with audit logs going to the SIEM. Replay real traffic
   (staging, E2E suites, a canary slice of production). Every match on known
   good traffic becomes a narrow exclusion, scoped by path and rule like the
   three here, never a rule disabled site-wide. Each exclusion is reviewed and
   committed next to the application code it describes.
2. **Then block with a high bar.** Switch to `On` with a high inbound anomaly
   threshold (around 50, so effectively only stacked critical matches block)
   and step it down toward 5 as the logs stay clean.
3. **Raise paranoia the same way.** Use `DETECTION_PARANOIA` above
   `BLOCKING_PARANOIA`, so the stricter rules log without blocking until they
   too are tuned.
4. **Keep it tested.** Run a regression suite of known-good requests and known
   attacks against the WAF in CI, so an application change (a new PUT endpoint,
   a new content type) shows up as a failing test, not a production outage. The
   operating rule throughout: a 403 rate change on the dashboard pages someone,
   and turning the WAF off is never the fix.
