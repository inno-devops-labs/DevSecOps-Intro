# Lab 11 Submission — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

---

## Task 1 — Reverse Proxy Compose Setup

### What I did

Generated a self-signed TLS certificate with SAN for `localhost`, started the Docker Compose stack with Juice Shop and Nginx, and confirmed only Nginx exposes ports to the host.

### Why reverse proxies are valuable for security

A reverse proxy sits in front of the actual application and handles all incoming traffic. This gives you a single place to enforce security without touching the app code:

- **TLS termination** — the proxy handles HTTPS. The app behind it talks plain HTTP on an internal network only.
- **Security headers injection** — you can add X-Frame-Options, HSTS, CSP etc. at the proxy even if the app doesn't set them.
- **Request filtering** — rate limiting, IP blocking, request size limits — all enforced before the request ever reaches the app.
- **Single access point** — attackers can only reach the app through Nginx. You can lock down firewall rules to allow only proxy traffic.

### Why hiding direct app ports reduces attack surface

If the app (Juice Shop on port 3000) had its port published to the host, attackers could bypass Nginx entirely and hit the app directly — skipping all rate limits, headers, and filters. By using `expose` instead of `ports` in the Compose file, port 3000 is only reachable from inside the Docker network, not from the host or the internet.

### docker compose ps output

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     20 seconds ago   Up 19 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     20 seconds ago   Up 19 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

- `juice` service: only `3000/tcp` shown — no host port mapping, internal only
- `nginx` service: `8080` and `8443` published to the host

HTTP redirect check:
```
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```

---

## Task 2 — Security Headers

### Headers from headers-https.txt

```
HTTP/2 200 
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Note: HSTS (`strict-transport-security`) appears only in the HTTPS response, not in the HTTP 308 redirect. This is correct — HSTS only makes sense over a secure connection.

### What each header does

**X-Frame-Options: DENY**
Stops other websites from loading this page inside an `<iframe>`. Protects against clickjacking attacks where an attacker frames your login page and tricks users into clicking invisible buttons.

**X-Content-Type-Options: nosniff**
Tells the browser to trust the declared `Content-Type` and not try to "sniff" or guess the actual file type. Prevents attacks where a malicious file is uploaded as an image but executed as JavaScript because the browser guessed wrong.

**Strict-Transport-Security (HSTS)**
Once a browser receives this header over HTTPS, it remembers to always use HTTPS for this domain for 1 year (`max-age=31536000`). Protects against SSL stripping attacks where someone on the same network tries to downgrade the connection to plain HTTP.

**Referrer-Policy: strict-origin-when-cross-origin**
Controls what URL is sent in the `Referer` header when clicking links. With this setting, cross-site requests only get the origin (e.g., `https://example.com`) not the full URL (e.g., `https://example.com/account?token=abc`). Prevents leaking sensitive URL parameters to third parties.

**Permissions-Policy: camera=(), geolocation=(), microphone=()**
Disables browser features (camera, mic, GPS) for this page. Even if there is a JavaScript injection, the attacker cannot silently access the user's camera or location. Reduces the blast radius of XSS attacks.

**COOP (Cross-Origin-Opener-Policy): same-origin**
Isolates the browsing context from other origins. Prevents cross-origin windows from getting a reference to this page via `window.opener`. Protects against cross-origin attacks that rely on accessing the opener's JavaScript context.

**CORP (Cross-Origin-Resource-Policy): same-origin**
Prevents other origins from reading resources from this server (images, scripts etc.) via `fetch` or `XMLHttpRequest`. Defends against Spectre-style side-channel attacks that read cross-origin data.

**Content-Security-Policy-Report-Only**
A CSP that only logs violations instead of blocking them. This is a "learning mode" — it shows what would break if CSP were enforced without actually breaking anything. Because Juice Shop uses `unsafe-inline` and `unsafe-eval` heavily, strict CSP would break it. Report-only mode lets you study the violations first.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### TLS Scan Summary (testssl.sh)

#### Protocol support

| Protocol | Status |
|----------|--------|
| SSLv2    | Not offered (OK) |
| SSLv3    | Not offered (OK) |
| TLS 1.0  | Not offered |
| TLS 1.1  | Not offered |
| TLS 1.2  | Offered (OK) |
| TLS 1.3  | Offered (OK) |

#### Cipher suites supported

TLS 1.2:
- `ECDHE-RSA-AES256-GCM-SHA384` — 256-bit AES, forward secrecy
- `ECDHE-RSA-AES128-GCM-SHA256` — 128-bit AES, forward secrecy

TLS 1.3:
- `TLS_AES_256_GCM_SHA384` — 256-bit AES
- `TLS_CHACHA20_POLY1305_SHA256` — ChaCha20, good for mobile/low-power
- `TLS_AES_128_GCM_SHA256` — 128-bit AES

All ciphers use AEAD (authenticated encryption) and provide forward secrecy.

#### Why TLSv1.2+ is required (prefer TLSv1.3)

TLS 1.0 and 1.1 have known weaknesses (BEAST, POODLE, CRIME). They use older cipher constructions (CBC mode, RC4) that are vulnerable to various attacks. TLS 1.2 fixes most of these by supporting AEAD ciphers. TLS 1.3 is even better — it removed all legacy ciphers, requires forward secrecy for every connection, and the handshake is faster (1-RTT instead of 2-RTT). So TLS 1.2 is the minimum acceptable baseline, but TLS 1.3 is preferred.

#### Warnings from testssl

- **Chain of trust: NOT ok (self signed)** — expected in a local dev environment. A real deployment needs a certificate from a trusted CA (e.g., Let's Encrypt).
- **Neither CRL nor OCSP URI provided** — no revocation info in the self-signed cert. Expected.
- **OCSP stapling: not offered** — disabled in `nginx.conf` intentionally (requires a publicly-trusted cert and a reachable OCSP responder).
- **DNS CAA RR: not offered** — no DNS CAA record. Only matters for production domains.
- **Overall grade: T** — downgraded from A because of the self-signed cert trust issue. On a real domain with a proper CA cert, the configuration would score well (all modern ciphers, FS, no old protocols, no known vulnerabilities).

No actual vulnerabilities found: Heartbleed, ROBOT, POODLE, CRIME, BEAST, RC4, DROWN — all clean.

#### HSTS only on HTTPS

Confirmed: `Strict-Transport-Security` appears in `headers-https.txt` but not in `headers-http.txt`. The HTTP server block in `nginx.conf` only returns a 308 redirect and does not set HSTS. Correct behavior.

---

### Rate Limiting & Timeouts

#### Rate limit test output

```
401
401
401
401
401
401
429
429
429
429
429
429
```

12 POST requests to `/rest/user/login`: first 6 got `401` (wrong credentials, processed normally), then 6 got `429` (rate limited). 

#### Rate limit configuration explained

From `nginx.conf`:
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req zone=login burst=5 nodelay;
limit_req_status 429;
```

- `rate=10r/m` — allows 10 requests per minute per IP. That's about 1 every 6 seconds on average.
- `burst=5` — allows up to 5 requests in a short spike before rate limiting kicks in. The first batch went through because of `burst=5` + a few tokens already available.
- `nodelay` — queued burst requests are served immediately rather than delayed. This prevents slow responses from confusing clients while still stopping floods.
- `limit_req_status 429` — returns HTTP 429 Too Many Requests (correct RFC 6585 status for rate limiting).

**Security vs usability balance:** 10 requests/minute is more than enough for a real user typing a password. A human logs in once, maybe twice if they mistype. An attacker running a brute-force script would hit the 429 wall almost immediately. The `burst=5` allows for quick retries (e.g., password manager filling the form) without penalizing normal users.

#### Timeout settings explained

From `nginx.conf` HTTPS server block:
```nginx
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 10s;
send_timeout 10s;
```

From the `http` block (applied globally for proxy):
```nginx
proxy_read_timeout 30s;
proxy_send_timeout 30s;
```

| Setting | Value | What it does | Trade-off |
|---|---|---|---|
| `client_body_timeout` | 10s | Max time to receive the full request body. If a client sends data very slowly (Slowloris-body attack), Nginx drops the connection. | Too short: slow mobile connections might get cut off. 10s is a reasonable middle ground. |
| `client_header_timeout` | 10s | Max time to receive the request headers. Defends against Slowloris-header attacks. | Same trade-off as above. |
| `proxy_read_timeout` | 30s | How long Nginx waits for the upstream app (Juice Shop) to respond. | Too short: complex API calls or slow DB queries fail. 30s is generous but bounded. |
| `proxy_send_timeout` | 30s | How long Nginx waits to send a response chunk to the client after writing starts. | Protects against clients that stop reading, which could hold up worker connections. |

These timeouts together protect against slow-loris style DoS attacks where an attacker holds connections open by sending data extremely slowly, eventually exhausting Nginx's worker connections.

#### Access log showing 429s

```
192.168.32.1 - - [16/Apr/2026:18:44:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
192.168.32.1 - - [16/Apr/2026:18:44:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
192.168.32.1 - - [16/Apr/2026:18:44:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
192.168.32.1 - - [16/Apr/2026:18:44:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
192.168.32.1 - - [16/Apr/2026:18:44:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
192.168.32.1 - - [16/Apr/2026:18:44:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
```

`rt=0.000` confirms these were rejected by Nginx immediately — no upstream request was made, which is the point. Rate limiting at the proxy level saves backend resources.
