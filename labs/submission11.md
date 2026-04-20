# Lab 11 Submission

## Task 1 — Reverse Proxy Compose Setup

A reverse proxy improves security by centralizing TLS termination, security headers, request filtering, and rate limiting in one enforcement point.  
Hiding direct app ports reduces attack surface because clients cannot bypass proxy controls and hit Juice Shop directly.

`docker compose ps` (only Nginx exposes host ports):

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     53 seconds ago   Up 52 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     52 seconds ago   Up 51 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

HTTP redirect check:

```text
HTTP 308
```

## Task 2 — Security Headers

Relevant headers from HTTPS response:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

- **X-Frame-Options**: mitigates clickjacking by blocking iframe embedding.
- **X-Content-Type-Options**: prevents MIME sniffing and reduces content-type confusion/XSS risk.
- **Strict-Transport-Security (HSTS)**: forces HTTPS and helps prevent SSL stripping.
- **Referrer-Policy**: limits sensitive referrer data leakage across origins.
- **Permissions-Policy**: disables sensitive browser capabilities (camera, geolocation, microphone).
- **COOP/CORP**: strengthens origin isolation and cross-origin resource protections.
- **CSP-Report-Only**: reports CSP violations without breaking app functionality.

## Task 3 — TLS, HSTS, Rate Limiting, and Timeouts

### TLS / testssl summary

- Protocols enabled: TLS 1.2 and TLS 1.3.
- Protocols disabled: SSLv2, SSLv3, TLS 1.0, TLS 1.1.
- Supported cipher suites (scan output):
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256
- Why TLS 1.2+ is required: older SSL/TLS versions are cryptographically weak; TLS 1.3 provides stronger defaults and a safer handshake.
- testssl warnings/notes:
  - Chain of trust: NOT ok (self-signed certificate)
  - Hostname mismatch for `host.docker.internal` vs cert SAN/CN `localhost`
  - No OCSP/CRL URI; OCSP stapling not offered
- HSTS check:
  - HTTP (`http://localhost:8080`): HSTS not present
  - HTTPS (`https://localhost:8443`): HSTS present

### Rate limiting and timeouts

Rate-limit test output (`analysis/rate-limit-test.txt`):

```text
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

Result: 6x `401` (backend handled invalid credentials), then 6x `429` (Nginx rate limit triggered).

Rate-limit config explanation:
- `rate=10r/m`: allows up to 10 login requests per minute per client IP.
- `burst=5`: allows short spikes of 5 extra requests.
- Trade-off: reduces brute-force risk while still tolerating brief legitimate bursts.

Timeout settings in `nginx.conf`:
- `client_body_timeout 10s`: limits slow body upload time; mitigates slow POST attacks.
- `client_header_timeout 10s`: limits slow header transmission; mitigates slowloris behavior.
- `proxy_read_timeout 30s`: limits how long Nginx waits for upstream responses.
- `proxy_send_timeout 30s`: limits how long Nginx waits to send data to upstream.

Trade-off: tighter timeouts improve resilience under abuse, but can impact very slow clients or long backend operations.

Relevant `access.log` lines with `429`:

```text
172.21.0.1 - - [20/Apr/2026:17:22:11 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "Mozilla/5.0 (Windows NT; Windows NT 10.0; ru-RU) WindowsPowerShell/5.1.19041.6456" rt=0.002 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:17:22:11 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "Mozilla/5.0 (Windows NT; Windows NT 10.0; ru-RU) WindowsPowerShell/5.1.19041.6456" rt=0.002 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:17:22:11 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "Mozilla/5.0 (Windows NT; Windows NT 10.0; ru-RU) WindowsPowerShell/5.1.19041.6456" rt=0.003 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:17:22:11 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "Mozilla/5.0 (Windows NT; Windows NT 10.0; ru-RU) WindowsPowerShell/5.1.19041.6456" rt=0.004 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:17:22:11 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "Mozilla/5.0 (Windows NT; Windows NT 10.0; ru-RU) WindowsPowerShell/5.1.19041.6456" rt=0.002 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:17:22:11 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "Mozilla/5.0 (Windows NT; Windows NT 10.0; ru-RU) WindowsPowerShell/5.1.19041.6456" rt=0.003 uct=- urt=-
```

## Evidence files

- `labs/lab11/analysis/http-redirect.txt`
- `labs/lab11/analysis/compose-ps.txt`
- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`
- `labs/lab11/analysis/testssl.txt`
- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/nginx-logs.txt`
