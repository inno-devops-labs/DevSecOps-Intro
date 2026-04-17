# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting


Environment:
- Docker `26.1.3`
- Docker Compose `v2.36.2`
- Branch: `feature/lab11`


## Task 1 — Reverse Proxy Compose Setup

### What I did

1. Generated a local self-signed certificate for `localhost` with SAN entries for `localhost`, `127.0.0.1`, and `::1`.
2. Started the stack from `labs/lab11` with `docker compose up -d`.
3. Verified that HTTP on `http://localhost:8080/` returns a redirect to HTTPS.
4. Verified that only Nginx publishes host ports and Juice Shop is only reachable on the internal Docker network.

### Why a reverse proxy improves security

- A reverse proxy centralizes TLS termination, so the application can stay unchanged while traffic is encrypted in transit.
- It can inject security headers consistently, even when the upstream application does not set them correctly.
- It acts as a filtering layer for request controls such as rate limiting, request size limits, and timeouts.
- It gives operations teams a single entry point to monitor, log, and enforce policy instead of exposing each app container directly.

### Why hiding direct app ports reduces attack surface

- Juice Shop is not published to the host, so users and scanners cannot reach the app directly on port `3000`.
- All inbound traffic must go through Nginx first, which means TLS, headers, logging, and rate limiting are enforced before requests reach the application.
- This removes the possibility of bypassing proxy controls by talking to the app container directly from the host.

### Compose evidence

`docker compose ps` output:

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     2 minutes ago   Up 2 minutes   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     2 minutes ago   Up 2 minutes   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```

Interpretation:
- `lab11-nginx-1` exposes host ports `8080` and `8443`.
- `lab11-juice-1` shows only `3000/tcp`, which means it is exposed to the Compose network but not published to the host.

HTTP redirect evidence:

```text
HTTP 308
```

## Task 2 — Security Headers

### HTTPS header evidence

Relevant headers from `labs/lab11/analysis/headers-https.txt`:

```text
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

### Header-by-header analysis

- **X-Frame-Options: DENY**
  Prevents the site from being embedded in frames or iframes, which helps stop clickjacking attacks.

- **X-Content-Type-Options: nosniff**
  Prevents browsers from MIME-sniffing content into a different type than declared, reducing script execution from mislabeled files.

- **Strict-Transport-Security (HSTS)**
  Tells browsers to use HTTPS for future requests, which helps block protocol downgrade and SSL stripping attacks after the first secure visit.

- **Referrer-Policy: strict-origin-when-cross-origin**
  Limits how much referrer information is leaked to other origins. This helps avoid exposing full URLs, query strings, or sensitive path data to third parties.

- **Permissions-Policy: camera=(), geolocation=(), microphone=()**
  Explicitly disables powerful browser features that Juice Shop does not need, reducing abuse if a browser-side bug or injection occurs.

- **COOP/CORP**
  `Cross-Origin-Opener-Policy: same-origin` isolates the browsing context from cross-origin windows.
  `Cross-Origin-Resource-Policy: same-origin` restricts how resources can be loaded by other origins.
  Together they reduce cross-origin data leaks and help mitigate some XS-Leaks-style abuse patterns.

- **CSP-Report-Only**
  The proxy advertises a CSP without enforcing it yet. This is useful when hardening an existing app because it reveals policy violations without immediately breaking inline scripts or other legacy behaviors. That trade-off makes sense for Juice Shop, which depends on inline/eval behavior that would likely fail under a strict enforced CSP.

## Task 3 — TLS, HSTS, Rate Limiting, and Timeouts

### TLS scan summary

Source: `labs/lab11/analysis/testssl-clean.txt`

Protocol support observed:
- Enabled: `TLSv1.2`, `TLSv1.3`
- Disabled: `SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`

Supported cipher suites observed:
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES128-GCM-SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

Why TLS 1.2+ is required:
- TLS 1.0 and 1.1 are deprecated and lack the modern security baseline expected for current browsers and compliance programs.
- TLS 1.2 and 1.3 support strong AEAD cipher suites and modern handshake protections.
- TLS 1.3 is preferred because it simplifies the handshake, removes obsolete options, and generally gives stronger default security with better performance.

Observed TLS findings:
- Positive:
  - Forward secrecy was offered.
  - HTTP/2 was offered over ALPN.
  - No SSLv3/TLS1.0 fallback was possible.
  - Common legacy issues such as Heartbleed, CCS, BREACH, POODLE, FREAK, DROWN, SWEET32, and RC4 were reported as not vulnerable.
- Expected local-development warnings:
  - `Chain of trust NOT ok (self signed)`
  - No CRL or OCSP URI in the certificate
  - `OCSP stapling not offered`
  - `DNS CAA RR not offered`
  - `Certificate Transparency --`
  - Overall testssl grade was capped because the certificate is self-signed

Interpretation:
- These warnings are acceptable for a localhost lab with a self-signed certificate.
- In production, I would replace the cert with a publicly trusted CA certificate or a locally trusted development CA such as `mkcert`, then enable OCSP stapling and proper trust-chain distribution.

### HSTS verification

HSTS appeared only on HTTPS responses.

Evidence:
- `labs/lab11/analysis/headers-http.txt` contains no `Strict-Transport-Security` header.
- `labs/lab11/analysis/hsts-check.txt` shows:

```text
analysis/headers-https.txt:strict-transport-security: max-age=31536000; includeSubDomains; preload
```

This is the correct behavior because HSTS should only be sent over HTTPS. Sending it over HTTP would be ignored by browsers and can create confusion during validation.

### Rate limit results

Source files:
- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/rate-limit-summary.txt`
- `labs/lab11/analysis/access-429.txt`

Observed response sequence:

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

Summary counts:

```text
401 6
429 6
```

Interpretation of the configuration:
- `rate=10r/m` allows roughly 10 login requests per minute per client IP.
- `burst=5` allows a short temporary spike above that baseline.
- `nodelay` means burst requests are passed immediately instead of being queued and slowed down.

Why these values are a good balance:
- They are strict enough to slow brute-force attempts against `/rest/user/login`.
- They still allow a small burst for legitimate users who double-submit or retry after a typing error.
- In practice here, one request fit the steady rate window and five extra requests were accepted in the burst, so the first 6 attempts hit the app and returned `401`, while the remaining 6 were blocked at the proxy with `429`.

### Access log evidence for 429 responses

Relevant lines from `labs/lab11/analysis/access-429.txt`:

```text
172.18.0.1 - - [17/Apr/2026:13:02:47 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [17/Apr/2026:13:02:48 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [17/Apr/2026:13:02:48 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
```

The `uct=- urt=-` values are consistent with Nginx rejecting the request locally before proxying it upstream.

### Timeout settings and trade-offs

Relevant values from `labs/lab11/reverse-proxy/nginx.conf`:
- `client_body_timeout 10s`
- `client_header_timeout 10s`
- `proxy_read_timeout 30s`
- `proxy_send_timeout 30s`

Analysis:
- `client_body_timeout 10s`
  Limits how long Nginx waits for the client to finish sending the request body. This helps against slow POST uploads and slowloris-style abuse. The trade-off is that very slow clients on poor networks may be cut off.

- `client_header_timeout 10s`
  Limits how long Nginx waits for the client to finish sending headers. This directly reduces slowloris risk by preventing half-open header drips from tying up worker connections. The trade-off is that extremely slow or unstable clients may time out sooner.

- `proxy_read_timeout 30s`
  Limits how long Nginx waits between read operations from the upstream app. This protects the proxy from hanging forever on a stalled backend. The trade-off is that very long-running application responses could be terminated if 30 seconds is too aggressive.

- `proxy_send_timeout 30s`
  Limits how long Nginx waits between writes to the upstream app. This helps prevent stuck upstream connections from lingering forever. The trade-off is similar: if the app or network path is unusually slow, legitimate requests may fail earlier.

Overall trade-off:
- The chosen values are reasonable for an interactive web application like Juice Shop.
- They favor resilience and connection hygiene over support for extremely slow clients or long-lived upstream requests.

## Final Assessment

The reverse proxy hardening worked as intended:
- Nginx is the only host-exposed entry point.
- HTTP is redirected to HTTPS.
- Core security headers are present.
- HSTS is only sent on HTTPS.
- TLS is limited to `TLSv1.2+` with modern cipher suites.
- Login bursts trigger `429 Too Many Requests` at the proxy.
- Request timeouts reduce slow-client and slow-upstream risk without modifying application code.

Artifacts created for this lab:
- `labs/lab11/analysis/compose-up.txt`
- `labs/lab11/analysis/compose-ps.txt`
- `labs/lab11/analysis/http-redirect.txt`
- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`
- `labs/lab11/analysis/hsts-check.txt`
- `labs/lab11/analysis/testssl.txt`
- `labs/lab11/analysis/testssl-clean.txt`
- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/rate-limit-summary.txt`
- `labs/lab11/analysis/login-access-log.txt`
- `labs/lab11/analysis/access-429.txt`
- `labs/lab11/analysis/compose-down.txt`
- `labs/lab11/analysis/docker-system-df.txt`
- `labs/lab11/logs/access.log`
- `labs/lab11/logs/error.log`
- `labs/lab11/reverse-proxy/certs/localhost.crt`
- `labs/lab11/reverse-proxy/certs/localhost.key`