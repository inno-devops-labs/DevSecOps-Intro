# Lab 11 Submission — Nginx Reverse Proxy Hardening

**Student:** Sarmat  
**Date:** April 19, 2026

---

## Task 1 — Reverse Proxy Compose Setup

### Why Reverse Proxies Are Valuable for Security

A reverse proxy sits between the internet and the application, providing:
- **TLS termination** — the app doesn't need to handle certificates; the proxy manages encryption
- **Security headers injection** — headers like HSTS, CSP, X-Frame-Options are added centrally without touching app code
- **Request filtering** — rate limiting, size limits, and timeout enforcement happen before requests reach the app
- **Single access point** — all traffic flows through one controlled entry point, simplifying firewall rules and logging

### Why Hiding Direct App Ports Reduces Attack Surface

If Juice Shop's port 3000 were exposed directly, attackers could bypass all proxy-level protections (rate limiting, headers, TLS). By using `expose` instead of `ports` in Docker Compose, port 3000 is only reachable within the Docker network — not from the host or internet.

### docker compose ps Output

```
NAME            IMAGE                           SERVICE   STATUS    PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   juice     Up        3000/tcp
lab11-nginx-1   nginx:stable-alpine             nginx     Up        0.0.0.0:8080->8080/tcp, 0.0.0.0:8443->8443/tcp
```

Juice Shop shows only `3000/tcp` (internal), no host binding. Nginx has the published ports.

### HTTP Redirect Verification

```
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```

HTTP traffic is permanently redirected to HTTPS (308 Permanent Redirect).

---

## Task 2 — Security Headers

### Headers on HTTP (308 redirect)

```
HTTP/1.1 308 Permanent Redirect
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; ...
```

Note: No `Strict-Transport-Security` on HTTP — correct, HSTS only makes sense over HTTPS.

### Headers on HTTPS (200 OK)

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

### Header Analysis

**X-Frame-Options: DENY**
Prevents the page from being embedded in `<iframe>`, `<frame>`, or `<object>` on any other origin. Protects against clickjacking attacks where an attacker overlays a transparent iframe over a legitimate page to trick users into clicking hidden elements.

**X-Content-Type-Options: nosniff**
Prevents browsers from MIME-sniffing a response away from the declared Content-Type. Without this, a browser might execute a JavaScript file served as `text/plain`, enabling content injection attacks.

**Strict-Transport-Security (HSTS)**
Tells browsers to only connect via HTTPS for the next year (`max-age=31536000`). After the first visit, the browser refuses HTTP connections entirely, preventing SSL stripping attacks. `includeSubDomains` extends this to all subdomains. `preload` allows submission to browser preload lists.

**Referrer-Policy: strict-origin-when-cross-origin**
Sends the full URL as referrer for same-origin requests, but only the origin (no path/query) for cross-origin requests. Prevents leaking sensitive URL parameters (e.g., tokens in query strings) to third-party sites.

**Permissions-Policy**
Disables access to camera, geolocation, and microphone APIs. Reduces the risk of malicious scripts silently accessing sensitive device features.

**Cross-Origin-Opener-Policy: same-origin**
Isolates the browsing context from cross-origin windows. Prevents cross-origin attacks like Spectre that exploit shared memory between tabs/windows.

**Cross-Origin-Resource-Policy: same-origin**
Prevents other origins from loading this site's resources (images, scripts). Protects against cross-site resource inclusion attacks.

**Content-Security-Policy-Report-Only**
CSP in report-only mode — violations are logged but not blocked. This allows testing a CSP policy without breaking the app. Juice Shop uses inline scripts and eval extensively, so a strict enforced CSP would break functionality. Report-only mode is the correct starting point.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### TLS Scan Summary (testssl.sh)

```
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
```

**Supported cipher suites:**

TLS 1.2:
- `ECDHE-RSA-AES256-GCM-SHA384` (256-bit AESGCM, ECDH 256)
- `ECDHE-RSA-AES128-GCM-SHA256` (128-bit AESGCM, ECDH 256)

TLS 1.3:
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

**Forward Secrecy:** offered (OK) — ephemeral key exchange means past sessions can't be decrypted even if the private key is later compromised.

**HSTS:** `365 days=31536000 s, includeSubDomains, preload` ✅

**Expected NOT ok items (self-signed cert):**
- Chain of trust: NOT ok (self-signed) — expected in dev; use Let's Encrypt in production
- CRL/OCSP URI: not provided — expected without a CA
- OCSP stapling: not offered — can be enabled with a public CA cert

**Why TLSv1.2+ is required:**
TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE, CRIME) and use deprecated cipher suites. TLS 1.2 with AEAD ciphers (GCM) is the minimum acceptable standard. TLS 1.3 is preferred — it removes legacy cipher suites entirely, has a faster handshake (1-RTT), and provides better security by design.

### Rate Limiting Test

```bash
for i in $(seq 1 12); do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -X POST https://localhost:8443/rest/user/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"a@a","password":"a"}'
done
```

**Output:**
```
401  ← invalid credentials (request passed through)
401
401
401
401
401
429  ← rate limit exceeded
429
429
429
429
429
```

6 requests passed (401 = wrong password), 6 blocked (429 = Too Many Requests).

**Rate limit configuration analysis:**

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req zone=login burst=5 nodelay;
limit_req_status 429;
```

- `rate=10r/m` — allows 10 requests per minute per IP (~1 every 6 seconds). Slow enough to prevent automated brute-force but fast enough for legitimate users who mistype their password a few times.
- `burst=5` — allows a burst of 5 additional requests before rate limiting kicks in. This handles legitimate rapid retries without immediately blocking users.
- `nodelay` — burst requests are processed immediately (not queued), so legitimate users don't experience artificial delays.
- `limit_req_status 429` — returns HTTP 429 (Too Many Requests) instead of the default 503, which is the correct semantic response for rate limiting.

**Access log showing 429 responses:**
```
192.168.65.1 - - [19/Apr/2026:12:27:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [19/Apr/2026:12:27:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

Note: `rt=0.000 uct=- urt=-` — rate-limited requests are rejected immediately by Nginx without reaching the upstream app (no `uct`/`urt` values).

**Timeout settings analysis:**

```nginx
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 10s;
send_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
proxy_connect_timeout 5s;
```

- `client_body_timeout / client_header_timeout 10s` — closes connections if the client doesn't send the request body/headers within 10 seconds. Mitigates **Slowloris** attacks where attackers send headers very slowly to hold connections open indefinitely.
- `keepalive_timeout 10s` — closes idle keep-alive connections after 10 seconds, freeing resources.
- `proxy_read_timeout 30s` — if the upstream app doesn't respond within 30 seconds, Nginx returns 504. Prevents slow upstream responses from holding worker connections.
- `proxy_connect_timeout 5s` — fast failure if the upstream is unreachable, preventing connection pool exhaustion.

Trade-off: Very short timeouts improve resilience against DoS but can cause false positives for legitimate slow operations (e.g., large file uploads, slow database queries). The values chosen (10s client, 30s proxy) balance security with usability for a typical web app.
