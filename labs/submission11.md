# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### Why reverse proxies are valuable for security

A reverse proxy sits between external clients and backend application servers, providing several security benefits:
- **TLS termination**: Handles encryption/decryption centrally so each microservice doesn't need its own certificate management
- **Security headers injection**: Security headers can be enforced at the proxy layer without touching application code, reducing risk of inconsistencies
- **Request filtering**: Rate limiting, IP allowlisting, and WAF rules can be applied uniformly before requests reach the app
- **Single access point**: All traffic flows through one controlled entry point, simplifying monitoring, logging, and incident response

### Why hiding direct app ports reduces attack surface

When Juice Shop's port (3000) is not published to the host, external attackers cannot reach the application directly. All requests must pass through Nginx, which enforces TLS, injects security headers, applies rate limits, and strips sensitive upstream headers. Without the proxy:
- Attackers can bypass header policies by hitting the app directly
- Rate limiting is circumvented
- TLS is bypassed, exposing credentials in transit
- Nginx access logs lose visibility of direct attacks

### `docker compose ps` output

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     Up seconds       Up seconds     3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     Up seconds       Up seconds     0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Juice Shop shows only `3000/tcp` (internal only, no `->` host port mapping). Nginx publishes 8080 and 8443 to the host.

HTTP redirect confirmed:
```
HTTP 308
```

---

## Task 2 — Security Headers

### Headers from `headers-https.txt`

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

### Header explanations

**X-Frame-Options: DENY**
Prevents the page from being loaded in an `<iframe>`, `<frame>`, or `<object>` on any origin. Protects against clickjacking attacks where an attacker embeds the victim site in a transparent overlay to trick users into clicking malicious UI elements.

**X-Content-Type-Options: nosniff**
Instructs browsers not to MIME-sniff the response content type away from the declared `Content-Type`. Without this, browsers might execute a response as JavaScript even if served as `text/plain`. Prevents content-type confusion attacks and drive-by script execution via user-uploaded files.

**Strict-Transport-Security (HSTS): max-age=31536000; includeSubDomains; preload**
Tells browsers to only communicate with this domain over HTTPS for the next 365 days, even if the user types `http://`. Prevents SSL-stripping attacks (MITM downgrades) and protocol downgrade attacks. `includeSubDomains` extends this to all subdomains; `preload` opts into browser preload lists so HSTS is enforced on first visit too. HSTS is present only on the HTTPS server block — confirmed absent from HTTP 308 response.

**Referrer-Policy: strict-origin-when-cross-origin**
On same-origin requests the full URL is sent as `Referer`; on cross-origin requests only the origin (scheme + host + port) is sent; on downgrade (HTTPS → HTTP) nothing is sent. Limits information leakage of sensitive URL paths (e.g., password reset tokens, session IDs in URLs) to third parties.

**Permissions-Policy: camera=(), geolocation=(), microphone=()**
Restricts which browser APIs the page and embedded content may access. Empty `()` means the feature is disabled for all origins including the page itself. Reduces the blast radius if XSS is exploited — attacker JS cannot silently activate the camera, microphone, or location API.

**Cross-Origin-Opener-Policy (COOP): same-origin**
Isolates the browsing context from cross-origin documents. Prevents cross-origin windows opened via `window.open()` from retaining a reference back to this window. Required to enable `SharedArrayBuffer` safely and mitigates Spectre-class side-channel attacks that leak data across browsing contexts.

**Cross-Origin-Resource-Policy (CORP): same-origin**
Prevents other origins from loading this site's resources (images, scripts, fonts) via `<img>`, `<script>`, etc. Mitigates cross-origin information leakage and complements COOP to close the cross-origin isolation loop.

**Content-Security-Policy-Report-Only**
In report-only mode, the policy is not enforced — violations are reported (to a `report-uri` if configured) but the page continues to load. Set to `default-src 'self'` with loose `script-src` to avoid breaking Juice Shop's inline scripts. Allows teams to observe what a strict CSP would block before enforcing it, de-risking CSP rollout.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### TLS / testssl.sh summary

**Protocol support:**
- SSLv2: not offered (OK)
- SSLv3: not offered (OK)
- TLS 1.0: not offered
- TLS 1.1: not offered
- TLS 1.2: **offered (OK)**
- TLS 1.3: **offered (OK)**
- HTTP/2 (ALPN): offered

**Cipher suites (TLSv1.3):**
| Cipher | Key Exchange | Encryption | Bits |
|--------|-------------|-----------|------|
| TLS_AES_256_GCM_SHA384 | ECDH/MLKEM | AESGCM | 256 |
| TLS_CHACHA20_POLY1305_SHA256 | ECDH/MLKEM | ChaCha20 | 256 |
| TLS_AES_128_GCM_SHA256 | ECDH/MLKEM | AESGCM | 128 |

**Cipher suites (TLSv1.2):**
| Cipher | Key Exchange | Encryption | Bits |
|--------|-------------|-----------|------|
| ECDHE-RSA-AES256-GCM-SHA384 | ECDH 256 | AESGCM | 256 |
| ECDHE-RSA-AES128-GCM-SHA256 | ECDH 256 | AESGCM | 128 |

All offered ciphers use AEAD modes with Forward Secrecy — no RC4, 3DES, CBC, or NULL ciphers.

**Why TLSv1.2+ is required (prefer TLSv1.3):**
TLS 1.0 and 1.1 are deprecated (RFC 8996) because they rely on MD5/SHA-1 for MAC, are vulnerable to BEAST, POODLE, and CRIME, and do not support AEAD cipher suites. TLS 1.2 mandates SHA-2 and introduces AEAD but still requires careful cipher selection to avoid CBC-mode ciphers. TLS 1.3 eliminates all legacy cipher suites, reduces the handshake to 1-RTT (or 0-RTT), and mandates forward secrecy — making it significantly more resistant to passive decryption of recorded traffic.

**Vulnerability scan results:**
All known TLS vulnerabilities came back NOT vulnerable:
- Heartbleed (CVE-2014-0160): not vulnerable
- CCS injection (CVE-2014-0224): not vulnerable
- POODLE SSLv3: not vulnerable (no SSLv3)
- BEAST: not vulnerable (no TLS 1.0)
- CRIME/BREACH: not vulnerable (gzip disabled)
- SWEET32: not vulnerable (no 3DES)
- FREAK/DROWN/LOGJAM: not vulnerable
- RC4: no RC4 ciphers detected
- ROBOT: server does not use RSA key transport

**Expected "NOT ok" items for self-signed cert (dev environment):**
- Chain of trust: NOT ok (self-signed) — expected; use Let's Encrypt or mkcert for prod
- CRL/OCSP URI: NOT ok — no revocation infrastructure for self-signed certs
- OCSP stapling: not offered — disabled in nginx.conf (`ssl_stapling off`); enable with a real CA
- DNS CAA RR: not offered — no DNS zone for localhost
- Certificate Transparency: absent — only meaningful for publicly-trusted certs

**HSTS verification:**
HSTS header appears only on the HTTPS server block response, confirmed absent from the HTTP 308 redirect headers. This is correct behavior — sending HSTS on a plain-HTTP response would be ignored by browsers and could cause confusion.

HTTP headers (no HSTS):
```
HTTP/1.1 308 Permanent Redirect
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: ...
```
(No `Strict-Transport-Security` header on HTTP.)

HTTPS headers (HSTS present):
```
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

---

### Rate limiting & timeouts

**Rate-limit test output (`analysis/rate-limit-test.txt`):**

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

12 rapid POST requests to `/rest/user/login`:
- 6 requests returned **401** (authenticated, reached Juice Shop — burst allowance consumed)
- 6 requests returned **429** (blocked by Nginx rate limiter)

**Rate limit configuration analysis:**

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req zone=login burst=5 nodelay;
limit_req_status 429;
```

- `rate=10r/m` — allows 10 requests per minute per IP (≈ 1 every 6 seconds). A real user authenticating normally will never hit this; an automated brute-force script will be throttled almost immediately.
- `burst=5` — allows a short burst of up to 5 additional requests without delay before the rate limit kicks in. Without a burst allowance, even a user who clicks "Login" twice quickly could get a 429.
- `nodelay` — burst requests are served immediately (not queued and delayed), but they still consume burst tokens. Without `nodelay`, Nginx would delay burst requests to smooth them to `rate`. With `nodelay` it serves them fast and then hard-blocks once tokens are exhausted — preferable UX because legitimate users get immediate feedback.
- **Security vs usability balance**: 10 req/min is generous for manual logins (most users attempt 1-3 times) but makes credential stuffing and brute-force attacks ~600x slower than a typical 100 req/s attack tool. The burst=5 prevents false positives for users on unstable connections who reload quickly.

**Timeout settings (`nginx.conf`) and trade-offs:**

| Directive | Value | Purpose | Trade-off |
|-----------|-------|---------|-----------|
| `client_body_timeout 10s` | 10 s | Max time between consecutive reads of the client request body. | Low value stops Slowloris-style body exhaustion attacks; too low breaks slow mobile POSTs |
| `client_header_timeout 10s` | 10 s | Max time to receive the full request headers. | Mitigates slow HTTP header attacks; aggressive clients on bad networks may see errors |
| `proxy_read_timeout 30s` | 30 s | How long to wait for a response chunk from the upstream app. | Allows app startup / slow DB queries; too high leaves connections open during DoS |
| `proxy_send_timeout 30s` | 30 s | Max time between writes to the upstream. | Prevents half-open proxy connections consuming resources |
| `keepalive_timeout 10s` | 10 s (HTTPS), 10 s (global) | How long idle keepalive connections are held open. | Short value frees file descriptors quickly; clients may need to reconnect more often |

The combination of short client timeouts (10 s) and moderate proxy timeouts (30 s) is tuned against Slowloris and slow-read DoS variants while being lenient enough for the Juice Shop's Node.js backend.

**Access log entries showing 429 responses:**

```
172.22.0.1 - - [20/Apr/2026:12:07:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.81.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:12:07:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.81.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:12:07:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.81.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:12:07:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.81.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:12:07:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.81.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:12:07:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.81.0" rt=0.000 uct=- urt=-
```

`rt=0.000` and `uct=-` confirm Nginx returned 429 without forwarding the request to the upstream (`urt=-` means no upstream response time — request was rejected at the proxy layer).
