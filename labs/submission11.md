# Lab 11 Submission — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

---

## Task 1 — Reverse Proxy Compose Setup

### Why reverse proxies are valuable for security

A reverse proxy sits between external clients and backend application servers. It provides several security benefits without requiring any changes to the application:

- **TLS termination** — the proxy handles certificate management and HTTPS; the backend app can use plain HTTP internally.
- **Security headers injection** — headers like `X-Frame-Options`, `HSTS`, or `CSP` are injected at the proxy, enforcing policy regardless of what the app sends.
- **Request filtering and rate limiting** — the proxy can block or throttle bad traffic before it reaches the app.
- **Single access point** — all inbound traffic flows through one choke point, making monitoring, logging, and policy enforcement easier.

### Why hiding direct app ports reduces attack surface

When the Juice Shop container uses `expose: "3000"` (not `ports:`), port 3000 is only reachable inside the Docker network — not from the host or the internet. This means:

- Attackers cannot bypass the proxy's security controls by connecting directly to the app.
- The app's own headers (weaker, uncontrolled) are never seen by clients.
- The number of externally visible services is minimized, reducing the number of potential entry points.

### `docker compose ps` output

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     20 seconds ago   Up 19 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     20 seconds ago   Up 18 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

`juice` exposes port 3000 only internally (`3000/tcp` — no host binding). `nginx` is the only container with published host ports (`8080`, `8443`).

---

## Task 2 — Security Headers

### Headers captured over HTTPS (`headers-https.txt`)

```
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 20 Apr 2026 09:16:35 GMT
Content-Type: text/html; charset=UTF-8
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Header explanations

**X-Frame-Options: DENY**
Prevents the page from being embedded in an `<iframe>` on any other origin. Mitigates **clickjacking** attacks, where an attacker overlays invisible frames to trick users into clicking malicious content.

**X-Content-Type-Options: nosniff**
Tells browsers not to sniff (guess) the MIME type of a response and to use only the declared `Content-Type`. Prevents **MIME-type confusion attacks** where a browser might execute a file as JavaScript even if it was served as `text/plain`.

**Strict-Transport-Security (HSTS): max-age=31536000; includeSubDomains; preload**
Forces browsers to use HTTPS for all future connections to this domain for one year, including subdomains. Mitigates **SSL-stripping attacks** and protocol downgrade attacks. The `preload` flag allows the domain to be included in browser HSTS preload lists, so HTTPS is enforced even on the very first visit.

Note: HSTS appears **only in `headers-https.txt`** (HTTPS response) and is absent from `headers-http.txt` (HTTP/308 redirect). This is correct — sending HSTS over HTTP provides no security benefit since the connection is already unencrypted.

**Referrer-Policy: strict-origin-when-cross-origin**
On same-origin requests the full URL is sent as the `Referer` header. On cross-origin requests, only the origin (scheme + host) is sent, and nothing is sent when downgrading from HTTPS to HTTP. Prevents **leaking sensitive URL parameters** (e.g., tokens, search terms) to third-party sites.

**Permissions-Policy: camera=(), geolocation=(), microphone=()**
Disables browser APIs for camera, geolocation, and microphone for this page and all embedded frames. Limits the potential impact of **XSS or malicious iframes** trying to access device hardware without user awareness.

**Cross-Origin-Opener-Policy (COOP): same-origin**
Isolates the browsing context so that cross-origin windows cannot access `window.opener`. Mitigates **cross-origin information leaks and Spectre-style side-channel attacks** that rely on shared memory between tabs.

**Cross-Origin-Resource-Policy (CORP): same-origin**
Prevents other origins from loading this site's resources (images, scripts, etc.) via `<img>`, `<script>`, `fetch`, etc. Defends against **cross-origin data leakage** and Spectre-type attacks that can read cross-origin pixel data.

**Content-Security-Policy-Report-Only**
`default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'`

Defines a Content Security Policy that is **not enforced** — violations are only reported (to the browser console). Allows observing what a strict CSP would block before enforcing it. Mitigates **XSS** by restricting which sources scripts, styles, and images may load from. Juice Shop uses inline scripts and `eval`, so enforcing a strict CSP would break the app; Report-Only mode allows monitoring without breaking functionality.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### TLS / testssl.sh Summary

**Scan target:** `https://host.docker.internal:8443`
**Tool:** testssl.sh 3.2.3

#### Protocol support

| Protocol | Status |
|----------|--------|
| SSLv2    | Not offered (OK) |
| SSLv3    | Not offered (OK) |
| TLS 1.0  | Not offered |
| TLS 1.1  | Not offered |
| TLS 1.2  | **Offered (OK)** |
| TLS 1.3  | **Offered (OK)** |
| HTTP/2   | Offered via ALPN |

#### Cipher suites supported

**TLSv1.2:**
- `ECDHE-RSA-AES256-GCM-SHA384` (ECDH 256 bit)
- `ECDHE-RSA-AES128-GCM-SHA256` (ECDH 256 bit)

**TLSv1.3:**
- `TLS_AES_256_GCM_SHA384` (ECDH/MLKEM)
- `TLS_CHACHA20_POLY1305_SHA256` (ECDH/MLKEM)
- `TLS_AES_128_GCM_SHA256` (ECDH/MLKEM)

All suites provide **forward secrecy (FS)** — compromise of the server's private key does not expose past session traffic.

#### Why TLSv1.2+ is required (prefer TLSv1.3)

TLS 1.0 and 1.1 are deprecated (RFC 8996) due to design weaknesses: CBC padding oracle attacks (POODLE, LUCKY13, BEAST), weak MAC construction, and no support for modern AEAD ciphers. TLS 1.2 with AEAD ciphers (GCM) addresses these issues. TLS 1.3 is preferred because it removes legacy cipher suites entirely, reduces the handshake to 1-RTT (faster), and has no known protocol-level vulnerabilities.

#### Vulnerability scan results

All classical TLS vulnerabilities returned **not vulnerable (OK)**:

| Vulnerability | Result |
|---|---|
| Heartbleed (CVE-2014-0160) | Not vulnerable |
| CCS Injection (CVE-2014-0224) | Not vulnerable |
| POODLE SSL (CVE-2014-3566) | Not vulnerable — no SSLv3 |
| SWEET32 | Not vulnerable |
| FREAK | Not vulnerable |
| LOGJAM | Not vulnerable |
| BEAST | Not vulnerable — no TLS 1.0 |
| LUCKY13 | Not vulnerable |
| RC4 | No RC4 ciphers detected |
| BREACH | Not vulnerable — gzip disabled (`gzip off` in nginx.conf) |

#### Warnings (expected for a local dev cert)

- **Chain of trust: NOT ok (self-signed)** — the certificate is its own CA. Browsers will show a warning. In production, use a certificate from a public CA (e.g., Let's Encrypt).
- **Certificate does not match supplied URI** — testssl connected to `host.docker.internal` but the cert's CN/SAN is `localhost`/`127.0.0.1`. Expected; for production, match the SAN to the actual domain.
- **Neither CRL nor OCSP URI provided** — no revocation mechanism. Expected for a self-signed cert; real CAs provide OCSP endpoints.
- **OCSP stapling: not offered** — disabled intentionally in `nginx.conf` (`ssl_stapling off`) since there is no OCSP responder for a self-signed cert.
- **DNS CAA RR: not offered** — no DNS record restricting which CAs may issue certificates for this domain. Irrelevant for localhost/dev.
- **Overall grade: T** — capped because of self-signed cert. All cryptographic controls are properly configured; the grade reflects the certificate trust issue only.

#### HSTS verification

HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`) is present in the HTTPS response headers and confirmed by testssl ("365 days, includeSubDomains, preload"). It is **absent from the HTTP (port 8080) response**, which is correct — HSTS over HTTP is meaningless and could cause issues.

---

### Rate Limiting & Timeouts

#### Rate limit test results (`analysis/rate-limit-test.txt`)

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

- **6 × 401** — requests passed through to Juice Shop; credentials were wrong, so app returned 401 Unauthorized.
- **6 × 429** — Nginx rejected the requests before they reached the app: Too Many Requests.

Out of 12 rapid-fire login attempts, 50% were blocked by the rate limiter.

#### Rate limit configuration explained

From `nginx.conf`:
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req zone=login burst=5 nodelay;
limit_req_status 429;
```

- **`rate=10r/m`** — allows 10 login requests per minute per IP (one every 6 seconds). This is enough for legitimate users who won't attempt login more than a few times per minute, but effectively throttles brute-force tools that make hundreds of requests per second.
- **`burst=5`** — allows a temporary burst of up to 5 extra requests above the rate before rejecting. This prevents legitimate users from being blocked if they make a few rapid retries (e.g., mistyped password twice quickly), while still capping sustained attacks.
- **`nodelay`** — burst requests are processed immediately (not queued and delayed). Without `nodelay`, burst requests would be queued and served slowly, which can cause legitimate UX problems and still doesn't block the attacker quickly.

**Trade-offs:**
- A stricter rate (e.g., `5r/m`, `burst=2`) would catch attackers faster but could frustrate users on slow connections or corporate NAT (many users share one IP).
- A looser rate (e.g., `100r/m`) gives attackers more attempts per minute, reducing the protection value.
- `10r/m` / `burst=5` balances usability for normal users with meaningful throttling of brute-force attempts.

#### Access log — 429 responses

```
172.19.0.1 - - [20/Apr/2026:09:20:24 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.2.1" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:09:20:24 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.2.1" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:09:20:24 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.2.1" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:09:20:25 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.2.1" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:09:20:25 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.2.1" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:09:20:25 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.2.1" rt=0.000 uct=- urt=-
```

`rt=0.000` and `uct=-`/`urt=-` confirm the requests were rejected entirely by Nginx (no upstream connection was made), meaning the backend never saw the flood.

#### Timeout settings explained

From `nginx.conf` (HTTPS server block):

```nginx
client_body_timeout   10s;
client_header_timeout 10s;
keepalive_timeout     10s;
send_timeout          10s;
proxy_read_timeout    30s;
proxy_send_timeout    30s;
proxy_connect_timeout  5s;
```

| Timeout | Purpose | Trade-off |
|---|---|---|
| `client_body_timeout 10s` | Max time to receive the request body after the first byte. Mitigates **Slowloris-style body attacks** where an attacker drip-sends data to hold a connection open indefinitely. | Too short may disconnect slow mobile clients on large uploads. |
| `client_header_timeout 10s` | Max time to receive the full request headers. Mitigates **slow header attacks**. | Too short may affect clients on very slow links. |
| `keepalive_timeout 10s` | How long an idle keep-alive connection is kept open. Limits resource exhaustion from clients holding many idle connections. | Very short values increase TLS handshake overhead for legitimate clients. |
| `send_timeout 10s` | Max time between successive writes to the client. Disconnects clients that stop reading responses (possible DoS vector). | May prematurely close connections for users on slow downloads. |
| `proxy_read_timeout 30s` | Max time to wait for the upstream app to send a response. Prevents Nginx from hanging forever if Juice Shop is slow or stuck. | If legitimate requests take >30 s (heavy reports, etc.), they will timeout. |
| `proxy_send_timeout 30s` | Max time to send a request to the upstream app. Releases connections to a stalled upstream. | Same as above for slow app ingestion. |
| `proxy_connect_timeout 5s` | Max time to establish a TCP connection to the upstream. Fails fast if Juice Shop is down, rather than hanging. | Should be short — 5 s is appropriate for a local Docker network. |

**Overall trade-off:** Short timeouts protect server resources and mitigate slow-attack DoS vectors, but can cause false positives for legitimate slow clients or heavy operations. The values chosen (10 s client, 30 s proxy) are reasonable for an interactive web application; they would need adjustment for file-upload or long-polling use cases.

---

## Acceptance Criteria Checklist

- [x] Nginx reverse proxy running; Juice Shop not directly exposed to host
- [x] Security headers present over HTTP/HTTPS; HSTS only on HTTPS
- [x] TLS enabled and scanned with testssl.sh; HSTS verified; outputs captured under `labs/lab11/analysis/`
- [x] Rate limiting returns 429 on excessive login attempts; access log lines captured; timeouts documented with trade-offs
