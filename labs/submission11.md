# Lab 11 Submission — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup (2 pts)

### 1.1 Certificate Generation & Stack Startup

A self-signed certificate with SAN was generated for `localhost`, then the stack was started:

```bash
# Generate self-signed cert with SAN
docker run --rm -v "$(pwd)/reverse-proxy/certs":/certs \
  alpine:latest \
  sh -c "apk add --no-cache openssl && \
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /certs/localhost.key -out /certs/localhost.crt \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'"

# Start the compose stack
docker compose up -d
```

HTTP redirect verification:

```bash
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```

The 308 (Permanent Redirect) response confirms Nginx is receiving requests on port 8080 and redirecting to HTTPS on port 8443. HTTP 308 preserves the request method (unlike 301/302 which may downgrade POST to GET), which is important for API clients.

### 1.2 Docker Compose Stack Status

```
$ docker compose ps
NAME                  IMAGE                          STATUS          PORTS
lab11-juice-1         bkimminich/juice-shop:v19.0.0  Up 2 minutes
lab11-nginx-1         nginx:stable-alpine            Up 2 minutes    0.0.0.0:8080->8080/tcp, 0.0.0.0:8443->8443/tcp
```

**Key observation:** The `juice` container has **no published ports** — it only exposes port 3000 internally via Docker's `expose` directive (which creates no host-level firewall rule). External traffic can only reach Juice Shop through the Nginx reverse proxy.

### 1.3 Why Reverse Proxies Are Valuable for Security

**TLS termination:** The application (Juice Shop) doesn't need to implement TLS itself. The proxy handles certificate management, cipher negotiation, and decryption. This centralizes a complex security concern and means the backend runs plain HTTP on an internal Docker network that never reaches the host.

**Security header injection:** Headers like `Strict-Transport-Security`, `X-Frame-Options`, and `Content-Security-Policy` can be added at the proxy layer without modifying application code. This is especially valuable for legacy applications or third-party apps (like Juice Shop) where changing source code isn't practical.

**Request filtering and rate limiting:** The proxy can enforce policies (rate limits, body size limits, request timeouts) before traffic reaches the application. This offloads security logic from the application and provides a consistent defense point.

**Hiding internal topology:** The backend service's technology stack, server version, port, and internal address are invisible to external clients. `server_tokens off` removes the Nginx version from the `Server` header. `proxy_hide_header X-Powered-By` prevents "X-Powered-By: Express" from leaking the application framework.

**Single access point:** By publishing only Nginx ports, all traffic — including any future monitoring, WAF rules, or auth middleware — flows through one place. Without a reverse proxy, each service would need its own hardening, creating inconsistency as the fleet grows.

---

## Task 2 — Security Headers (3 pts)

### 2.1 Headers Over HTTP (308 redirect response)

```
$ curl -sI http://localhost:8080/
```

Full output saved to [labs/lab11/analysis/headers-http.txt](labs/lab11/analysis/headers-http.txt):

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; ...
```

**Note:** `Strict-Transport-Security` is intentionally absent on the HTTP response. HSTS is only meaningful over HTTPS — if sent over HTTP, it can be ignored or spoofed by attackers. The nginx.conf places HSTS exclusively in the `server { listen 8443 ssl; }` block.

### 2.2 Headers Over HTTPS (200 response)

```
$ curl -skI https://localhost:8443/
```

Full output saved to [labs/lab11/analysis/headers-https.txt](labs/lab11/analysis/headers-https.txt):

```
HTTP/2 200
server: nginx
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### 2.3 Header Analysis

**X-Frame-Options: DENY**

Prevents the site from being embedded in an `<iframe>` on any other origin. This defeats **clickjacking attacks** — where an attacker overlays a transparent frame of the target site on their own page and tricks users into clicking controls they can't see. `DENY` is the strictest setting; `SAMEORIGIN` would allow embedding only on the same domain.

**X-Content-Type-Options: nosniff**

Instructs the browser not to perform **MIME-type sniffing** — the browser must respect the `Content-Type` declared by the server. Without this header, browsers may interpret a JavaScript file served as `text/plain` as executable script, enabling **MIME-confusion attacks**. This is particularly relevant for user upload endpoints.

**Strict-Transport-Security (HSTS): max-age=31536000; includeSubDomains; preload**

Tells the browser to only contact this domain over HTTPS for the next 365 days, even if the user types `http://`. This defeats **SSL stripping attacks** (MITM that downgrades HTTPS to HTTP before the browser sends the request). `includeSubDomains` extends the policy to all subdomains. `preload` allows the domain to be added to browsers' built-in HSTS preload lists, providing protection before the user has ever visited the site.

**Critical:** HSTS is only present on the HTTPS response — confirmed by comparing `headers-http.txt` (absent) vs `headers-https.txt` (present). Sending HSTS over HTTP would be meaningless and potentially harmful.

**Referrer-Policy: strict-origin-when-cross-origin**

Controls what URL is sent in the `Referer` header when navigating to another page. `strict-origin-when-cross-origin` means:
- Same-origin navigation: sends the full URL (origin + path)
- Cross-origin navigation over HTTPS→HTTPS: sends only the origin (e.g., `https://localhost:8443/`, not the full path)
- Cross-origin navigation with downgrade (HTTPS→HTTP): sends nothing

This prevents sensitive URL paths (e.g., `/profile/12345/edit`, `/reset-password?token=abc`) from leaking to third-party analytics or advertising scripts embedded on the page.

**Permissions-Policy: camera=(), geolocation=(), microphone=()**

Disables browser APIs that could be used to silently spy on users. Empty parentheses `()` mean the feature is blocked for all origins. This header replaced the older `Feature-Policy`. Juice Shop doesn't need camera, microphone, or geolocation access, so disabling them reduces the risk from **malicious third-party scripts** or **XSS payloads** attempting to access these sensors.

**Cross-Origin-Opener-Policy (COOP): same-origin**

Prevents cross-origin documents from sharing a browsing context group with the current page. This isolates the page from windows opened by scripts on other origins, defeating **cross-window attacks** like `window.opener` abuse and some **Spectre-class side-channel attacks** that require shared memory. COOP is also required to enable `SharedArrayBuffer`, which is needed by some performance-sensitive applications.

**Cross-Origin-Resource-Policy (CORP): same-origin**

Blocks cross-origin pages from reading resources (images, scripts, JSON) served by this origin using `fetch`/`XMLHttpRequest`. This is a defense against **cross-origin data leakage** and **Spectre-based attacks** where an attacker reads the contents of a cross-origin response via a speculative execution side channel.

**Content-Security-Policy-Report-Only: default-src 'self'; ...**

Declares a Content Security Policy but only reports violations to the browser console — it does **not** block anything. This mode is used to test CSP compatibility before enforcing it. A strict CSP would mitigate **Cross-Site Scripting (XSS)** by preventing inline scripts and unauthorized external script sources. Report-only mode is appropriate for Juice Shop because:
1. Juice Shop is intentionally vulnerable and uses many inline scripts  
2. Switching to enforcement mode (`Content-Security-Policy`) would break most of its functionality
3. In a real application, you'd iterate: observe violations in report-only, adjust the policy, then enforce

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts (5 pts)

### 3.1 TLS Scan (testssl.sh)

```bash
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 \
  | tee labs/lab11/analysis/testssl.txt
```

Full output saved to [labs/lab11/analysis/testssl.txt](labs/lab11/analysis/testssl.txt).

**Protocol support:**

| Protocol | Status | Notes |
|----------|--------|-------|
| SSLv2 | Not offered | ✅ Legacy, broken by DROWN |
| SSLv3 | Not offered | ✅ Legacy, broken by POODLE |
| TLS 1.0 | Not offered | ✅ Deprecated by RFC 8996 (2021) |
| TLS 1.1 | Not offered | ✅ Deprecated by RFC 8996 (2021) |
| TLS 1.2 | Offered | ✅ Still widely needed for compatibility |
| TLS 1.3 | Offered | ✅ Preferred — faster handshake, no legacy modes |

**Cipher suites:**

```
TLS_AES_256_GCM_SHA384         (TLS 1.3)
TLS_CHACHA20_POLY1305_SHA256   (TLS 1.3)
TLS_AES_128_GCM_SHA256         (TLS 1.3)
ECDHE-RSA-AES256-GCM-SHA384    (TLS 1.2)
ECDHE-RSA-AES128-GCM-SHA256    (TLS 1.2)
DHE-RSA-AES256-GCM-SHA384      (TLS 1.2)
DHE-RSA-AES128-GCM-SHA256      (TLS 1.2)
```

All ciphers provide **forward secrecy** (ECDHE/DHE key exchange) and use **AEAD** (authenticated encryption with additional data — GCM/ChaCha20-Poly1305). No RC4, 3DES, CBC-mode, or export ciphers are present.

**Why TLSv1.2+ is required and TLSv1.3 is preferred:**

- TLS 1.0 and 1.1 use SHA-1 in the PRF (pseudorandom function) and support obsolete cipher modes (RC4, 3DES). They are banned in RFC 8996 and PCI DSS v4.0.
- TLS 1.2 is still secure when used with forward-secret, AEAD ciphers. However it requires careful configuration — the protocol supports weak ciphers (RC4, 3DES, non-FS modes) that must be explicitly disabled.
- TLS 1.3 removes all legacy cipher modes, mandates forward secrecy, and adds **0-RTT resumption** (improved latency) and **encrypted handshake metadata** (protects SNI and certificate in transit). It is simpler, faster, and has a smaller attack surface.

**Vulnerability check summary:** All tested attack vectors returned "not vulnerable (OK)": POODLE, BEAST, CRIME, BREACH, ROBOT, DROWN, FREAK, LOGJAM, LUCKY13, Heartbleed, Ticketbleed, RC4.

**Expected "NOT ok" items for self-signed cert (by design):**
- `Chain of trust: NOT ok (self signed CA in chain)` — No CA has signed this certificate. Browsers will show a security warning. In production, this would be replaced with a Let's Encrypt or corporate CA certificate.
- `OCSP URI: --` — No OCSP endpoint in the certificate (self-signed certs don't have one)
- `OCSP stapling: not offered` — Disabled in nginx.conf (`ssl_stapling off`). OCSP stapling would allow the server to attach a pre-fetched OCSP response to the TLS handshake, proving the certificate hasn't been revoked without requiring the client to contact the CA. Enabled for publicly trusted certs.
- `DNS CAA RR: not offered` — No Certification Authority Authorization DNS record exists for `localhost`. In production, CAA records restrict which CAs can issue certificates for your domain.

**HSTS verification:** HSTS appeared only in the HTTPS response (`headers-https.txt`), not in the HTTP redirect response (`headers-http.txt`). The testssl.sh scan confirmed `Strict-Transport-Security` in the HTTPS headers section.

### 3.2 Rate Limiting Test

```bash
for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done | tee labs/lab11/analysis/rate-limit-test.txt
```

**Results** ([labs/lab11/analysis/rate-limit-test.txt](labs/lab11/analysis/rate-limit-test.txt)):

```
200  ← request 1
200  ← request 2
200  ← request 3
200  ← request 4
200  ← request 5
200  ← request 6  (burst exhausted)
429  ← request 7
429  ← request 8
429  ← request 9
429  ← request 10
429  ← request 11
429  ← request 12
```

**Summary:** 6 requests succeeded, 6 returned HTTP 429 Too Many Requests.

**Rate limit configuration analysis:**

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
# ...
location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_status 429;
```

- `rate=10r/m` — allows 10 requests per minute per IP address (1 token every 6 seconds)
- `burst=5` — an IP can consume up to 5 tokens in advance (token bucket algorithm). Combined with the 1 token always present in the bucket, this allows 6 requests before the burst is exhausted.
- `nodelay` — queued burst requests are served immediately (not delayed). Without `nodelay`, Nginx would serve them at the token refill rate (1 per 6s), causing long delays. With `nodelay`, the burst is consumed instantly, then excess requests are immediately rejected with 429.
- `limit_req_status 429` — returns HTTP 429 ("Too Many Requests") instead of the default 503, correctly communicating rate limiting semantics to clients per RFC 6585.

**Why these values balance security vs usability:**

- 10 requests/minute is generous for legitimate login attempts. A human user rarely has to retry login more than 1-2 times. A brute-force tool attempting to guess passwords would be severely slowed: at 10 req/min, a 100,000 candidate list would take ~7 days per IP.
- `burst=5` accommodates brief legitimate spikes — e.g., a page that makes multiple API calls on load, or a user who double-clicks the login button. Without burst, the first exceeded request would be blocked.
- For higher-security contexts (financial apps), values like `rate=5r/m, burst=3` would be more appropriate. For public APIs with token auth, `rate=60r/m` might be needed for legitimate use cases.

### 3.3 Timeout Settings Analysis

From [labs/lab11/reverse-proxy/nginx.conf](labs/lab11/reverse-proxy/nginx.conf):

```nginx
# In the HTTPS server block:
client_body_timeout  10s;
client_header_timeout 10s;
keepalive_timeout    10s;

# Global proxy settings:
proxy_read_timeout   30s;
proxy_send_timeout   30s;
proxy_connect_timeout 5s;
```

**`client_body_timeout 10s`** — Maximum time between successive read operations for reading the request body. If the client doesn't send data within 10 seconds, Nginx returns 408 Request Timeout. This defeats **Slowloris-style attacks** on the request body phase, where an attacker trickle-sends data just fast enough to keep the connection alive, exhausting worker connections.

**`client_header_timeout 10s`** — Maximum time to read the request headers. Protects against the same Slowloris pattern at the header phase. A legitimate browser sends headers in milliseconds; only a deliberately slow attacker would take 10+ seconds.

**`keepalive_timeout 10s`** — After a request completes, how long to keep the TCP connection open for reuse. Setting this to 10s (vs. the default 75s) reduces the number of idle connections that an attacker can hold open. The trade-off: legitimate clients that send requests less frequently than 10s apart will need to re-establish the TCP connection, adding ~1ms latency per reconnect. Acceptable for an application with interactive users (vs. a high-frequency API).

**`proxy_read_timeout 30s`** — Maximum time to wait for the upstream (Juice Shop) to send data after the request is forwarded. If Juice Shop is processing a long request (heavy DB query, file generation), it must complete within 30 seconds or Nginx returns 504 Gateway Timeout. **Trade-off:** Long-running legitimate operations (e.g., large file uploads, complex reports) may timeout. The appropriate value depends on the application's expected response time; 30s is a reasonable default for a web UI.

**`proxy_send_timeout 30s`** — Maximum time between successive write operations back to the upstream. Rarely triggered in practice (usually only if the upstream is completely hung).

**`proxy_connect_timeout 5s`** — Maximum time to establish a TCP connection to the upstream. If Juice Shop is overloaded or crashed, Nginx fails fast (5s) and returns 502 Bad Gateway, rather than queuing requests indefinitely.

**Overall trade-off:** Short timeouts improve resilience against DoS and connection exhaustion at the cost of potentially timing out legitimate slow operations. The values in this nginx.conf are conservative — suitable for a typical interactive web application but may need tuning for APIs with known long-running operations.

### 3.4 Access Log — 429 Responses

From [labs/lab11/logs/access.log](labs/lab11/logs/access.log):

```
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 200 248 "-" "curl/8.7.1" rt=0.089 uct=0.002 urt=0.087
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 200 248 "-" "curl/8.7.1" rt=0.041 uct=0.001 urt=0.040
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 200 248 "-" "curl/8.7.1" rt=0.038 uct=0.001 urt=0.037
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 200 248 "-" "curl/8.7.1" rt=0.037 uct=0.001 urt=0.036
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 200 248 "-" "curl/8.7.1" rt=0.035 uct=0.001 urt=0.035
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 200 248 "-" "curl/8.7.1" rt=0.034 uct=0.001 urt=0.034
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 429 177 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 429 177 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
172.20.0.1 - - [09/Mar/2026:11:27:03 +0000] "POST /rest/user/login HTTP/2.0" 429 177 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
172.20.0.1 - - [09/Mar/2026:11:27:04 +0000] "POST /rest/user/login HTTP/2.0" 429 177 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
172.20.0.1 - - [09/Mar/2026:11:27:04 +0000] "POST /rest/user/login HTTP/2.0" 429 177 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
172.20.0.1 - - [09/Mar/2026:11:27:04 +0000] "POST /rest/user/login HTTP/2.0" 429 177 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

The log format is `security` (defined in nginx.conf): `rt` = total request time, `uct` = upstream connect time, `urt` = upstream response time.

**Notable observations from the 429 log entries:**
- `rt=0.000` — rate-limited requests are rejected by Nginx instantly, before any upstream connection is attempted
- `uct=-` and `urt=-` — no upstream connection was made; Juice Shop was protected from the brute-force traffic entirely
- All 12 requests came from the same IP (`172.20.0.1`), demonstrating the per-IP rate limiting working correctly

---

## Cleanup

```bash
cd labs/lab11
docker compose down
```
