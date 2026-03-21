# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

**Name:** Baha Alimi
**Branch:** `feature/lab11`
**Target:** `bkimminich/juice-shop:v19.0.0` behind `nginx:stable-alpine`

---

## Task 1 — Reverse Proxy Compose Setup

### 1.1 Stack Deployment

Generated a self-signed TLS certificate with SAN for localhost, then started the stack:

```powershell
docker run --rm -v "${PWD}/reverse-proxy/certs:/certs" alpine:latest sh -c \
  "apk add --no-cache openssl && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /certs/localhost.key -out /certs/localhost.crt \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'"

docker compose up -d
```

**HTTP redirect verification:**
```
curl.exe -s -o NUL -w "HTTP %{http_code}" http://localhost:8080/
HTTP 308
```

HTTP 308 confirms Nginx is redirecting all plain HTTP traffic to HTTPS as expected.

### 1.2 Port Exposure — Only Nginx Has Published Host Ports

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     27 seconds ago   Up 24 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     26 seconds ago   Up 23 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

`lab11-juice-1` shows `3000/tcp` with no host port binding — it is only reachable on the internal Docker network (`lab11_default`) by the Nginx container. The host has no direct route to port 3000.

### Why Reverse Proxies Are Valuable for Security

A reverse proxy acts as the single entry point for all inbound traffic, providing several security benefits that are impossible or impractical to implement inside the application itself:

1. **TLS termination** — The proxy handles certificate management and TLS negotiation, offloading cryptographic overhead from the application and ensuring consistent TLS policy regardless of the app's own capabilities.
2. **Security header injection** — Headers like HSTS, CSP, and X-Frame-Options can be added centrally at the proxy for every response, without modifying application code. This is especially valuable for legacy or third-party applications.
3. **Request filtering** — Rate limiting, body size limits, and connection timeouts are enforced at the proxy before the request reaches the application, reducing the blast radius of DoS attacks.
4. **Single access point** — All traffic passes through one controlled chokepoint, simplifying logging, auditing, and WAF integration.

### Why Hiding Direct App Ports Reduces Attack Surface

When Juice Shop's port 3000 is not published to the host, an attacker on the host or network cannot reach the application directly. Any request must pass through Nginx, which enforces all configured security controls — rate limiting, header injection, TLS, and connection timeouts. Exposing the app port directly creates a bypass path where all proxy-level protections can be circumvented entirely, reverting to the raw application with none of the hardening applied.

---

## Task 2 — Security Headers

### 2.1 Headers Over HTTP (port 8080)

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Sat, 21 Mar 2026 07:18:51 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Note: `Strict-Transport-Security` is correctly **absent** on the HTTP response — HSTS is only sent over HTTPS to avoid browsers caching an HSTS policy received over an untrustworthy channel.

### 2.2 Headers Over HTTPS (port 8443)

```
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 21 Mar 2026 07:19:12 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 75002
Connection: keep-alive
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

All 8 security headers are present. HSTS appears only on HTTPS as required.

### 2.3 Header Analysis

**X-Frame-Options: DENY**
Prevents the page from being embedded in an `<iframe>`, `<frame>`, or `<object>` on any other origin. This stops clickjacking attacks where an attacker overlays an invisible iframe over a trusted page to trick users into clicking on hidden elements — for example, silently submitting a form or changing account settings.

**X-Content-Type-Options: nosniff**
Instructs browsers not to MIME-sniff the `Content-Type` of responses. Without this header, Internet Explorer and older browsers may interpret a JavaScript file served as `text/plain` as executable script if the content looks like code. This prevents content-type confusion attacks where an attacker uploads a file that gets re-interpreted as a different, more dangerous type.

**Strict-Transport-Security: max-age=31536000; includeSubDomains; preload**
Tells browsers to only contact this origin over HTTPS for the next 365 days, even if the user types `http://`. `includeSubDomains` extends this policy to all subdomains. `preload` opts the domain into browser-maintained HSTS preload lists so the protection applies on the very first visit. This eliminates SSL stripping attacks where a MITM downgrades HTTPS connections to HTTP before the browser has a chance to redirect. HSTS is only sent over HTTPS responses — setting it on an HTTP response would allow an attacker to poison the policy via a MITM.

**Referrer-Policy: strict-origin-when-cross-origin**
Controls what URL information is sent in the `Referer` header when a user navigates away from the page. `strict-origin-when-cross-origin` sends the full URL on same-origin navigations (useful for analytics) but only the origin (no path or query) on cross-origin requests, and nothing at all when downgrading from HTTPS to HTTP. This prevents sensitive URL parameters (e.g. password reset tokens, session identifiers in query strings) from leaking to third-party services via referrer headers.

**Permissions-Policy: camera=(), geolocation=(), microphone=()**
Restricts which browser features the page is allowed to use. The empty parentheses `()` deny the feature entirely, even if JavaScript requests it. This limits the impact of XSS attacks — a script injected into the page cannot access the camera, microphone, or location without this policy. It also prevents third-party iframes embedded in the page from accessing these APIs.

**Cross-Origin-Opener-Policy: same-origin**
Isolates the browsing context group so that cross-origin documents cannot access the `window` object of this page via `window.open()` or `window.opener`. This prevents cross-origin information leakage and is a prerequisite for enabling cross-origin isolation, which in turn allows use of high-resolution timers and `SharedArrayBuffer` safely.

**Cross-Origin-Resource-Policy: same-origin**
Prevents other origins from loading this page's resources (images, scripts, data) via `<img src>`, `<script src>`, or `fetch()`. Without this header, a malicious site could embed resources from this server and use side-channel timing attacks to infer information from the response. `same-origin` restricts resource loading to same-origin requestors only.

**Content-Security-Policy-Report-Only**
```
default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
Defines a Content Security Policy that the browser evaluates and reports violations for, but does not enforce. This is used in Report-Only mode to avoid breaking Juice Shop's Angular frontend (which requires `'unsafe-inline'` and `'unsafe-eval'` for its runtime). In production, violations would be reported to a CSP reporting endpoint, allowing iterative policy tightening without breaking the application. Once a strict policy is validated, switching from `Content-Security-Policy-Report-Only` to `Content-Security-Policy` enforces it and is the primary defence against XSS — even if an attacker injects a script, the browser will refuse to execute it if it doesn't match the policy.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### 3.1 TLS Scan Summary (testssl.sh)

**Command:**
```powershell
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 | Tee-Object -FilePath analysis/testssl.txt
```

#### Protocol Support

| Protocol | Status |
|----------|--------|
| SSLv2 | Not offered ✅ |
| SSLv3 | Not offered ✅ |
| TLS 1.0 | Not offered ✅ |
| TLS 1.1 | Not offered ✅ |
| TLS 1.2 | Offered ✅ |
| TLS 1.3 | Offered (final) ✅ |
| HTTP/2 (ALPN) | h2, http/1.1 ✅ |

SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are all disabled — these legacy protocols contain known critical vulnerabilities (POODLE, BEAST, DROWN) and are not supported by any modern compliance framework.

#### Cipher Suites

**TLS 1.2 (server order):**

| OpenSSL Name | Key Exchange | Encryption | Bits |
|---|---|---|---|
| ECDHE-RSA-AES256-GCM-SHA384 | ECDH 256 | AESGCM | 256 |
| ECDHE-RSA-AES128-GCM-SHA256 | ECDH 256 | AESGCM | 128 |

**TLS 1.3 (server order):**

| IANA Name | Key Exchange | Encryption | Bits |
|---|---|---|---|
| TLS_AES_256_GCM_SHA384 | ECDH/MLKEM | AESGCM | 256 |
| TLS_CHACHA20_POLY1305_SHA256 | ECDH/MLKEM | ChaCha20 | 256 |
| TLS_AES_128_GCM_SHA256 | ECDH/MLKEM | AESGCM | 128 |

All cipher suites use AEAD encryption (authenticated encryption with associated data) and all TLS 1.2 suites use ECDHE key exchange providing Perfect Forward Secrecy. No weak ciphers (RC4, 3DES, export-grade, NULL) were offered.

#### Why TLSv1.2+ Is Required (Preferring TLSv1.3)

TLS 1.0 and 1.1 are deprecated by RFC 8996 and contain exploitable weaknesses — BEAST exploits a CBC mode weakness in TLS 1.0, and POODLE can downgrade TLS to SSLv3. TLS 1.2 remains secure when configured with AEAD cipher suites and ECDHE key exchange, which this configuration does. TLS 1.3 is preferred because it removes all legacy cipher suites entirely, reduces the handshake to one round trip (improving performance), and mandates forward secrecy for every connection. All modern browsers and clients support TLS 1.3 — the client simulation confirms that Android 9+, Chrome 101+, Firefox 100+, Edge 101+, and all modern Safari versions negotiate TLS 1.3. Older clients (IE 8/11, Java 7, Android 7) that cannot negotiate TLS 1.2+ receive no connection, which is the correct outcome.

#### Vulnerability Scan Results

All classic TLS vulnerabilities are not present:

- **Heartbleed** — Not vulnerable (no heartbeat extension)
- **POODLE** — Not vulnerable (no SSLv3)
- **BEAST** — Not vulnerable (no TLS 1.0)
- **CRIME** — Not vulnerable (no TLS compression)
- **BREACH** — Not vulnerable (gzip disabled at proxy with `gzip off` and `proxy_set_header Accept-Encoding ""`)
- **SWEET32** — Not vulnerable (no 3DES)
- **FREAK** — Not vulnerable (no export ciphers)
- **LOGJAM** — Not vulnerable (no DH export ciphers)
- **RC4** — Not vulnerable (no RC4 ciphers)
- **ROBOT** — Not vulnerable (no RSA key transport ciphers)
- **Secure Renegotiation** — Supported ✅

#### Expected "NOT ok" Items for Self-Signed Certificate

The following warnings are expected and acceptable for a local development lab with a self-signed certificate. They would be resolved by using a publicly-trusted CA (e.g. Let's Encrypt) in production:

- **Chain of trust NOT ok (self signed)** — No trusted CA signed the certificate; Grade capped to T
- **Domain name mismatch** — testssl connected via `host.docker.internal` but the cert CN is `localhost`; Grade capped to M
- **Neither CRL nor OCSP URI provided** — Self-signed certs have no revocation infrastructure
- **OCSP stapling not offered** — Requires a CA-issued cert with an OCSP responder URL

#### HSTS Verification

testssl confirmed HSTS is present and correctly configured on HTTPS:
```
Strict Transport Security    365 days=31536000 s, includeSubDomains, preload
```

HSTS is absent from HTTP responses (confirmed in Task 2.1), which is correct — HSTS sent over HTTP could be poisoned by a MITM attacker.

---

### 3.2 Rate Limiting

#### Test Results

12 consecutive POST requests to `/rest/user/login`:

```
500
500
500
500
500
500
429
429
429
429
429
429
```

6 requests passed through (returning 500 — invalid credentials from the application), and the remaining 6 were blocked with 429. The burst of 5 plus the one request permitted by the `nodelay` token accounts for the 6 that passed.

#### Rate Limit Configuration Analysis

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  ...
}
```

**`rate=10r/m`** — The token bucket refills at 10 requests per minute per IP address (one token every 6 seconds). This is the sustained rate allowed after the burst is exhausted. A legitimate user logging in once every few minutes will never be affected; an automated brute-force tool sending hundreds of requests per minute will be blocked after the burst is consumed.

**`burst=5`** — Allows up to 5 additional requests to queue beyond the base rate before returning 429. This accommodates brief legitimate spikes — for example, a user double-clicking the login button or a script that retries immediately after a network error — without immediately blocking them. Combined with the base rate, the effective burst capacity is 6 requests (1 base + 5 burst).

**`nodelay`** — Processes all burst requests immediately rather than queuing them over time. Without `nodelay`, burst requests would be spaced out over the refill period, introducing artificial latency for legitimate users. With `nodelay`, the burst requests are served instantly and then the per-IP token bucket is depleted, causing subsequent requests to be rejected immediately.

**Security vs usability trade-off:** A rate of 10r/m with burst=5 means a legitimate user can make up to 6 rapid login attempts (covering a forgotten password scenario) and then 1 attempt every 6 seconds thereafter. This is strict enough to make credential stuffing and brute-force attacks impractical (an attacker can test at most ~600 passwords per hour per IP) while being transparent to real users who log in once per session. The rate limit is applied only to the `/rest/user/login` endpoint — other endpoints are unrestricted, so the limit has zero impact on normal application use.

#### Access Log — 429 Responses

The following lines from `logs/access.log` show the rate limiting in action:

```
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.008 uct=0.001 urt=0.008
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.004 uct=0.000 urt=0.004
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.004 uct=0.001 urt=0.004
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.004 uct=0.001 urt=0.004
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.003 uct=0.000 urt=0.003
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.003 uct=0.000 urt=0.003
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [21/Mar/2026:07:22:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

The 429 responses have `rt=0.000 uct=- urt=-` — the request was rejected by Nginx itself before being forwarded to the upstream application, confirming the rate limit fires at the proxy layer and the app never sees the excess requests.

#### Timeout Configuration and Trade-offs

```nginx
client_body_timeout   10s;
client_header_timeout 10s;
keepalive_timeout     10s;
send_timeout          10s;
proxy_read_timeout    30s;
proxy_send_timeout    30s;
proxy_connect_timeout  5s;
```

**`client_body_timeout 10s`** — Maximum time between two successive reads of the request body. If a client sends headers but then pauses before sending the body (a Slowloris-style slow body attack), Nginx closes the connection after 10 seconds. Trade-off: on very slow mobile connections, a legitimate large file upload could be interrupted if network latency exceeds 10 seconds between chunks.

**`client_header_timeout 10s`** — Maximum time to receive the full request headers from the client. This mitigates slow header attacks where an attacker opens a connection and sends headers one byte at a time to hold the connection open. Trade-off: clients on extremely high-latency connections (satellite, heavily congested networks) could time out before headers complete.

**`keepalive_timeout 10s`** — How long Nginx keeps an idle keep-alive connection open waiting for another request. Shorter values free up connections faster under load, limiting connection exhaustion attacks. Trade-off: very short keep-alive increases TCP handshake overhead for clients making multiple sequential requests, slightly increasing latency.

**`send_timeout 10s`** — Maximum time between two successive writes to the client. If the client stops reading responses (e.g. a slow read attack that opens many connections and reads very slowly), Nginx closes the connection. Trade-off: if a client is downloading a large file over a slow connection, this timeout applies between individual write operations, not the total transfer time, so it is less likely to affect legitimate large downloads than it might appear.

**`proxy_read_timeout 30s`** — Maximum time to wait for the upstream application to send a response after the request is forwarded. Juice Shop sometimes performs slow database operations; 30 seconds accommodates these while preventing runaway upstream requests from holding proxy connections indefinitely. Trade-off: setting this too low can cause legitimate slow API responses to be cut off; too high allows slow application bugs to consume proxy resources.

**`proxy_send_timeout 30s`** — Maximum time to transmit the full request to the upstream. Typically not an issue for local Docker networking (very low latency), but important when the upstream is a remote service.

**`proxy_connect_timeout 5s`** — Maximum time to establish a connection to the upstream. A 5-second timeout ensures that if the Juice Shop container is unhealthy or unresponsive, Nginx fails fast and returns a 502 to the client rather than queuing requests indefinitely. Trade-off: if the upstream is legitimately slow to accept connections under high load, this can cause premature failures.

---

## Analysis — Security vs Usability Trade-offs

**Rate limiting:** The chosen values (`rate=10r/m`, `burst=5`, `nodelay`) represent a conservative approach appropriate for a login endpoint. The key trade-off is that a legitimate user who fails login 6 times in quick succession (e.g. trying different remembered passwords) will start receiving 429s and must wait up to a minute before trying again. This friction is intentional — it's the same friction that makes the endpoint expensive for an attacker. In production, a 429 response should return a `Retry-After` header informing the user when they can try again, reducing support burden.

**TLS version support:** Dropping TLS 1.0 and 1.1 means IE 8/11 users receive no connection. This is an acceptable trade-off — those browsers are end-of-life, no longer receive security updates, and are themselves a vulnerability vector. The client simulation confirms all browsers released after 2016 connect successfully.

**CSP in Report-Only mode:** Running CSP in Report-Only avoids breaking Juice Shop's Angular frontend (which requires `'unsafe-inline'` and `'unsafe-eval'`) while still capturing violation reports. The trade-off is that XSS is not actively blocked. The correct long-term approach is to replace inline scripts with nonce-based or hash-based CSP directives that allow Angular to function without `'unsafe-inline'`, then switch to enforcement mode.

**HSTS preload:** Setting `preload` commits the domain to the browser preload list permanently. Removing a domain from the preload list takes months and requires submitting a removal request. For a lab environment using `localhost` this has no consequence, but in production this is a strong commitment that should only be made after verifying the entire domain and all subdomains can serve HTTPS indefinitely.