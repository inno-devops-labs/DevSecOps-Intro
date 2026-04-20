### Why Use a Reverse Proxy?

A reverse proxy like Nginx provides several critical security benefits:

- **TLS termination**: The proxy handles SSL/TLS, so the backend app does not need to manage certificates. This centralizes crypto configuration and makes certificate rotation easier.
- **Security headers injection**: Headers such as `X-Frame-Options`, `HSTS`, and `CSP` are added uniformly at the proxy layer - without touching application code.
- **Request filtering & rate limiting**: The proxy can block malicious traffic, throttle login attempts, enforce request size limits, and set timeouts before requests ever reach the application.
- **Single access point**: All traffic flows through Nginx, enabling centralized logging, monitoring, and enforcement of access controls.

### Why Hide Direct App Ports?

Exposing the application container directly (e.g., Juice Shop on port 3000) expands the attack surface:

- Attackers could bypass proxy-level controls (rate limiting, headers, WAF rules).
- Direct access means no TLS protection on the app port.
- Internal services should never be reachable from the host unless explicitly required.

### `docker compose ps` Output

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     ...   Up ...   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     ...   Up ...   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```
### HTTP Redirect Verification

```
curl.exe -s -o NUL -w "HTTP %{http_code}" http://localhost:8080/
HTTP 308
```

### Security Headers from HTTPS Response

```
HTTP/1.1 200 OK
Server: nginx
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### 2.2 Header Analysis

| Header                                                           | What It Protects Against                                                                                                                                                                                                                                                                                                                                                              |
|------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **X-Frame-Options: DENY**                                        | Prevents the page from being embedded in an `<iframe>` on another site. Mitigates **Clickjacking** attacks where an attacker overlays invisible frames to steal clicks.                                                                                                                                                                                                               |
| **X-Content-Type-Options: nosniff**                              | Prevents browsers from MIME-sniffing a response away from the declared `Content-Type`. Stops **content-type confusion attacks** where a browser misinterprets a file (e.g., treating a `.txt` upload as executable JavaScript).                                                                                                                                                       |
| **Strict-Transport-Security (HSTS)**                             | Instructs browsers to only access the site over HTTPS for 1 year (`max-age=31536000`), including subdomains. Prevents **SSL stripping** and **protocol downgrade attacks**. The `preload` directive allows the domain to be included in browser HSTS preload lists. Critically, HSTS only appears on the HTTPS response - not on the HTTP 308 redirect - which is correct behavior.   |
| **Referrer-Policy: strict-origin-when-cross-origin**             | Controls how much referrer information is sent in HTTP requests. Cross-origin requests only send the origin (scheme + host), not the full URL. Prevents **leaking sensitive URL parameters** (e.g., tokens in query strings) to third-party sites.                                                                                                                                    |
| **Permissions-Policy: camera=(), geolocation=(), microphone=()** | Disables access to powerful browser features (camera, microphone, GPS) for this origin. Mitigates **feature abuse** - e.g., a compromised script silently accessing the webcam or location.                                                                                                                                                                                           |
| **Cross-Origin-Opener-Policy: same-origin**                      | Isolates the browsing context so it cannot share a window handle with cross-origin pages. Prevents **cross-origin attacks like Spectre** that exploit shared memory/process space, and breaks cross-site window scripting.                                                                                                                                                            |
| **Cross-Origin-Resource-Policy: same-origin**                    | Prevents other origins from loading this site's resources (images, scripts, etc.) via `<img>`, `<script>`, `fetch`. Mitigates **cross-site data exfiltration** using speculative execution side-channels (related to Spectre).                                                                                                                                                        |
| **Content-Security-Policy-Report-Only**                          | Defines which sources are allowed for scripts, styles, images, etc., but only in *report* mode - violations are reported (or logged) without blocking. Allows iterative development of a strict CSP without breaking the app. Juice Shop is JavaScript-heavy with `unsafe-inline` and `unsafe-eval`, which would break under a strict CSP, so report-only is the safe starting point. |

### HSTS Present Only on HTTPS (Not HTTP)

HTTP response (port 8080) - **no HSTS**:
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

HTTPS response (port 8443) - **HSTS present**:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

#### Protocol Support

| Protocol      | Status                 |
|---------------|------------------------|
| SSLv2         | Not offered            |
| SSLv3         | Not offered            |
| TLS 1.0       | Not offered            |
| TLS 1.1       | Not offered            |
| TLS 1.2       | Offered                |
| TLS 1.3       | Offered                |
| HTTP/2 (ALPN) | Offered (h2, http/1.1) |

#### Supported Cipher Suites

**TLS 1.3:**

| Cipher                       | Key Exchange | Bits |
|------------------------------|--------------|------|
| TLS_AES_256_GCM_SHA384       | ECDH/MLKEM   | 256  |
| TLS_CHACHA20_POLY1305_SHA256 | ECDH/MLKEM   | 256  |
| TLS_AES_128_GCM_SHA256       | ECDH/MLKEM   | 128  |

**TLS 1.2:**

| Cipher                      | Key Exchange | Bits |
|-----------------------------|--------------|------|
| ECDHE-RSA-AES256-GCM-SHA384 | ECDH 256-bit | 256  |
| ECDHE-RSA-AES128-GCM-SHA256 | ECDH 256-bit | 128  |

#### Why TLSv1.2+ Is Required

- **TLS 1.0 and 1.1** are deprecated (RFC 8996) and vulnerable to BEAST, POODLE, and CRIME attacks.
- **TLS 1.2** remains secure when configured with strong AEAD ciphers (GCM) and ECDHE key exchange. Widely supported by legacy clients (IE 11, older Androids, OpenSSL 1.0.x).
- **TLS 1.3** removes all legacy/weak cipher suites, mandates forward secrecy, reduces the handshake to 1-RTT (faster connections), and eliminates many downgrade attack vectors. It is the preferred protocol for all modern clients.
- The Nginx config uses `ssl_protocols TLSv1.2 TLSv1.3` - a best-practice balance of security and compatibility.

#### Vulnerability Check

| Vulnerability              | Status                                         |
|----------------------------|------------------------------------------------|
| Heartbleed (CVE-2014-0160) | Not vulnerable                                 |
| CCS (CVE-2014-0224)        | Not vulnerable                                 |
| ROBOT                      | Not vulnerable  (no RSA key transport ciphers) |
| CRIME                      | Not vulnerable  (TLS compression disabled)     |
| BREACH                     | Not vulnerable  (gzip disabled at proxy)       |
| POODLE SSL                 | Not vulnerable  (no SSLv3)                     |
| SWEET32                    | Not vulnerable  (no 3DES)                      |
| FREAK                      | Not vulnerable  (no EXPORT ciphers)            |
| LOGJAM                     | Not vulnerable  (no DH EXPORT ciphers)         |
| BEAST                      | Not vulnerable  (no SSL3/TLS1)                 |
| LUCKY13                    | Not vulnerable                                 |
| RC4                        | Not vulnerable                                 |

#### Expected "NOT OK" Items (Dev Certificate)

As noted in the lab instructions, the following warnings are expected and acceptable for a local self-signed certificate:

- **Chain of trust: NOT ok** - No CA signed this certificate. Fix with mkcert or Let's Encrypt on a real domain.
- **OCSP/CRL not provided** - No revocation infrastructure for a self-signed cert.
- **OCSP stapling: not offered** - Disabled in nginx.conf (`ssl_stapling off`), enabled only when a public CA is used.
- **DNS CAA not offered** - CAA DNS records require a real domain.
- **Grade T** - Capped due to self-signed chain-of-trust issue. On a real domain with a public CA, this configuration would achieve an **A+ rating** on SSL Labs.
- **Domain name mismatch** - testssl.sh connects via `host.docker.internal` but the SAN only covers `localhost`/`127.0.0.1`.

#### HSTS Confirmed

testssl.sh output confirms:
```
Strict Transport Security    365 days=31536000 s, includeSubDomains, preload
```

#### Configuration

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

#### Rate Limit Test Output

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

12 rapid POST requests to `/rest/user/login`:
- **Requests 1–6**: Passed through to the upstream (Juice Shop returned `500` - invalid credentials, but the request was processed).
- **Requests 7–12**: Blocked by Nginx with `429 Too Many Requests` - the burst buffer was exhausted.

**Result: 6 * 200/500 (allowed), 6 * 429 (blocked)** 

#### Why `rate=10r/m`, `burst=5`, `nodelay`?

| Parameter    | Value                                          | Rationale                                                                                                                                                                                          |
|--------------|------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `rate=10r/m` | 10 requests per minute per IP                  | Allows ~1 login attempt every 6 seconds - reasonable for a legitimate user typing a password, but too slow for automated brute-force (which might attempt thousands per second).                   |
| `burst=5`    | Allow up to 5 extra requests to queue          | Handles brief, legitimate bursts (e.g., a user quickly retrying after a typo). Without burst, even 2 rapid requests would trigger rate limiting.                                                   |
| `nodelay`    | Don't delay burst requests, reject immediately | Burst requests are processed instantly (not queued with delay). Once burst is exhausted, further requests get 429 immediately rather than waiting in a queue. This prevents slow-queue exhaustion. |

#### Access Log - 429 Responses

```
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.016 uct=0.000 urt=0.017
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.003 uct=0.000 urt=0.002
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.002 uct=0.001 urt=0.002
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.002 uct=0.000 urt=0.002
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.002 uct=0.000 urt=0.002
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 500 2373 "-" "curl/8.18.0" rt=0.002 uct=0.000 urt=0.001
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.21.0.1 - - [20/Apr/2026:12:00:18 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

#### Timeout Configuration Analysis

| Directive                   | Value      | Purpose & Trade-off                                                                                                                                                                                                                                                                              |
|-----------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `client_body_timeout 10s`   | 10 seconds | Time to wait for the client to send the request body. Protects against **Slowloris-style body attacks** where attackers send data very slowly to hold connections open. Too low risks timing out slow mobile clients on poor networks.                                                           |
| `client_header_timeout 10s` | 10 seconds | Time to receive the full request header. Prevents **slow header attacks** (e.g., R-U-Dead-Yet). Same trade-off: aggressive crawlers or slow clients may get disconnected.                                                                                                                        |
| `proxy_read_timeout 30s`    | 30 seconds | Maximum time to wait for the upstream to send a response body byte. Prevents a stuck backend from holding Nginx worker connections indefinitely. Set at 30s to accommodate Juice Shop's slower operations (e.g., large product list queries). Too short could cause valid slow queries to fail.  |
| `proxy_send_timeout 30s`    | 30 seconds | Maximum time between writes to the client when transmitting the response. Guards against slow clients that consume bandwidth slowly. Setting this too low could disconnect clients on congested networks.                                                                                        |
| `keepalive_timeout 10s`     | 10 seconds | How long an idle keep-alive connection is held open. Reduces connection setup overhead for clients making multiple requests, while limiting the number of idle connections. A lower value (e.g., 5s) is more aggressive against connection exhaustion; higher (e.g., 65s) is more user-friendly. |