# Lab 11 Submission -- Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 -- Reverse Proxy Compose Setup (2 pts)

### Why reverse proxies are valuable for security

A reverse proxy sits between external clients and internal application servers, providing several security benefits:

- **TLS termination**: The proxy handles TLS encryption/decryption, so the app itself does not need to manage certificates. This centralizes certificate management and ensures all traffic is encrypted in transit.
- **Security headers injection**: Headers like HSTS, X-Frame-Options, and CSP can be added at the proxy layer without modifying application code. This is especially useful for third-party apps (like Juice Shop) where source changes are impractical.
- **Request filtering and rate limiting**: The proxy can enforce rate limits, block malicious request patterns, and set timeouts before requests ever reach the application, reducing DoS and brute-force risk.
- **Single access point**: All traffic funnels through one entry point, making it easier to monitor, log, and audit. Internal services remain hidden from the public network.

### Why hiding direct app ports reduces attack surface

When Juice Shop's port 3000 is not published to the host, attackers cannot reach the application directly. They must go through Nginx, which enforces TLS, security headers, rate limits, and timeouts. If a vulnerability exists in the application's HTTP handling, the proxy may block or mitigate the attack before it reaches the app. It also prevents information leakage from the app's default headers (e.g., `X-Powered-By`).

### `docker compose ps` output

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED              STATUS              PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     About a minute ago   Up About a minute   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     About a minute ago   Up About a minute   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Only Nginx has published host ports (8080, 8443). Juice Shop shows `3000/tcp` (exposed within the Docker network only) with no host-mapped ports.

---

## Task 2 -- Security Headers (3 pts)

### Security headers from HTTPS response (`headers-https.txt`)

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

- **X-Frame-Options (`DENY`)**: Prevents the page from being embedded in `<iframe>`, `<frame>`, or `<object>` elements. Protects against **clickjacking** attacks where an attacker overlays a transparent frame over a legitimate page to trick users into clicking hidden elements.

- **X-Content-Type-Options (`nosniff`)**: Prevents browsers from MIME-sniffing a response away from the declared `Content-Type`. Protects against **MIME confusion attacks** where a browser might interpret a text file as executable script, leading to XSS.

- **Strict-Transport-Security (HSTS) (`max-age=31536000; includeSubDomains; preload`)**: Instructs browsers to only connect via HTTPS for the next year, including all subdomains. Protects against **protocol downgrade attacks** and **SSL stripping** (e.g., an attacker on a public Wi-Fi intercepting the initial HTTP request before the redirect to HTTPS).

- **Referrer-Policy (`strict-origin-when-cross-origin`)**: Controls how much referrer information is sent with requests. For same-origin requests, the full URL is sent; for cross-origin requests, only the origin is sent; for downgrades (HTTPS to HTTP), nothing is sent. Protects against **information leakage** of sensitive URL paths and query parameters to third-party sites.

- **Permissions-Policy (`camera=(), geolocation=(), microphone=()`)**: Disables access to camera, geolocation, and microphone APIs. Protects against **malicious scripts or embedded content** attempting to access device sensors without user knowledge, even if an XSS vulnerability exists.

- **Cross-Origin-Opener-Policy (COOP) / Cross-Origin-Resource-Policy (CORP) (`same-origin`)**: COOP ensures the page cannot be referenced by cross-origin windows (prevents `window.opener` attacks). CORP prevents cross-origin reads of the resource. Together they protect against **Spectre-like side-channel attacks** and **cross-origin data leaks** by isolating the browsing context.

- **Content-Security-Policy-Report-Only**: Defines which content sources are allowed (scripts, images, styles) but only reports violations without blocking them. This is a **monitoring mode** for CSP -- it helps identify what a strict CSP would break before enforcing it. Protects against **XSS** and **data injection** attacks once moved to enforcement mode. Report-Only is used here because Juice Shop relies on inline scripts and eval, which a strict CSP would break.

---

## Task 3 -- TLS, HSTS, Rate Limiting & Timeouts (5 pts)

### TLS/testssl summary

#### Protocol support

| Protocol | Status |
|----------|--------|
| SSLv2    | Not offered (OK) |
| SSLv3    | Not offered (OK) |
| TLS 1.0  | Not offered |
| TLS 1.1  | Not offered |
| TLS 1.2  | Offered (OK) |
| TLS 1.3  | Offered (OK) |

Only TLSv1.2 and TLSv1.3 are enabled, which is the recommended configuration.

#### Cipher suites

**TLSv1.2 (server order):**
- `ECDHE-RSA-AES256-GCM-SHA384` (256-bit AESGCM, ECDH key exchange)
- `ECDHE-RSA-AES128-GCM-SHA256` (128-bit AESGCM, ECDH key exchange)

**TLSv1.3 (server order):**
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

All ciphers use AEAD (Authenticated Encryption with Associated Data) and provide forward secrecy. No weak, export, NULL, or RC4 ciphers are offered.

#### Why TLSv1.2+ is required

TLSv1.0 and TLSv1.1 have known vulnerabilities (BEAST, POODLE-like attacks on CBC mode, weak cipher suites). They were formally deprecated by RFC 8996 in 2021. TLSv1.2 with AEAD ciphers is the minimum secure baseline. TLSv1.3 is preferred because it removes all legacy cipher suites, reduces the handshake to one round trip, and mandates forward secrecy.

#### Warnings from testssl

- **Chain of trust: NOT ok** (self-signed certificate) -- expected for localhost dev environment
- **OCSP/CRL URI: NOT ok** -- no revocation info provided, expected for self-signed certs
- **OCSP stapling: not offered** -- cannot be used with self-signed certificates
- **DNS CAA RR: not offered** -- not applicable for localhost
- **Overall grade: T** -- capped due to self-signed certificate chain of trust issues

All of these are expected with a self-signed certificate. In production, using a CA-signed certificate (e.g., Let's Encrypt) would resolve these and enable OCSP stapling.

**No actual TLS vulnerabilities were found.** All tested CVEs (Heartbleed, CCS, POODLE, DROWN, FREAK, Logjam, SWEET32, BREACH, CRIME, ROBOT, LUCKY13, etc.) returned "not vulnerable (OK)".

#### HSTS verification

HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`) appears **only on HTTPS** responses, which is correct. The HTTP server block (port 8080) does not include HSTS -- it only performs a 308 redirect to HTTPS. This is the right behavior because sending HSTS over plain HTTP would be ignored by browsers and could be spoofed by a MITM attacker.

### Rate limiting & timeouts

#### Rate-limit test output (`analysis/rate-limit-test.txt`)

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

12 rapid requests to `/rest/user/login`: the first 6 returned `401` (Unauthorized -- the app rejected the bad credentials), and the remaining 6 returned `429` (Too Many Requests -- Nginx blocked them before they reached the app).

#### Rate limit configuration

From `nginx.conf`:
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
    limit_req zone=login burst=5 nodelay;
    ...
}
```

- **`rate=10r/m`**: Allows 10 requests per minute per IP (1 request every 6 seconds on average).
- **`burst=5`**: Allows up to 5 extra requests to queue above the rate limit before rejecting. With `nodelay`, burst requests are served immediately rather than queued.
- **`limit_req_status 429`**: Returns HTTP 429 (Too Many Requests) instead of the default 503, which is more semantically correct.

**Trade-offs**: The 10r/m rate is strict enough to slow down brute-force attacks (an attacker can only try ~10 passwords per minute per IP) while still allowing legitimate users to make a few retry attempts after mistyping a password. The burst of 5 accommodates brief spikes (e.g., a user rapidly correcting a typo) without immediately blocking them.

#### Timeout settings

From `nginx.conf`:
```nginx
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 10s;
send_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
proxy_connect_timeout 5s;
```

- **`client_body_timeout 10s`** / **`client_header_timeout 10s`**: If a client takes more than 10 seconds to send the request body or headers, the connection is closed. Protects against **Slowloris** and **slow POST** attacks where an attacker sends data very slowly to hold connections open and exhaust server resources.
- **`keepalive_timeout 10s`**: Idle keep-alive connections are closed after 10 seconds, freeing resources. Shorter than the default (75s) to reduce the window for connection exhaustion attacks.
- **`send_timeout 10s`**: If the client stops reading the response for 10 seconds, the connection is closed. Prevents slow-read attacks.
- **`proxy_read_timeout 30s`** / **`proxy_send_timeout 30s`**: Maximum time to wait for the upstream (Juice Shop) to respond or accept data. Prevents the proxy from hanging indefinitely if the app becomes unresponsive. Set higher than client timeouts because the app may legitimately need time to process requests.
- **`proxy_connect_timeout 5s`**: Maximum time to establish a connection to upstream. A short timeout ensures fast failure if the app container is down, rather than making clients wait.

**Trade-offs**: Aggressive timeouts improve resilience against slowloris/slow-read DoS, but if set too low they can cut off legitimate slow connections (e.g., users on poor networks uploading files). The current values are appropriate for a web app with small payloads like Juice Shop.

#### Access log lines showing 429 responses

```
172.22.0.1 - - [15/Apr/2026:04:30:14 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.68.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [15/Apr/2026:04:30:14 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.68.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [15/Apr/2026:04:30:14 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.68.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [15/Apr/2026:04:30:14 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.68.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [15/Apr/2026:04:30:14 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.68.0" rt=0.000 uct=- urt=-
172.22.0.1 - - [15/Apr/2026:04:30:14 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/7.68.0" rt=0.000 uct=- urt=-
```

Note that `rt=0.000` and `uct=-` / `urt=-` confirm that Nginx rejected these requests immediately at the proxy layer -- they never reached the upstream Juice Shop application.
