# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### Why reverse proxies matters

A reverse proxy sits between external clients and backend application servers, providing several security benefits:
- TLS Termination: Nginx handles HTTPS, so backend apps don’t manage certificates directly.
- Security Headers Injection: Adds headers like X-Frame-Options or Content-Security-Policy to protect apps.
- Request Filtering: Can block suspicious traffic before it reaches the app.
- Single Access Point: All external requests go through Nginx; easier to monitor and control access.
- Hiding Direct App Ports: Juice Shop is not exposed to host; reduces attack surface, less chance for direct attacks.

### Why hiding direct app ports reduces attack surface

Hiding direct application ports reduces the attack surface because the service is no longer directly reachable from outside the system. This means attackers cannot connect to the app or probe it through its native port.

All incoming traffic is forced to go through the reverse proxy (e.g., Nginx), where security controls like TLS, request filtering, and headers are enforced. This prevents attackers from bypassing these protections.

Additionally, automated scanners are less likely to detect the service since its port is not exposed. Even if vulnerabilities exist in the application, exploiting them becomes harder because access is restricted to internal network paths only.

### Outputs

```bash
 ✔ Container lab11-juice-1 Running                                                                                                                                                       0.0s
 ✔ Container lab11-nginx-1 Recreated                                                                                                                                                     0.3s
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS                  PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     38 seconds ago   Up 37 seconds           3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     1 second ago     Up Less than a second   80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp, 0.0.0.0:80->8080/tcp, [::]:80->8080/tcp
HTTP 308
```

```bash
$ docker compose ps

NAME            IMAGE                           COMMAND                  SERVICE   CREATED              STATUS              PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     About a minute ago   Up About a minute   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     56 seconds ago       Up 54 seconds       80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp, 0.0.0.0:80->8080/tcp, [::]:80->8080/tcp
```

Only Nginx has host ports published; Juice Shop is hidden behind reverse proxy

### Task 2 — Security Headers

Relevant Headers (from headers-https.txt):
```txt
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; ...
```

Explanation:
- X-Frame-Options: Prevents clickjacking by disallowing the site to be embedded in iframes.
- X-Content-Type-Options: Stops MIME-type sniffing, so browsers don’t misinterpret files (helps prevent XSS attacks).
- Strict-Transport-Security (HSTS): Forces browsers to use HTTPS only, protecting against downgrade attacks and man-in-the-middle attacks.
- Referrer-Policy: Controls how much referrer information is shared, reducing leakage of sensitive URLs.
- Permissions-Policy: Disables access to browser features (camera, location, mic), reducing abuse from malicious scripts.
- COOP/CORP:
- COOP (same-origin) isolates browsing context; protects against cross-origin attacks (e.g., Spectre).
- CORP (same-origin) restricts which resources can be loaded; prevents data leaks across origins.
- CSP-Report-Only: Defines allowed content sources but only reports violations (does not block yet), useful for testing protection against XSS and injection attacks.

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### TLS scan summary

| Protocol | Status |
|----------|--------|
| SSLv2    | Not offered (OK) |
| SSLv3    | Not offered (OK) |
| TLS 1.0  | Not offered |
| TLS 1.1  | Not offered |
| TLS 1.2  | **Offered (OK)** |
| TLS 1.3  | **Offered (OK)** |
| HTTP/2   | Offered via ALPN |

Cipher suites that are supported:
- TLSv1.2: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256
- TLSv1.3: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256

Why TLSv1.2+ is required:
- TLS 1.0/1.1 have known security vulnerabilities (Heartbleed, POODLE, etc.)
- TLS 1.3: strongest security with forward secrecy and modern cipher suites
- Older protocols can be exploited for man-in-the-middle attacks

The self-signed certificate causes some expected **“NOT ok”** items:
- Chain of trust: self-signed; not trusted by browsers.
- OCSP/CRL/CT/CAA checks: not available; certificate revocation and transparency info missing.
- OCSP stapling: not offered; no stapled revocation proof sent to clients.

To fully resolve these issues:
- Trust a local CA (e.g., mkcert) for development.
- Or use a real domain + public CA (e.g., Let’s Encrypt) and enable OCSP stapling in nginx.conf.


### Rate limit config & test
Rate Limit Configuration:
- rate=10r/m: max 10 requests per minute per client.
- burst=5: allows short bursts above the limit before blocking.

This creates good balance. Users can make occasional bursts (better UX) while preventing automated abuse or DoS attacks.


Timeout Settings in nginx.conf
- client_body_timeout: max time to receive body from client → prevents slow POST attacks.
- client_header_timeout: max time to read headers → protects against slow header attacks.
- proxy_read_timeout: max time to wait for backend response → avoids hanging connections.
- proxy_send_timeout: max time to send request to backend → prevents slow backend sends from tying up resources.


Trade-offs: Short timeouts improve security but may affect users with slow connections; long timeouts improve UX but increase exposure to resource exhaustion attacks.

#### Access log:
```txt
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.18.0" rt=0.045 uct=0.000 urt=0.045
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.18.0" rt=0.023 uct=0.001 urt=0.023
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.18.0" rt=0.015 uct=0.000 urt=0.015
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.18.0" rt=0.015 uct=0.000 urt=0.015
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.18.0" rt=0.017 uct=0.001 urt=0.017
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.18.0" rt=0.014 uct=0.000 urt=0.014
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-  << HERE RL HAPPENED
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [20/Apr/2026:13:55:32 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

Logs confirms that excessive requests are correctly throttled

*P.S: I hate reverse proxies because they're headace while penetration tests XD*