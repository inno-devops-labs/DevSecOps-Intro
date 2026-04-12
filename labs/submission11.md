# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Overview

In this lab I placed OWASP Juice Shop behind an Nginx reverse proxy using Docker Compose and applied hardening controls at the proxy layer only. The application itself was not modified. The final setup terminates TLS at Nginx, injects security headers, redirects HTTP to HTTPS, and applies request rate limiting to the login endpoint.

A practical issue during setup was a host port conflict: `django-defectdojo-nginx-1` was already bound to `0.0.0.0:8080` and `0.0.0.0:8443`, so the lab11 Nginx container could not start until those DefectDojo containers were stopped. After releasing the ports, the lab11 stack started successfully.

---

## Environment and command evidence

```powershell
docker --version
# Docker version 28.0.4, build b8034c0

docker compose version
# Docker Compose version v2.34.0-desktop.1

git switch -c feature/lab11
```

Directories for the lab were created under `labs/lab11/`, and a local self-signed certificate with SAN entries for `localhost`, `127.0.0.1`, and `::1` was generated successfully. The generated files were:

- `labs/lab11/reverse-proxy/certs/localhost.crt`
- `labs/lab11/reverse-proxy/certs/localhost.key`
- `labs/lab11/reverse-proxy/certs/san.cnf`

---

## Task 1 — Reverse proxy compose setup

### Why a reverse proxy is valuable for security

A reverse proxy improves security because it provides a single controlled entry point in front of the application. In this setup, Nginx performs:

- TLS termination, so HTTPS can be added without changing Juice Shop code.
- Security header injection, again without modifying the application.
- Request filtering and rate limiting, especially useful for login endpoints.
- Centralized timeout and protocol settings.

This is operationally valuable because infrastructure teams can harden exposure at the edge instead of changing app logic.

### Why hiding direct app ports reduces attack surface

Publishing only the reverse proxy ports reduces the externally reachable surface. Clients can access the application only through Nginx, which means all traffic must pass the TLS policy, header policy, redirect logic, and rate limiting. The Juice Shop container itself has no published host ports, so it is not directly reachable from the host network.

### Compose evidence

`docker compose ps`:

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j..."   juice     3 minutes ago   Up 3 minutes    3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint...."   nginx     3 minutes ago   Up 26 seconds   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```

This shows that only **Nginx** publishes host ports, while **Juice Shop** is internal-only (`3000/tcp` with no host binding).

### HTTP redirect check

```text
HTTP 308
```

The HTTP endpoint on `http://localhost:8080/` correctly redirects to HTTPS.

---

## Task 2 — Security headers

### HTTP header check

`curl -sI http://localhost:8080/` returned a `308 Permanent Redirect` with the following relevant headers:

```text
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### HTTPS header check

`curl -skI https://localhost:8443/` returned `200 OK` with the following relevant security headers:

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

### Header explanations

- **X-Frame-Options: DENY**  
  Prevents the site from being embedded in an iframe. This helps protect against clickjacking.

- **X-Content-Type-Options: nosniff**  
  Prevents browsers from MIME-sniffing content types. This reduces the risk of browsers interpreting a response as executable content when it should not be.

- **Strict-Transport-Security (HSTS)**  
  Tells browsers to use HTTPS for future requests. This helps reduce protocol downgrade and SSL stripping risks after the first successful HTTPS connection.

- **Referrer-Policy: strict-origin-when-cross-origin**  
  Limits referrer leakage to other origins while keeping useful referrer behavior for same-origin navigation.

- **Permissions-Policy: camera=(), geolocation=(), microphone=()**  
  Explicitly disables access to selected browser features unless allowed. This reduces unnecessary exposure of sensitive browser capabilities.

- **Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy**  
  These headers strengthen isolation between browsing contexts and cross-origin resource usage. They help reduce some cross-origin data leakage and process-level interaction risks.

- **Content-Security-Policy-Report-Only**  
  A non-blocking CSP policy that reports violations without enforcing them. This is useful for a JavaScript-heavy application like Juice Shop, where a strict enforced CSP could easily break functionality during initial hardening.

### HSTS verification

- `headers-http.txt`: no `Strict-Transport-Security` header was present.
- `headers-https.txt`: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` was present.

This confirms that HSTS is applied only on HTTPS responses, which is the correct behavior.

---

## Task 3 — TLS, HSTS, rate limiting, and timeouts

### TLS / testssl summary

The TLS scan shows a modern protocol configuration:

- **Disabled:** SSLv2, SSLv3, TLS 1.0, TLS 1.1
- **Enabled:** TLS 1.2 and TLS 1.3
- **ALPN offered:** `h2`, `http/1.1`

Supported cipher suites observed in the scan:

- **TLS 1.2**
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

- **TLS 1.3**
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
  - `TLS_AES_128_GCM_SHA256`

The server also reports cipher order enabled and forward secrecy offered.

### Why TLS 1.2+ is required

TLS 1.0 and 1.1 are obsolete and weaker. Restricting support to **TLS 1.2 and TLS 1.3** removes older protocol downgrade paths and aligns the deployment with current secure defaults. TLS 1.3 is preferred because it simplifies the handshake and uses modern cryptography by default.

### Warnings / notable findings from testssl

The scan did **not** report major classic TLS vulnerabilities such as Heartbleed, CCS, Ticketbleed, CRIME, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, or RC4-related issues.

Expected warnings remained because the lab uses a self-signed localhost certificate:

- `Chain of trust: NOT ok (self signed)`
- hostname mismatch in the test context (`host.docker.internal` vs certificate CN/SAN for `localhost`)
- no CRL / OCSP URI
- OCSP stapling not offered
- no public CA trust chain / CT / CAA

These warnings are acceptable for a local development certificate and are explicitly consistent with the lab’s note about self-signed localhost certificates.

### Rate limiting results

The login endpoint was tested with 12 POST requests to `/rest/user/login`:

```text
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

Summary:

```text
Count Name Group
----- ---- -----
    6 429  {429, 429, 429, 429...}
    6 500  {500, 500, 500, 500...}
```

Interpretation:

- The first six requests reached the backend and returned `500` for invalid login handling in the application path used during the test.
- The next six requests were blocked by Nginx and returned **`429 Too Many Requests`**.

So rate limiting is clearly active and enforced at the reverse proxy.

### Access log evidence for 429

Relevant lines from `access.log`:

```text
172.20.0.1 - - [12/Apr/2026:10:05:49 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [12/Apr/2026:10:05:49 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [12/Apr/2026:10:05:49 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [12/Apr/2026:10:05:49 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [12/Apr/2026:10:05:49 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [12/Apr/2026:10:05:49 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

### Rate-limit configuration and trade-offs

Relevant Nginx configuration:

- `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;`
- `limit_req_status 429;`
- `limit_req zone=login burst=5 nodelay;`

Meaning:

- `rate=10r/m` allows about 10 login requests per minute per client IP.
- `burst=5` allows a short burst above the steady-state rate.
- `nodelay` means excess burst requests are processed immediately until the burst is exhausted; after that, Nginx returns `429` instead of queueing.

This is a reasonable balance between security and usability:

- it slows brute-force attempts and noisy automated login traffic,
- but still allows a user to make a few quick retries without being blocked immediately.

If the limit were lower, legitimate users could be throttled too aggressively. If it were much higher, brute-force resistance would be weaker.

### Timeout settings and trade-offs

Relevant settings:

- `client_body_timeout 10s`
- `client_header_timeout 10s`
- `proxy_read_timeout 30s`
- `proxy_send_timeout 30s`

Interpretation:

- **client_body_timeout / client_header_timeout** protect against slow client attacks such as slowloris by preventing clients from holding connections open indefinitely while slowly sending headers or bodies.
- **proxy_read_timeout / proxy_send_timeout** limit how long Nginx waits when communicating with the upstream app.

Trade-offs:

- Lower timeouts improve resilience against resource exhaustion and abusive slow connections.
- If the values are too low, they can break legitimate users on poor networks or requests handled by a slow backend.
- The chosen values are short enough to reduce abuse risk while still being practical for a local Juice Shop deployment.

---

## Files produced

The following lab artifacts were created under `labs/lab11/analysis/`:

- `compose-ps.txt`
- `http-redirect.txt`
- `headers-http.txt`
- `headers-https.txt`
- `testssl.txt`
- `rate-limit-test.txt`
- `rate-limit-summary.txt`
- `nginx-logs.txt`
- `access-429.txt`

---

## Conclusion

The lab objectives were achieved:

- Juice Shop is running behind an Nginx reverse proxy.
- Juice Shop is not directly exposed on a host port.
- HTTP requests are redirected to HTTPS with `308`.
- Required hardening headers are present.
- HSTS appears only on HTTPS.
- TLS is restricted to TLS 1.2 and TLS 1.3 with modern cipher suites.
- Rate limiting is active and returns `429` for excessive login attempts.
- Timeout settings are configured to reduce brute-force and slow-client / DoS risk.

The remaining TLS warnings are expected for a localhost self-signed certificate and do not indicate a configuration failure for this lab context.
