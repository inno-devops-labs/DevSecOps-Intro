# Lab 11 Submission - Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Artifacts

- `labs/lab11/docker-compose.yml`
- `labs/lab11/reverse-proxy/nginx.conf`
- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`
- `labs/lab11/analysis/testssl.txt`
- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/logs/access.log`
- `labs/lab11/logs/error.log`

## Task 1 - Reverse Proxy Compose Setup

Setup note:

- Initial `docker pull` attempts hit `no space left on device` and transient Docker registry `EOF` / `broken pipe` errors.
- After retrying, all required images were available locally and the stack started successfully.

Why the reverse proxy improves security:

- Nginx provides a single ingress point for Juice Shop, which lets operations teams apply TLS termination, request filtering, security headers, and request shaping without modifying application code.
- Centralizing these controls at the proxy makes it easier to harden multiple apps consistently and reduces the chance of every service implementing security features differently.
- The proxy can reject or redirect unwanted traffic before it ever reaches the application container, which reduces unnecessary backend exposure.

Why hiding the direct app port reduces attack surface:

- The Juice Shop container is only reachable on the internal Docker network, so scanners and browsers on the host cannot connect to `3000/tcp` directly.
- This forces all traffic through Nginx, where TLS, header injection, and rate limiting are enforced.
- If the app were published directly, an attacker could bypass those proxy controls and interact with the application on an unfiltered port.

Compose evidence:

```text
$ docker compose ps
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     20 seconds ago   Up 19 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     20 seconds ago   Up 19 seconds   0.0.0.0:8080->8080/tcp, :::8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, :::8443->8443/tcp

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```

Interpretation:

- `lab11-juice-1` shows only `3000/tcp`, which means the app port is exposed to the Compose network but not published on the host.
- `lab11-nginx-1` publishes the host-facing ports `8080` and `8443`, so Nginx is the only external entry point.
- The HTTP endpoint returned `308 Permanent Redirect`, confirming the proxy is redirecting plaintext traffic to HTTPS.

## Task 2 - Security Headers

HTTP header evidence from `labs/lab11/analysis/headers-http.txt`:

```text
HTTP/1.1 308 Permanent Redirect
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

HTTPS header evidence from `labs/lab11/analysis/headers-https.txt`:

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

Header analysis:

- `X-Frame-Options: DENY`: blocks framing of the site and reduces clickjacking risk.
- `X-Content-Type-Options: nosniff`: stops browsers from MIME-sniffing content into a different type, which helps prevent some script/style execution issues.
- `Strict-Transport-Security`: tells browsers to use HTTPS for future requests, reducing SSL stripping and downgrade risk after the first trusted HTTPS visit.
- `Referrer-Policy: strict-origin-when-cross-origin`: limits cross-site referrer leakage to the origin instead of the full URL, which reduces accidental disclosure of path/query details.
- `Permissions-Policy: camera=(), geolocation=(), microphone=()`: disables high-risk browser features that Juice Shop does not need at the proxy boundary.
- `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`: isolate browsing context and restrict cross-origin resource loading, which helps reduce cross-origin data leaks and some XS-Leaks style attacks.
- `Content-Security-Policy-Report-Only`: records what a tighter CSP would block without enforcing it yet. This is the safer starting point for a JavaScript-heavy app like Juice Shop because a strict enforced CSP could easily break application behavior.

Trade-off:

- Running CSP in `Report-Only` mode preserves functionality during rollout, but it does not actively block unsafe script behavior yet.
- The proxy adds headers even on redirects and errors via `add_header ... always;`, which is good for consistent policy coverage and verification.

## Task 3 - TLS, HSTS, Rate Limiting, and Timeouts

### TLS and HSTS

TLS summary from `labs/lab11/analysis/testssl.txt`:

- Enabled protocols: `TLS 1.2` and `TLS 1.3`
- Disabled protocols: `SSLv2`, `SSLv3`, `TLS 1.0`, and `TLS 1.1`
- HTTP/2 via ALPN is offered
- Forward secrecy is offered

Supported cipher suites observed by `testssl.sh`:

- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

Why TLS 1.2+ is required:

- TLS 1.0 and 1.1 are obsolete and missing modern cryptographic protections, so disabling them reduces downgrade and weak-cipher exposure.
- TLS 1.3 is preferred because it simplifies the handshake, removes many legacy options, and gives better security defaults.
- The compatibility trade-off is visible in the scan: very old clients such as `IE 8 Win 7`, `IE 11 Win 7`, and `Java 7u25` could not connect.

Warnings and notable scan results:

- `Chain of trust: NOT ok (self signed)` because the lab uses a self-signed localhost certificate.
- `NOT ok -- neither CRL nor OCSP URI provided` and `OCSP stapling not offered`, which is expected for a local development certificate.
- `DNS CAA RR not offered` and `Certificate Transparency --`, also expected on localhost.
- No major protocol or cipher vulnerabilities were reported. `testssl.sh` marked Heartbleed, CCS, Ticketbleed, ROBOT, CRIME, BREACH, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, and RC4 as not vulnerable or not applicable.

HSTS confirmation:

- `labs/lab11/analysis/headers-http.txt` does not include `Strict-Transport-Security`.
- `labs/lab11/analysis/headers-https.txt` includes `strict-transport-security: max-age=31536000; includeSubDomains; preload`.
- This is the correct behavior because HSTS must only be sent over HTTPS.

### Rate Limiting

Observed rate-limit test from `labs/lab11/analysis/rate-limit-test.txt`:

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

Result summary:

- `6` requests reached Juice Shop and returned `401 Unauthorized` for the bad credentials.
- `6` later requests were blocked by Nginx with `429 Too Many Requests`.

Rate-limit configuration and rationale:

- `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;`
- `location = /rest/user/login { limit_req zone=login burst=5 nodelay; }`
- `limit_req_status 429;`

Interpretation:

- `rate=10r/m` allows an average of 10 login attempts per minute per client IP.
- `burst=5` allows a short spike above the steady-state rate so a legitimate user can make a few quick retries.
- `nodelay` means requests above the burst are rejected immediately rather than queued, which is better for login endpoints because it keeps feedback fast and avoids holding connections open.
- In practice, the first allowed request plus the `burst=5` budget explains why the test produced `6` upstream `401` responses before `429` responses started.

Timeout settings and trade-offs from `labs/lab11/reverse-proxy/nginx.conf`:

- `client_body_timeout 10s`: limits how long Nginx waits for the request body. This helps against slow-upload abuse, but very slow clients may be cut off.
- `client_header_timeout 10s`: limits how long clients can take to finish sending headers. This reduces slowloris risk, but can affect extremely poor network conditions.
- `proxy_read_timeout 30s`: limits how long Nginx waits for the upstream app to respond. This prevents stuck backend connections from consuming proxy resources forever, but long-running backend operations may need a higher value.
- `proxy_send_timeout 30s`: limits how long Nginx waits while sending the request to the upstream. This reduces resource exhaustion from stalled upstream communication, but again trades off against unusually slow backends.

Relevant access log lines showing `429` responses from `labs/lab11/logs/access.log`:

```text
192.168.158.1 - - [20/Apr/2026:14:54:58 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.6.0" rt=0.000 uct=- urt=-
192.168.158.1 - - [20/Apr/2026:14:54:58 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.6.0" rt=0.000 uct=- urt=-
192.168.158.1 - - [20/Apr/2026:14:54:59 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.6.0" rt=0.000 uct=- urt=-
```

Rate-limit behavior analysis:

- The `429` log entries have `uct=-` and `urt=-`, which shows those requests were blocked by Nginx before being proxied upstream.
- Earlier `401` entries in the same log have non-empty upstream timings, confirming that allowed login attempts reached Juice Shop and were rejected by application logic instead of the proxy.
- `labs/lab11/logs/error.log` also contains `limiting requests` warnings from the `login` zone, which confirms the rate limiter triggered exactly where it was configured.

## Acceptance Criteria Check

- [x] Nginx reverse proxy runs and Juice Shop is not directly exposed on a host port
- [x] Security headers are present on HTTP and HTTPS responses
- [x] HSTS appears only on HTTPS
- [x] TLS is enabled, scanned, and documented
- [x] Excess login attempts return `429`
- [x] Evidence artifacts are saved under `labs/lab11/`
