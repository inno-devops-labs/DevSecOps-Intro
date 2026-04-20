# Lab 11 Submission — Reverse Proxy Hardening with Nginx

## Student

- GitHub username: `ellilin`
- Branch: `feature/lab11`
- Date: `2026-04-20`
- Environment: macOS + Docker Desktop + local Nginx reverse proxy in front of OWASP Juice Shop

## Artifacts

- [compose-ps.txt](lab11/analysis/compose-ps.txt)
- [http-redirect.txt](lab11/analysis/http-redirect.txt)
- [headers-http.txt](lab11/analysis/headers-http.txt)
- [headers-https.txt](lab11/analysis/headers-https.txt)
- [testssl.txt](lab11/analysis/testssl.txt)
- [testssl-summary.txt](lab11/analysis/testssl-summary.txt)
- [rate-limit-test.txt](lab11/analysis/rate-limit-test.txt)
- [access-log-rate-limit.txt](lab11/analysis/access-log-rate-limit.txt)
- Runtime prerequisite: a local self-signed certificate and key were generated under `labs/lab11/reverse-proxy/certs/` so Nginx could start. The directory is git-ignored because private key material should stay local.

## Task 1 — Reverse Proxy Compose Setup

The stack was started from `labs/lab11/docker-compose.yml` after generating a local self-signed certificate with SANs for `localhost`, `127.0.0.1`, and `::1`. HTTP on `localhost:8080` redirects to HTTPS on `localhost:8443`.

Redirect check:

```text
HTTP 308
```

Compose status:

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     29 seconds ago   Up 27 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     28 seconds ago   Up 27 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Why the reverse proxy improves security:

- It centralizes TLS termination, so the application itself does not need to manage certificates or HTTPS policy.
- It injects security headers without changing Juice Shop code.
- It becomes a single enforcement point for redirect logic, request filtering, rate limiting, and timeout policy.
- It hides the upstream app behind an internal-only service, which simplifies exposure management and logging.

Why hiding the app port reduces attack surface:

- Only Nginx publishes host ports, so clients cannot bypass proxy controls and connect directly to Juice Shop.
- All external traffic must pass through the hardened policy layer first.
- The backend service remains reachable only on the internal Docker network, which reduces accidental exposure and removes an alternate attack path.

## Task 2 — Security Headers

Relevant HTTPS headers from [headers-https.txt](lab11/analysis/headers-https.txt):

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Header purpose:

- `X-Frame-Options: DENY`: blocks framing and reduces clickjacking risk.
- `X-Content-Type-Options: nosniff`: prevents MIME sniffing and helps stop browsers from treating content as a different type than declared.
- `Strict-Transport-Security`: tells browsers to prefer HTTPS for future requests and reduces downgrade/SSL-stripping risk after the first secure visit.
- `Referrer-Policy: strict-origin-when-cross-origin`: limits referrer leakage to other origins while still keeping useful same-origin detail.
- `Permissions-Policy: camera=(), geolocation=(), microphone=()`: disables sensitive browser capabilities that Juice Shop does not need.
- `COOP/CORP`: isolates the browsing context and restricts cross-origin resource usage, which helps reduce cross-origin data leaks and some XS-Leaks style interactions.
- `CSP-Report-Only`: evaluates a content security policy without blocking content yet, which is safer for an existing app that may rely on inline scripts or styles.

HSTS behavior was verified correctly:

- `headers-http.txt` contains the redirect and the non-HSTS headers only.
- `headers-https.txt` contains `strict-transport-security`.
- This is the right behavior because HSTS should only be delivered over HTTPS.

## Task 3 — TLS, HSTS, Rate Limiting, and Timeouts

### TLS and HSTS

The TLS scan was run with Docker Desktop on macOS against `https://host.docker.internal:8443`, and the full output is saved in [testssl.txt](lab11/analysis/testssl.txt).

Protocol support summary:

- Enabled: `TLS 1.2`, `TLS 1.3`
- Disabled: `SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`

Supported cipher suites reported by `testssl.sh`:

- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES128-GCM-SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

Why TLS 1.2+ is required:

- TLS 1.0 and 1.1 are deprecated and lack the modern cipher and protocol hardening expected for production systems.
- TLS 1.2 remains the practical compatibility baseline.
- TLS 1.3 is preferred because it simplifies the handshake, removes obsolete options, and defaults to stronger cryptography.

`testssl.sh` findings:

- Positive results: forward secrecy is offered, server cipher order is enforced, HSTS is present for 365 days, and the scan reported no Heartbleed, CCS, Ticketbleed, ROBOT, CRIME, BREACH, POODLE, FREAK, DROWN, LOGJAM, BEAST, or RC4 exposure.
- Expected local-development warnings: the chain of trust is `NOT ok (self signed)`, no CRL/OCSP URI is present, OCSP stapling is not offered, DNS CAA is not offered, and certificate transparency is not available.
- Additional caveat: because Docker Desktop on macOS scans `host.docker.internal` while the certificate SANs cover `localhost` and loopback IPs, `testssl.sh` also reports a hostname mismatch for the scan target. That is a tooling/localhost artifact, not a protocol weakness in Nginx itself.

### Rate Limiting

The login endpoint `/rest/user/login` is protected by:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

Burst-test results from [rate-limit-test.txt](lab11/analysis/rate-limit-test.txt):

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

Summary:

- `6` requests reached Juice Shop and failed authentication with `401`.
- `6` later requests were rejected by Nginx with `429 Too Many Requests`.

Why `rate=10r/m` with `burst=5` is a reasonable balance:

- It is low enough to slow brute-force password guessing from a single IP.
- The small burst allows short legitimate spikes, such as double-clicks or a few rapid retries.
- `nodelay` means those burst requests are accepted immediately instead of being queued, which keeps user experience snappy for small bursts but still drops excess traffic once the budget is exhausted.
- The trade-off is that very aggressive users behind a shared NAT could hit the limiter sooner than expected.

Relevant access-log lines from [access-log-rate-limit.txt](lab11/analysis/access-log-rate-limit.txt):

```text
192.168.65.1 - - [20/Apr/2026:16:40:08 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:16:40:08 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:16:40:08 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:16:40:08 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:16:40:08 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:16:40:08 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

### Timeout Settings and Trade-Offs

Relevant timeout configuration from `labs/lab11/reverse-proxy/nginx.conf`:

- `client_body_timeout 10s`
- `client_header_timeout 10s`
- `proxy_read_timeout 30s`
- `proxy_send_timeout 30s`
- `proxy_connect_timeout 5s`
- `send_timeout 10s`

Security effect and trade-offs:

- `client_body_timeout 10s`: limits how long Nginx waits for the client body, which helps against slow-upload behavior. Too low a value can hurt users on very poor connections.
- `client_header_timeout 10s`: constrains slow header delivery and helps reduce slowloris-style abuse. Too low a value can break unusually slow clients or long proxy chains.
- `proxy_read_timeout 30s`: limits how long Nginx waits for Juice Shop to produce a response. This contains hung upstream requests but could cut off legitimately slow operations.
- `proxy_send_timeout 30s`: limits how long Nginx waits while sending the request to the upstream. This prevents resource tying on unhealthy upstream paths.
- `proxy_connect_timeout 5s`: fails quickly when the upstream is unavailable instead of letting connections hang.
- `send_timeout 10s`: limits how long Nginx will spend sending data to a stalled client.

Overall, these values are conservative enough to reduce DoS exposure while still leaving normal interactive web traffic room to succeed.

## Deliverable Checklist

- [x] Task 1 — Reverse proxy compose setup
- [x] Task 2 — Security headers verification
- [x] Task 3 — TLS + HSTS + rate limiting + timeouts

## Bonus Task

No separate bonus task was listed inside `labs/lab11.md`. Lab 11 itself is already one of the optional bonus labs mentioned in the course `README.md`.
