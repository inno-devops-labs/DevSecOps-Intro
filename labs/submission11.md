# Lab 11 Submission - Reverse Proxy Hardening with Nginx

## Student / Context
- Name: `Danil Fishchenko`
- Target branch for PR: `feature/lab11`
- Work date: `2026-04-19`
- Repository root: `DevSecOps-Intro/`
- Stack location: `labs/lab11/`
- Reverse proxy image: `nginx:stable-alpine`
- Application image: `bkimminich/juice-shop:v19.0.0`
- Generated certificate material is intentionally kept out of git via `labs/lab11/.gitignore`.

Helper assets added for reproducibility:
- `labs/lab11/collect-evidence.sh`
- `labs/lab11/generate-certs.sh`
- `labs/lab11/reverse-proxy/san.cnf`
- `labs/lab11/.gitignore`

Generated evidence for this submission is stored under `labs/lab11/analysis/` and `labs/lab11/logs/`.

## Task 1 - Reverse Proxy Compose Setup

Why the reverse proxy matters for security:
- It centralizes inbound traffic so TLS termination, header injection, request filtering, and rate limiting happen in one place without changing application code.
- It lets the operations layer enforce transport security and browser protections even if the upstream app does not implement them consistently.
- It reduces exposure by making Nginx the only published entrypoint and keeping Juice Shop reachable only on the internal Docker network.
- The Compose stack also waits for Juice Shop to become healthy before starting Nginx, which avoids transient startup-time `502` errors during verification.

Why hiding direct app ports reduces attack surface:
- The application is no longer directly reachable from the host, so scans and brute-force traffic must pass through the proxy controls.
- Nginx becomes the single choke point for TLS policy, timeouts, logging, and throttling.
- It avoids accidental bypass of hardening by users hitting the app container port directly.

Evidence:
- `labs/lab11/analysis/http-redirect.txt` shows the HTTP listener returns `308`.
- `labs/lab11/analysis/docker-compose-ps.txt` shows only `nginx` publishes host ports.
- `labs/lab11/analysis/docker-compose-config.txt` confirms the Compose file resolves cleanly.
- `labs/lab11/collect-evidence.sh` rebuilds the stack and refreshes all evidence files from one clean run.
- `labs/lab11/generate-certs.sh` recreates the local self-signed certificate before `docker compose up -d`.
- `labs/lab11/analysis/host-header-redirect-check.txt` confirms the HTTP redirect targets the fixed lab endpoint `https://localhost:8443/` even when a spoofed `Host` header is supplied.

Relevant `docker compose ps` output:

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS                   PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     6 seconds ago   Up 6 seconds (healthy)   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     6 seconds ago   Up Less than a second    0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Interpretation:
- `juice` exposes `3000/tcp` only inside Docker.
- `nginx` is the only service bound to host ports `8080` and `8443`.

## Task 2 - Security Headers Verification

Evidence:
- HTTP redirect headers: `labs/lab11/analysis/headers-http.txt`
- HTTPS headers: `labs/lab11/analysis/headers-https.txt`
- HSTS presence check: `labs/lab11/analysis/hsts-check.txt`

Relevant HTTPS security headers:

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

Header purpose summary:

| Header | Protection / value |
| --- | --- |
| `X-Frame-Options: DENY` | Blocks clickjacking by preventing the site from being embedded in frames. |
| `X-Content-Type-Options: nosniff` | Stops MIME-type sniffing so browsers do not reinterpret content types. |
| `Strict-Transport-Security` | Forces future HTTPS use and reduces downgrade / SSL stripping risk after the first secure visit. |
| `Referrer-Policy: strict-origin-when-cross-origin` | Limits referrer leakage to other origins while keeping same-origin detail. |
| `Permissions-Policy` | Explicitly disables powerful browser features not needed here, shrinking browser-side exposure. |
| `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` | Isolate the browsing context and restrict cross-origin resource usage to reduce XS-Leaks / cross-origin abuse. |
| `Content-Security-Policy-Report-Only` | Audits what a stricter CSP would block without breaking Juice Shop behavior in this lab. |

HSTS validation:
- `Strict-Transport-Security` is present on `https://localhost:8443/`.
- `Strict-Transport-Security` is absent from `http://localhost:8080/`, which is the expected behavior because HSTS must only be delivered over HTTPS.

## Task 3 - TLS, HSTS, Rate Limiting, and Timeouts

Evidence:
- TLS scan (plain text): `labs/lab11/analysis/testssl.txt`
- Convenience copy of the TLS scan with ANSI escape codes and the Docker platform warning removed: `labs/lab11/analysis/testssl-clean.txt`
- Certificate details: `labs/lab11/analysis/cert-details.txt`
- Rate-limit responses: `labs/lab11/analysis/rate-limit-test.txt`
- Rate-limit counts: `labs/lab11/analysis/rate-limit-counts.txt`
- Access log excerpts with `429`: `labs/lab11/analysis/access-429-snippets.txt`
- Filtered Nginx rate-limit warnings: `labs/lab11/analysis/rate-limit-warnings.txt`
- Full proxy logs: `labs/lab11/logs/access.log`, `labs/lab11/logs/error.log`

### TLS / HSTS Summary

Protocol support from `testssl-clean.txt`:
- Disabled: `SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`
- Enabled: `TLS 1.2`, `TLS 1.3`
- ALPN: `h2`, `http/1.1`

Supported cipher suites observed by `testssl`:
- TLS 1.2:
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- TLS 1.3:
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
  - `TLS_AES_128_GCM_SHA256`

Cipher-suite configuration note:
- `ssl_ciphers` in `nginx.conf` explicitly pins the TLS 1.2 suite set.
- The TLS 1.3 suites above are the suites actually negotiated and observed by `testssl`; with modern Nginx/OpenSSL they are governed by the TLS library and confirmed by the scan output.

Why TLS 1.2+ is required:
- TLS 1.0 and 1.1 are deprecated and do not meet current baseline expectations for modern web services.
- TLS 1.2 removes legacy protocol risk and still supports older but acceptable clients.
- TLS 1.3 further reduces handshake complexity, improves performance, and narrows the attack surface.

Key `testssl` findings:
- `Forward Secrecy` is offered.
- `Trust (hostname)` is `Ok via SAN`, because the generated certificate covers both `localhost` and `host.docker.internal`.
- `Session Resumption` is limited to `ID: yes` with `Tickets no`, which matches `ssl_session_tickets off` in the proxy configuration.
- `Heartbleed`, `CCS`, `CRIME`, `BREACH`, `POODLE`, `SWEET32`, `FREAK`, `DROWN`, `LOGJAM`, `BEAST`, and `RC4` checks reported `not vulnerable (OK)`.
- HSTS was detected as `365 days=31536000 s, includeSubDomains, preload`.

Expected warnings / limitations in this local setup:
- `Chain of trust: NOT ok (self signed)` because the lab uses a local self-signed certificate.
- `OCSP URI: NOT ok -- neither CRL nor OCSP URI provided`.
- `OCSP stapling: not offered`.
- `DNS CAA RR` and `Certificate Transparency` are not present for this local development certificate.
- The overall `testssl` grade is `T`, capped because of the self-signed certificate.
- The certificate SAN includes both `localhost` and `host.docker.internal`, which avoids a hostname mismatch when scanning from Docker Desktop.

How to improve the local TLS result further:
- Use a locally trusted CA such as `mkcert` so the certificate chains correctly on the host.
- For a real deployment, use a public CA certificate and enable OCSP stapling.
- Publish revocation metadata / OCSP endpoints only when using a real CA-backed certificate.

### Rate Limiting Results

Raw response sequence from `labs/lab11/analysis/rate-limit-test.txt`:

```text
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
429
```

Count summary from `labs/lab11/analysis/rate-limit-counts.txt`:
- `401 x 5`
- `429 x 7`

Interpretation:
- The non-throttled requests returned `401` because intentionally invalid credentials were submitted.
- After the initial request budget was exhausted, Nginx returned `429 Too Many Requests` before forwarding the remaining requests upstream.
- The lab prompt says to compare `200` vs `429`, but with intentionally invalid credentials the correct non-throttled result is `401`; this still proves the proxy rate limit because the later requests are blocked at Nginx before they reach Juice Shop.
- In this fresh run the split was `5 x 401` and `7 x 429`; slight variation around the cutoff is normal because `limit_req` uses a leaky-bucket algorithm and the exact result depends on request timing.

Rate-limit configuration analysis:
- `rate=10r/m` allows roughly one login attempt every six seconds per source IP in the steady state.
- `burst=5` allows a small short-lived spike so legitimate users can retry quickly after typos without being blocked immediately.
- `nodelay` means those burst requests are accepted immediately instead of being queued, which is suitable for interactive login flows.
- This is a practical balance: strict enough to slow brute-force attacks, but not so strict that a normal user gets locked out after one or two mistakes.

Relevant access-log lines showing `429` responses:

```text
192.168.65.1 - - [19/Apr/2026:09:24:02 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [19/Apr/2026:09:24:02 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [19/Apr/2026:09:24:02 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

Timeout settings from `labs/lab11/reverse-proxy/nginx.conf`:
- `client_body_timeout 10s`: limits how long Nginx waits for the request body, reducing slow body upload abuse.
- `client_header_timeout 10s`: limits how long headers may trickle in, helping against slowloris-style behavior.
- `proxy_read_timeout 30s`: limits how long Nginx waits for the upstream response once proxied.
- `proxy_send_timeout 30s`: limits how long Nginx waits while sending the proxied request to the upstream.

Timeout trade-offs:
- Shorter timeouts reduce resource exhaustion risk and are appropriate for a simple web app like Juice Shop.
- Timeouts that are too aggressive can hurt slow clients or long-running endpoints, so they should be tuned to real application behavior.
- A `30s` proxy timeout is conservative enough for the Juice Shop UI while still preventing connections from lingering too long.

Log evidence note:
- `labs/lab11/analysis/rate-limit-warnings.txt` is a filtered excerpt containing only `limiting requests` warnings from `logs/error.log`.
- The final stack run was captured after the Juice Shop healthcheck turned `healthy`, so the full logs reflect the validated run rather than transient startup race conditions.
- The `SSL_do_handshake() failed ... wrong version number` entries in `logs/error.log` are expected side effects of `testssl.sh` probing protocol combinations during the TLS scan, not evidence of an exploitable weakness by themselves.
- `labs/lab11/collect-evidence.sh` now regenerates the certificate, restarts the stack, and refreshes every artifact in one pass so the certificate dump, TLS scan, headers, and logs stay consistent.
- On ARM hosts the evidence script explicitly requests the `linux/amd64` `testssl.sh` image and writes a cleaned `testssl-clean.txt`, so the reviewer gets a readable TLS report without ANSI escape sequences or the Docker platform mismatch warning.

## Artifact Index

- Proxy config:
  - `labs/lab11/.gitignore`
  - `labs/lab11/collect-evidence.sh`
  - `labs/lab11/docker-compose.yml`
  - `labs/lab11/reverse-proxy/nginx.conf`
  - `labs/lab11/reverse-proxy/san.cnf`
  - `labs/lab11/generate-certs.sh`
- Verification outputs:
  - `labs/lab11/analysis/docker-compose-config.txt`
  - `labs/lab11/analysis/docker-compose-ps.txt`
  - `labs/lab11/analysis/http-redirect.txt`
  - `labs/lab11/analysis/headers-http.txt`
  - `labs/lab11/analysis/headers-https.txt`
  - `labs/lab11/analysis/host-header-redirect-check.txt`
  - `labs/lab11/analysis/hsts-check.txt`
  - `labs/lab11/analysis/testssl.txt`
  - `labs/lab11/analysis/testssl-clean.txt`
  - `labs/lab11/analysis/cert-details.txt`
  - `labs/lab11/analysis/rate-limit-test.txt`
  - `labs/lab11/analysis/rate-limit-counts.txt`
  - `labs/lab11/analysis/access-429-snippets.txt`
  - `labs/lab11/analysis/rate-limit-warnings.txt`
- Logs:
  - `labs/lab11/logs/access.log`
  - `labs/lab11/logs/error.log`

## Final Acceptance Check

- [x] Nginx reverse proxy runs and Juice Shop is not directly exposed on a host port
- [x] HTTP redirects to HTTPS with `308`
- [x] Security headers are present on the proxied responses
- [x] HSTS is present only on HTTPS
- [x] TLS is limited to `TLS 1.2` and `TLS 1.3`
- [x] `testssl.sh` output is captured under `labs/lab11/analysis/`
- [x] Login rate limiting returns `429` under repeated requests
- [x] Access logs with `429` responses are captured under `labs/lab11/`
- [x] Submission analysis is documented in `labs/submission11.md`
