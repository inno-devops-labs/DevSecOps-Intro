# Lab 11 Submission - Reverse Proxy Hardening with Nginx

## Task 1 - Reverse Proxy Compose Setup

Juice Shop was deployed behind an Nginx reverse proxy using `labs/lab11/docker-compose.yml`. Nginx is the only service with host-published ports, while Juice Shop is reachable only on the internal Docker network via `expose: 3000`.

Reverse proxies are valuable security control points because they can terminate TLS, inject security headers, centralize access logging, apply request filtering/rate limiting, and keep application containers off the public host interface. Hiding the direct app port reduces attack surface because scanners and attackers hit the hardened proxy first instead of the raw Node.js application.

Command evidence:

```text
$ docker compose ps
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j..." juice     ...             Up ...         3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint...." nginx     ...             Up ...         0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

HTTP redirects to HTTPS as expected:

```text
HTTP 308
```

Artifacts:

- `labs/lab11/analysis/docker-compose-ps.txt`
- `labs/lab11/analysis/http-redirect-status.txt`
- `labs/lab11/analysis/cert-details.txt`

## Task 2 - Security Headers

Relevant HTTPS response headers from `labs/lab11/analysis/headers-https.txt`:

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

Header analysis:

- **X-Frame-Options**: `DENY` prevents the application from being embedded in frames, reducing clickjacking risk.
- **X-Content-Type-Options**: `nosniff` tells browsers not to MIME-sniff responses, reducing script/style execution through content-type confusion.
- **Strict-Transport-Security (HSTS)**: forces future browser access over HTTPS for one year and includes subdomains; it is configured only on the HTTPS server block.
- **Referrer-Policy**: `strict-origin-when-cross-origin` limits sensitive URL leakage while preserving useful same-origin referrer behavior.
- **Permissions-Policy**: disables browser access to camera, geolocation, and microphone for this app surface.
- **COOP/CORP**: `same-origin` isolation reduces cross-origin data exposure and helps defend against browser side-channel and embedding issues.
- **CSP-Report-Only**: records likely CSP violations without enforcing blocking. Report-only is appropriate for Juice Shop because a strict CSP could break existing inline scripts/styles during a proxy-only hardening lab.

HSTS was verified as HTTPS-only: `headers-https.txt` contains `strict-transport-security`, while `headers-http.txt` does not.

Artifacts:

- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`

## Task 3 - TLS, HSTS, Rate Limiting, and Timeouts

TLS was scanned with `testssl.sh` against `https://localhost:8443`.

TLS protocol support:

```text
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
```

Supported cipher suites:

```text
TLSv1.2:
ECDHE-RSA-AES256-GCM-SHA384 / TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
ECDHE-RSA-AES128-GCM-SHA256 / TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

TLSv1.3:
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
```

TLSv1.2+ is required because SSLv2, SSLv3, TLSv1.0, and TLSv1.1 are obsolete and carry known downgrade, cipher, and protocol risks. TLSv1.3 is preferred because it removes legacy cryptography, simplifies negotiation, and improves handshake security/performance.

Notable `testssl.sh` findings:

- Forward secrecy is offered.
- Heartbleed, CCS, Ticketbleed, ROBOT, CRIME, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, and RC4 checks were not vulnerable/OK.
- Expected local-certificate warnings were present: chain of trust is `NOT ok (self signed)`, no CRL/OCSP URI is provided, OCSP stapling is not offered, and CAA is not offered. These are acceptable for a localhost self-signed lab certificate; production should use a trusted CA such as Let's Encrypt and enable OCSP stapling.

Rate limiting was tested against `/rest/user/login` with 12 rapid login attempts:

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

```text
401 6
429 6
```

The initial `401` responses are expected because the credentials are invalid but still allowed through the burst window. The later `429` responses confirm Nginx rate limiting blocked excessive login attempts.

Relevant access log lines:

```text
172.18.0.1 - - [07/May/2026:06:40:34 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [07/May/2026:06:40:34 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [07/May/2026:06:40:34 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
```

Rate-limit configuration:

- `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;`
- `limit_req zone=login burst=5 nodelay;`
- `limit_req_status 429;`

The `rate=10r/m` baseline slows brute-force attempts per source IP. `burst=5` allows short legitimate bursts, such as a user retrying credentials or a browser resubmitting quickly, while `nodelay` rejects excess traffic immediately instead of queueing requests. These values are intentionally conservative for a lab; production values should be tuned with traffic baselines and account lockout/step-up authentication behavior.

Timeout configuration and trade-offs:

- `client_body_timeout 10s`: limits slow request-body uploads and helps reduce slowloris-style abuse, but very slow clients may fail on large forms.
- `client_header_timeout 10s`: limits slow header transmission; good for DoS resistance, but hostile to very poor network conditions.
- `proxy_read_timeout 30s`: bounds how long Nginx waits for upstream responses; protects worker capacity, but long-running endpoints may need exceptions.
- `proxy_send_timeout 30s`: bounds upstream send time; prevents stuck upstream communication, but large uploads or slow upstream reads may require tuning.
- `proxy_connect_timeout 5s`: fails fast when the upstream app is unavailable.
- `keepalive_timeout 10s` and `send_timeout 10s`: reduce idle connection resource use while preserving normal browser behavior.

Artifacts:

- `labs/lab11/analysis/testssl.txt`
- `labs/lab11/analysis/testssl-clean.txt`
- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/rate-limit-summary.txt`
- `labs/lab11/analysis/rate-limit-access-log.txt`
- `labs/lab11/analysis/nginx-error-tail.txt`
- `labs/lab11/logs/access.log`
- `labs/lab11/logs/error.log`

## Submission Checklist

- [x] Task 1 - Reverse proxy compose setup completed.
- [x] Task 2 - Security headers verified over HTTP and HTTPS.
- [x] Task 3 - TLS, HSTS, rate limiting, logs, and timeout trade-offs documented.
- [x] Local private key was not committed; certificate metadata is captured in `analysis/cert-details.txt`.
