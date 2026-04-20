# Lab 11 - Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Scope

- Analysis date: `2026-04-20`
- Stack path: `labs/lab11`
- Public endpoints:
  - `http://localhost:8080` (HTTP redirect)
  - `https://localhost:8443` (TLS endpoint)
- Evidence directory: `labs/lab11/analysis`

## Task 1 - Reverse Proxy Compose Setup

### Why reverse proxying improves security

- TLS termination is centralized at Nginx, so certificate and protocol/cipher policy are managed in one place.
- Security headers are injected at the edge (`add_header ... always`) without modifying Juice Shop source code.
- Request filtering and throttling (for example, `limit_req` on login) are enforced before traffic reaches the app.
- Nginx becomes a single controlled ingress point for logging, timeout control, and policy enforcement.

### Why hiding app ports reduces attack surface

- The Juice Shop container is not directly reachable from host network; only Nginx is published.
- This prevents bypassing proxy controls (headers, TLS policy, rate limits, and logging).
- Attackers must go through one hardened entry point instead of probing app service ports directly.

### Compose evidence

Command run:

```bash
docker compose ps
```

Output (from `labs/lab11/analysis/compose-ps.txt`):

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j..."   juice     10 seconds ago   Up 9 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint...."   nginx     9 seconds ago    Up 8 seconds   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```

HTTP redirect check (`labs/lab11/analysis/http-redirect.txt`): `HTTP 308`.

## Task 2 - Security Headers

### Relevant HTTPS headers captured

From `labs/lab11/analysis/headers-https.txt`:

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

### Header purpose and protection

- **X-Frame-Options (`DENY`)**: mitigates clickjacking by blocking framing of the app in other origins.
- **X-Content-Type-Options (`nosniff`)**: stops MIME sniffing and reduces content-type confusion attacks.
- **Strict-Transport-Security (HSTS)**: forces browsers to use HTTPS for future requests and blocks protocol downgrade/SSL-stripping in subsequent visits.
- **Referrer-Policy (`strict-origin-when-cross-origin`)**: limits sensitive URL/path leakage in `Referer` headers.
- **Permissions-Policy**: disables high-risk browser features (camera, geolocation, microphone) unless explicitly allowed.
- **COOP/CORP (`same-origin`)**: isolates browsing context/resource usage to reduce cross-origin data leakage classes and XS-Leaks-style abuse.
- **CSP-Report-Only**: records CSP violations without breaking JS-heavy application behavior, enabling iterative hardening.

## Task 3 - TLS, HSTS, Rate Limiting, and Timeouts

### TLS scan summary (testssl)

Scan command (Windows/Docker Desktop target):

```bash
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443
```

Raw scan output: `labs/lab11/analysis/testssl.txt`.

Protocol support observed:

- Disabled: `SSLv2`, `SSLv3`, `TLS1.0`, `TLS1.1`
- Enabled: `TLS1.2`, `TLS1.3`

Supported cipher suites observed:

- TLS 1.2:
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- TLS 1.3:
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
  - `TLS_AES_128_GCM_SHA256`

Why TLS 1.2+ (prefer 1.3):

- TLS 1.0/1.1 are deprecated and weaker against modern attack models.
- TLS 1.2+ enables modern AEAD ciphers and stronger handshake behavior.
- TLS 1.3 reduces legacy negotiation complexity and improves baseline security/performance.

Warnings/notes from testssl:

- Expected for local self-signed cert setup:
  - `Chain of trust: NOT ok (self signed)`
  - URI/hostname mismatch in this scan context (`host.docker.internal` vs cert CN/SAN `localhost`)
  - `neither CRL nor OCSP URI provided`
  - `OCSP stapling not offered`
  - `DNS CAA RR not offered`
- Vulnerability checks (Heartbleed, CCS, POODLE, FREAK, DROWN, etc.) were reported as not vulnerable.

### HSTS scope check (HTTPS only)

- HTTP headers (`labs/lab11/analysis/headers-http.txt`) do **not** contain `Strict-Transport-Security`.
- HTTPS headers (`labs/lab11/analysis/headers-https.txt`) contain:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

This confirms HSTS is correctly emitted only on TLS responses.

### Rate limiting evidence and analysis

Configured in `labs/lab11/reverse-proxy/nginx.conf`:

- Zone: `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;`
- Endpoint enforcement: `location = /rest/user/login { limit_req zone=login burst=5 nodelay; ... }`
- Status for limited requests: `limit_req_status 429;`

Burst test output (`labs/lab11/analysis/rate-limit-test.txt`):

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

Result summary:

- `429` responses: `6`
- Non-429 responses: `6` (upstream app returned `500` for the invalid login payload used)

Interpretation:

- Even though upstream returned errors for early requests, Nginx rate limiting still activated and blocked excess attempts with `429`, which is the expected protective behavior.
- `rate=10r/m` with `burst=5` allows short legitimate spikes while throttling sustained brute-force traffic.

### Timeout settings and trade-offs

From `labs/lab11/reverse-proxy/nginx.conf`:

- `client_body_timeout 10s`: limits how long client can stream request body (helps against slow POST/slowloris variants).
- `client_header_timeout 10s`: limits header read time (reduces slow header abuse).
- `proxy_read_timeout 30s`: upper bound waiting for upstream response.
- `proxy_send_timeout 30s`: upper bound for sending request to upstream.

Trade-off rationale:

- Lower timeouts reduce resource exhaustion risk under abusive slow connections.
- Overly aggressive values can hurt legitimate users on high-latency/unstable networks.
- Current values are moderate for a training/lab setup: strict enough for abuse resistance, still practical for normal API/UI calls.

### Access log evidence for 429

From `labs/lab11/analysis/access-429.txt`:

```text
172.23.0.1 - - [20/Apr/2026:17:04:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.23.0.1 - - [20/Apr/2026:17:04:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.23.0.1 - - [20/Apr/2026:17:04:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.23.0.1 - - [20/Apr/2026:17:04:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.23.0.1 - - [20/Apr/2026:17:04:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.23.0.1 - - [20/Apr/2026:17:04:08 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

## Deliverable Checklist

- [x] Task 1 - Reverse proxy compose setup
- [x] Task 2 - Security headers verification
- [x] Task 3 - TLS + HSTS + rate limiting + timeout validation

