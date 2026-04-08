# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Environment

- Date: 2026-04-08
- OS: macOS (Darwin 25.3.0, arm64) / Docker Desktop
- Docker: 29.2.0
- Docker Compose: v5.0.2
- Target app: OWASP Juice Shop `v19.0.0`
- Reverse proxy: `nginx:stable-alpine`

---

## Task 1 — Reverse Proxy Compose Setup (2 pts)

### 1.1 Stack startup and redirect checks

Commands used:

```bash
cd labs/lab11
mkdir -p reverse-proxy/certs logs analysis

# Generate self-signed cert with SAN for localhost
docker run --rm -v "$(pwd)/reverse-proxy/certs":/certs alpine:latest sh -c 'apk add --no-cache openssl >/dev/null && cat > /tmp/san.cnf << "EOF"
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /certs/localhost.key -out /certs/localhost.crt -config /tmp/san.cnf -extensions v3_req'

docker compose up -d
docker compose ps | tee analysis/compose-ps.txt
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/ | tee analysis/http-redirect.txt
```

HTTP redirect result (`analysis/http-redirect.txt`):

```text
HTTP 308
```

Container exposure result (`analysis/compose-ps.txt`):

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED                  STATUS                  PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     Less than a second ago   Up Less than a second   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     Less than a second ago   Up Less than a second   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

### 1.2 Security rationale

- A reverse proxy gives one controlled ingress point where ops can enforce TLS termination, add security headers, and apply filtering/rate limits without changing application code.
- Proxy-based controls are centralized and consistent, which lowers configuration drift across environments.
- Hiding direct app ports reduces attack surface because clients cannot hit the Node.js app directly and bypass proxy security policies.
- In this setup only Nginx publishes host ports; Juice Shop stays internal (`3000/tcp` only), reachable through Docker network from Nginx.

---

## Task 2 — Security Headers (3 pts)

### 2.1 Header verification evidence

Commands used:

```bash
curl -sI http://localhost:8080/ | tee analysis/headers-http.txt
curl -skI https://localhost:8443/ | tee analysis/headers-https.txt
```

Relevant HTTPS headers (`analysis/headers-https.txt`):

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

### 2.2 What each header protects against

- **X-Frame-Options (`DENY`)**: blocks clickjacking by preventing page embedding in iframes.
- **X-Content-Type-Options (`nosniff`)**: prevents MIME sniffing and reduces script/style execution from mislabeled content.
- **Strict-Transport-Security (HSTS)**: tells browsers to use HTTPS only for the host during `max-age`, reducing SSL stripping/downgrade risk.
- **Referrer-Policy (`strict-origin-when-cross-origin`)**: limits sensitive URL/path leakage via Referer header on cross-origin requests.
- **Permissions-Policy**: disables browser capabilities (camera/geolocation/microphone) unless explicitly allowed.
- **COOP/CORP**: improves cross-origin isolation and limits resource sharing with other origins, reducing data-leak and cross-window attack vectors.
- **CSP-Report-Only**: evaluates CSP violations without breaking current app behavior; useful for tuning policy safely before enforcement.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts (5 pts)

### 3.1 TLS scan summary (`testssl.sh`)

Command used (macOS/Docker Desktop):

```bash
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 | tee analysis/testssl.txt
```

Protocol support summary:

- Enabled: `TLS 1.2`, `TLS 1.3`
- Disabled: `SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`

Supported cipher suites observed:

- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

Why TLS 1.2+ is required (prefer 1.3):

- TLS 1.0/1.1 and SSL versions are deprecated and have weaker cryptographic guarantees.
- TLS 1.2+ supports modern AEAD ciphers and forward secrecy, reducing impact of key compromise and known downgrade/legacy attacks.
- TLS 1.3 removes many legacy features and simplifies secure negotiation.

Warnings and notable findings from scan:

- Most tested vulnerabilities were reported as **not vulnerable** (Heartbleed, POODLE, FREAK, DROWN, LOGJAM, BEAST, etc.).
- Expected localhost/dev warnings:
  - self-signed certificate (`Chain of trust: NOT ok`)
  - hostname mismatch in scan (`host.docker.internal` vs cert CN/SAN `localhost`)
  - no CRL/OCSP URI and `OCSP stapling not offered`
- Overall testssl grade was capped due certificate trust/hostname issues, which is expected for self-signed local certs.

### 3.2 HSTS behavior (HTTPS only)

From `analysis/headers-http.txt` (HTTP 308 redirect), there is **no** `Strict-Transport-Security` header.

From `analysis/headers-https.txt`, HSTS is present:

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

This confirms HSTS is sent only on HTTPS responses.

### 3.3 Rate limiting validation

Command used:

```bash
for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done | tee analysis/rate-limit-test.txt
```

Observed results (`analysis/rate-limit-summary.txt`):

```text
401 6
429 6
```

Interpretation:

- `200`: 0 (test intentionally used invalid credentials, so successful auth was not expected)
- `429`: 6 (requests blocked by Nginx rate limiting)
- First requests reached upstream login handler and returned `401` (invalid credentials).
- After threshold exceeded, Nginx enforced `limit_req_status 429` and blocked additional attempts.

Rate-limit configuration rationale (`nginx.conf`):

- `rate=10r/m`: allows normal interactive login attempts while limiting brute-force velocity.
- `burst=5`: allows short spikes (e.g., user retries, browser/API retries) without immediate blocking.
- `nodelay`: beyond burst, excess requests are rejected immediately (faster protection, clearer client signal via 429).
- Security/usability trade-off: tighter limits block attacks earlier but can affect legitimate users behind NAT or during password manager retries.

Access log evidence for blocked requests (`analysis/access-429.txt`):

```text
146.75.122.132 - - [08/Apr/2026:10:43:51 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
146.75.122.132 - - [08/Apr/2026:10:43:51 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
146.75.122.132 - - [08/Apr/2026:10:43:51 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

### 3.4 Timeout settings and trade-offs

Configured in `nginx.conf`:

- `client_body_timeout 10s`: limits time to send request body; mitigates slow body uploads.
- `client_header_timeout 10s`: mitigates slowloris-style delayed headers.
- `proxy_read_timeout 30s`: limits waiting time for upstream response; avoids long-held worker connections.
- `proxy_send_timeout 30s`: limits time to send request to upstream.

Trade-off:

- Shorter timeouts reduce resource exhaustion risk and improve resilience under abusive traffic.
- Too aggressive values can hurt users on slow or unstable networks and can interrupt legitimately slow upstream operations.

---

## Artifacts Produced

All lab outputs were saved under `labs/lab11/`:

- `analysis/compose-ps.txt`
- `analysis/http-redirect.txt`
- `analysis/headers-http.txt`
- `analysis/headers-https.txt`
- `analysis/testssl.txt`
- `analysis/rate-limit-test.txt`
- `analysis/rate-limit-summary.txt`
- `analysis/access-429.txt`
- `analysis/docker-version.txt`
- `analysis/docker-compose-version.txt`
- `logs/access.log`
- `reverse-proxy/certs/localhost.crt`
- `reverse-proxy/certs/localhost.key` (generated locally, intentionally not committed)
