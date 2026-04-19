# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### What was implemented

- Juice Shop was deployed behind Nginx reverse proxy.
- Only Nginx publishes host ports (`8080`, `8443`).
- Juice Shop container has no published host ports (internal-only networking).

### Why reverse proxy improves security

A reverse proxy provides:
- **TLS termination** at a single control point.
- **Centralized security headers** injection without changing app code.
- **Request filtering and controls** (rate limiting, timeouts).
- **Single ingress point**, simplifying hardening, logging, and monitoring.

### Why hiding direct app ports reduces attack surface

When the app is not directly exposed:
- Attackers cannot bypass proxy security controls.
- Backend service is reachable only from internal Docker network.
- Operational controls (headers/TLS/rate limits) are consistently enforced.

### Evidence

![alt text](<Screenshot 2026-04-19 203149.png>)

## Task 2 — Security Headers Verification

Header checks were captured in:

- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`

### Verified headers (HTTPS)

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), geolocation=(), microphone=()`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'`

### What each header protects against

- **X-Frame-Options (DENY):** prevents clickjacking by blocking iframe embedding.
- **X-Content-Type-Options (nosniff):** prevents MIME sniffing and type confusion attacks.
- **HSTS:** forces HTTPS and reduces SSL stripping / downgrade risk.
- **Referrer-Policy:** limits leakage of sensitive URL/referrer information.
- **Permissions-Policy:** disables sensitive browser features not needed by the app.
- **COOP/CORP:** improves cross-origin isolation and reduces cross-origin data abuse.
- **CSP-Report-Only:** monitors policy violations without breaking JS-heavy app functionality in this phase.

---

## Task 3 — TLS, HSTS, Rate Limiting, and Timeouts

### 3.1 TLS scan summary (`analysis/testssl.txt`)

- Protocols:
  - **Enabled:** TLS 1.2, TLS 1.3
  - **Disabled:** SSLv2, SSLv3, TLS 1.0, TLS 1.1
- Cipher posture:
  - Strong AEAD ciphers offered (AES-GCM, CHACHA20-POLY1305)
  - Forward Secrecy is enabled
  - Server cipher order is enabled
- Vulnerability checks:
  - Major legacy TLS vulnerabilities reported as **not vulnerable** (Heartbleed, POODLE, FREAK, DROWN, LOGJAM, etc.)
- HSTS:
  - Present on HTTPS response
  - Not present on HTTP redirect response (expected and correct)

### Notes on expected development warnings

Because this lab uses a local self-signed cert:
- Chain of trust: **NOT ok (self-signed)** — expected
- Domain mismatch warning may appear when scanning `host.docker.internal` while cert CN/SAN is `localhost` — expected
- OCSP/CRL/CT/CAA/stapling warnings are expected in local dev setup

These are acceptable for localhost lab validation.

---

### 3.2 Rate limiting test (`analysis/rate-limit-test.txt`)

Login endpoint tested: `POST /rest/user/login`

Observed sequence:
- Initial requests returned `500` from upstream app
- Subsequent requests returned `429 Too Many Requests` after Nginx threshold was exceeded

This confirms proxy-level `limit_req` enforcement works even when backend responses are non-401/200.

Example observed output:
- `500` (first 6 requests)
- `429` (next 6 requests)

![alt text](<Screenshot 2026-04-19 204335.png>)

### 3.3 Access log evidence of 429 (`logs/access.log`)

Access log includes multiple entries like:

- `POST /rest/user/login HTTP/1.1" 429 ...`

This is direct evidence that Nginx rate limiting triggered.

### Rate limit configuration rationale

Configured values:
- `rate=10r/m`
- `burst=5`
- `limit_req_status 429`

Trade-off:
- Helps reduce brute-force and burst abuse on login.
- Keeps short, normal user bursts usable.
- Too strict values may affect legitimate users behind shared IP/NAT.

### Timeout trade-offs (from nginx.conf)

- `client_body_timeout`
- `client_header_timeout`
- `proxy_read_timeout`
- `proxy_send_timeout`

Security value:
- Reduces slowloris-style and stalled connection abuse.
- Limits backend resource exhaustion from slow clients/upstream stalls.

Trade-off:
- Aggressive timeout values can drop valid slow-network users.
- Must balance resilience and usability.

