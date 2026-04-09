# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

![difficulty](https://img.shields.io/badge/difficulty-intermediate-orange)
![topic](https://img.shields.io/badge/topic-Application%20Hardening-blue)
![points](https://img.shields.io/badge/points-10-orange)

> Goal: Place OWASP Juice Shop behind an Nginx reverse proxy and harden it with security headers, TLS, and request rate limiting — without changing app code.
> Deliverable: A PR from `feature/lab11` with `labs/submission11.md` including command evidence, header/TLS scans, rate-limit test results, and a short analysis of trade-offs.

---

## Overview

You will:
- Deploy Juice Shop behind a reverse proxy using Docker Compose
- Add and verify essential security headers (XFO, XCTO, HSTS, Referrer-Policy, Permissions-Policy, COOP/CORP)
- Enable TLS with a local self-signed certificate and verify configuration
- Implement request rate limiting and timeouts to reduce brute-force/DoS risk

This lab is designed to be practical and educational, focusing on changes operations teams can make without touching application code.

---

## Prerequisites

Before starting, ensure you have:
- ✅ Docker installed and running (`docker --version`)
- ✅ Docker Compose installed (`docker compose version`)
- ✅ `curl` and `jq` for testing and JSON parsing
- ✅ At least 2GB free disk space
- ✅ ~45-60 minutes available

**Quick Setup Check:**
```bash
# Pull images in advance (optional)
docker pull bkimminich/juice-shop:v19.0.0
docker pull nginx:stable-alpine
docker pull alpine:latest
docker pull drwetter/testssl.sh:latest

# Create working directories
mkdir -p labs/lab11/{reverse-proxy/certs,logs,analysis}
```

**Files provided in this repo:**
- `labs/lab11/docker-compose.yml` - Stack configuration
- `labs/lab11/reverse-proxy/nginx.conf` - Pre-configured with security headers, TLS, rate limiting

---

## Tasks

### Task 1 — Reverse Proxy Compose Setup (2 pts)
⏱️ **Estimated time:** 10 minutes

**Objective:** Run Juice Shop behind Nginx (no app port exposed directly).

#### 1.1: Prepare certs and start the stack
```bash
# Navigate to lab11 directory
cd labs/lab11

# Generate a local self-signed cert with SAN for localhost so Nginx can start
# (write OpenSSL config first, then run openssl — order matters)
mkdir -p reverse-proxy/certs
docker run --rm -v "$(pwd)/reverse-proxy/certs:/certs" alpine:latest sh -c '
  apk add --no-cache openssl
  cat > /tmp/san.cnf << "EOFCNF"
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
EOFCNF
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /certs/localhost.key -out /certs/localhost.crt \
    -config /tmp/san.cnf -extensions v3_req
'

# Start services
docker compose up -d
docker compose ps

# Verify HTTP (should redirect to HTTPS)
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
```

Expected: `HTTP 308` (redirect to HTTPS).

#### 1.2: Confirm no direct app exposure
```bash
# Only Nginx should have published host ports; Juice Shop should have none
docker compose ps
```

In `labs/submission11.md`, document:

**Task 1 Requirements:**
  - Explain why reverse proxies are valuable for security (TLS termination, security headers injection, request filtering, single access point)
  - Explain why hiding direct app ports reduces attack surface
  - Include the `docker compose ps` output showing only Nginx has published host ports (Juice Shop shows none)

---

### Task 2 — Security Headers (3 pts)
⏱️ **Estimated time:** 10 minutes

**Objective:** Review the essential headers at the proxy and verify they’re present over HTTP/HTTPS.

Headers configured in `nginx.conf`:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), geolocation=(), microphone=()`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin`
  - `Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'`

Note: CSP is set in Report-Only mode to avoid breaking Juice Shop functionality.

⏱️ ~10 minutes

#### 2.1: Verify headers (HTTP)
```bash
curl -sI http://localhost:8080/ | tee analysis/headers-http.txt
```

#### 2.2: Verify headers (after TLS in Task 3)
```bash
curl -skI https://localhost:8443/ | tee analysis/headers-https.txt
```

In `labs/submission11.md`, document:

**Task 2 Requirements:**
  - Paste relevant security headers from `headers-https.txt`
  - For each header, explain what it protects against:
    - **X-Frame-Options**: ---
    - **X-Content-Type-Options**: ---
    - **Strict-Transport-Security (HSTS)**: ---
    - **Referrer-Policy**: ---
    - **Permissions-Policy**: ---
    - **COOP/CORP**: ---
    - **CSP-Report-Only**: ---
---

### Task 3 — TLS, HSTS, Rate Limiting & Timeouts (5 pts)
⏱️ **Estimated time:** 20 minutes

**Objective:** Confirm HTTPS and HSTS behavior, scan TLS, and validate rate limiting and timeouts to reduce brute-force and slowloris risks.

#### 3.1: Scan TLS (testssl.sh)
Use one of the following, depending on your OS:
```bash
# Linux: use host networking to reach localhost:8443
docker run --rm --network host drwetter/testssl.sh:latest https://localhost:8443 \
  | tee analysis/testssl.txt

# Mac/Windows (Docker Desktop): target host.docker.internal
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 \
  | tee analysis/testssl.txt
```

---

#### 3.2: Validate rate limiting on login
Login rate limit is configured on `/rest/user/login` with Nginx `limit_req` and `limit_req_status 429`.

##### Trigger rate limiting
```bash
for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done | tee analysis/rate-limit-test.txt
```
Expected: Some responses return `429` once the burst+rate thresholds are exceeded.

In `labs/submission11.md`, document:

**Task 3 Requirements:**
- TLS/testssl summary:
  - Summarize TLS protocol support from testssl scan (which versions are enabled)
  - List cipher suites that are supported
  - Explain why TLSv1.2+ is required (prefer TLSv1.3)
  - Note any warnings or vulnerabilities from testssl output
  - Confirm HSTS header appears only on HTTPS responses (not HTTP)

Note on dev certificates: On localhost you should still expect these “NOT ok” items with a self‑signed cert: chain of trust (self‑signed), OCSP/CRL/CT/CAA, and OCSP stapling not offered. To eliminate them, either trust a local CA (e.g., mkcert) or use a real domain and a public CA (e.g., Let’s Encrypt) and then enable OCSP stapling (comments in nginx.conf).

- Rate limiting & timeouts:
  - Show rate-limit test output (how many 200s vs 429s)
  - Explain the rate limit configuration: `rate=10r/m`, `burst=5`, and why these values balance security vs usability
  - Explain timeout settings in nginx.conf: `client_body_timeout`, `client_header_timeout`, `proxy_read_timeout`, `proxy_send_timeout`, with trade-offs
  - Paste relevant lines from access.log showing 429 responses

---

## Acceptance Criteria

- ✅ Nginx reverse proxy running; Juice Shop not directly exposed
- ✅ Security headers present over HTTP/HTTPS; HSTS only on HTTPS
- ✅ TLS enabled and scanned; HSTS verified; outputs captured
- ✅ Rate limiting returns 429 on excessive login attempts; logs captured; timeouts discussed
- ✅ All outputs committed under `labs/lab11/`

---

## Cleanup

After completing the lab:

```bash
# Stop and remove containers
cd labs/lab11  # if not already there
docker compose down

# Optional: Remove generated certificates
# rm -rf labs/lab11/reverse-proxy/certs/*

# Check disk space
docker system df
```

---

## How to Submit

1. Create a branch and push it to your fork:
```bash
git switch -c feature/lab11
# create labs/submission11.md with your findings
git add labs/lab11/ labs/submission11.md
git commit -m "docs: add lab11 — nginx reverse proxy hardening"
git push -u origin feature/lab11
```
2. Open a PR from your fork’s `feature/lab11` → course repo’s `main`.
3. In the PR description include:
```text
- [x] Task 1 — Reverse proxy compose setup
- [x] Task 2 — Security headers verification
- [x] Task 3 — TLS + HSTS + rate limiting + timeouts (+ testssl)
```
4. Submit the PR URL via Moodle before the deadline.

---

## Rubric (10 pts)

| Criterion                                             | Points |
| ----------------------------------------------------- | -----: |
| Task 1 — Reverse proxy compose setup                  |    2.0 |
| Task 2 — Security headers (HTTP/HTTPS)                |    3.0 |
| Task 3 — TLS, HSTS, rate limiting & timeouts          |    5.0 |
| Total                                                 |   10.0 |

---

## Guidelines

- Keep app container internal; only expose Nginx ports to host
- Use `add_header ... always;` so headers appear even on errors/redirects
- Place HSTS only on HTTPS server blocks
- Start CSP in Report-Only and iterate; Juice Shop is JS-heavy and can break under strict CSP
- Choose rate limits that balance security and usability; document your rationale

<details>
<summary>Resources</summary>

- Nginx security headers: https://nginx.org/en/docs/http/ngx_http_headers_module.html
- TLS config guidelines: https://ssl-config.mozilla.org/
- testssl.sh: https://github.com/drwetter/testssl.sh
- Permissions Policy: https://www.w3.org/TR/permissions-policy-1/

</details>
