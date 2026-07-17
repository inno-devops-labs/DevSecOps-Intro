# Lab 11 — BONUS — Submission

**Stack:** `docker-compose` with `juice` (Juice Shop v20.0.0, port 3000) behind a hardened
`nginx:stable-alpine` reverse proxy (ports 80/443). Bonus adds an `owasp/modsecurity-crs`
(ModSecurity v3 + OWASP CRS v4.25.1) WAF sidecar in front of Nginx on ports 8080/8443.

> **Environment note:** run on Windows + Docker Desktop (WSL2). All proofs below were captured
> live against the running stack; raw artifacts are in [`labs/lab11/results/`](../labs/lab11/results/).

---

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)

```nginx
  # ---- http {} block ----
  # Fail-closed request timeouts at http level so BOTH :80 and :443 enforce them
  client_body_timeout   10s;
  client_header_timeout 10s;
  send_timeout          10s;

  # HTTP server — redirect to HTTPS, headers apply even on the redirect
  server {
    listen 80;
    listen [::]:80;
    server_name _;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    return 308 https://$host$request_uri;
  }

  # HTTPS server
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # TLS 1.3 only — modern profile
    ssl_protocols TLSv1.3;
    # TLS 1.3 suites MUST be set via ssl_conf_command Ciphersuites — the ssl_ciphers
    # directive only governs TLS <=1.2 and errors on 1.3 suite names under OpenSSL 3.x.
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers off;   # ignored by TLS 1.3 anyway (client picks)

    # Six required security headers, all with `always`
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    location = /rest/user/login { limit_req zone=login burst=5 nodelay; proxy_pass http://juice; }
    location / { proxy_pass http://juice; }
  }
```

> **Deviation from the handout, documented:** the lab suggests `ssl_ciphers TLS_AES_128_GCM_SHA256:...`
> for the TLS 1.3 suites. On this stack (nginx:stable-alpine → OpenSSL 3.x) that fails to start with
> `SSL_CTX_set_cipher_list(...) failed (no cipher match)`, because `ssl_ciphers` only accepts TLS ≤1.2
> cipher strings. The correct nginx directive for TLS 1.3 suites is `ssl_conf_command Ciphersuites`.
> Verified: nginx boots and negotiates the required suite (see Task 2 cipher proof).

### A. HTTPS redirect proof

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
```

### B. TLS 1.3 proof

```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
```

### C. Security headers proof (all 6 present)

```
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against

- **HSTS:** forces the browser to use HTTPS for 2 years, defeating SSL-strip/downgrade attacks where a network attacker rewrites `https://` links to `http://`.
- **X-Content-Type-Options: nosniff:** stops the browser from MIME-sniffing a response into an executable type, so a user-uploaded "image" can't be reinterpreted and run as HTML/JS.
- **X-Frame-Options: DENY:** forbids the site from being embedded in any `<iframe>`, killing clickjacking overlays.
- **Referrer-Policy:** trims the `Referer` header to just the origin cross-site (and nothing over plain HTTP), so full URLs with tokens/paths don't leak to third parties.
- **Permissions-Policy:** turns off camera, microphone and geolocation for all origins, so third-party scripts can't silently reach those browser APIs.
- **Content-Security-Policy (Report-Only):** constrains where scripts/styles/images may load from and reports violations without breaking Juice Shop's inline-script frontend — the staging step before enforcing a blocking CSP.

---

## Task 2: Production Posture

### Rate limit proof

`limit_req_zone ... rate=10r/m` + `limit_req zone=login burst=5 nodelay` + `limit_req_status 429`.
60 concurrent POSTs to `/rest/user/login`:

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 (allowed → reached upstream) | 6 |
| 429 (rate-limited at edge) | 54 |
| 5xx | 0 |

6 allowed = burst 5 + 1 in-window token; the remaining 54 are rejected with **429** at the edge.

### Timeout enforced

```
Slowloris-style partial-request test — sent 'GET / HTTP/1.0\r\n' with no terminating
blank line, then read the socket until close.

Result: nginx closed the connection after ~10038 ms  (client_header_timeout = 10s → fail-closed).
No response bytes are sent — the worker is freed instead of being held for the 60s default.
```

> Note: `client_header_timeout` was hoisted from the `server{}` block to the `http{}` block so the
> `:80` redirect server also enforces it (otherwise `:80` inherited nginx's 60s default and held the
> worker for a full minute — a real slowloris gap in the starter config).

### Cipher hardening

```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

Matches the required suite + curve: `TLS_AES_256_GCM_SHA384` over an `X25519` key exchange.
Session resumption: `ssl_session_cache shared:SSL:10m; ssl_session_timeout 1d; ssl_session_tickets off`
(cache on for the perf win, tickets off so leaked ticket keys can't retroactively break forward secrecy).
Connection cap: `limit_conn_zone ... zone=conn:10m` + `limit_conn conn 50` per client IP.

### Cert rotation runbook (7 steps)

1. **Detect expiry**: monitor the leaf cert's `notAfter` (`openssl x509 -enddate -noout -in current.crt`); alert at 30 days, page at 7. Most TLS outages are forgotten renewals.
2. **Order new cert**: `certbot renew` (Let's Encrypt, HTTP-01/DNS-01) for standard certs; vendor CSR for EV/wildcard. Produces `newcert.pem` + `newkey.pem`.
3. **Validate**: `openssl x509 -in newcert.pem -text -noout` (right CN/SAN + dates) and `openssl verify -CAfile chain.pem newcert.pem` (chain builds to a trusted root).
4. **Atomic swap**: point Nginx at symlinks (`current.crt`→`newcert.pem`) and flip with `ln -sf newcert.pem current.crt && nginx -t && nginx -s reload` — zero-downtime, no worker drop.
5. **Verify**: `curl -vkI https://host | head -1` and `echo | openssl s_client -connect host:443 | openssl x509 -noout -serial -enddate` show the new serial/expiry; `testssl.sh host:443` re-confirms full posture.
6. **Rollback plan**: keep the previous cert+key on disk ~7 days; roll back by re-pointing the symlink to `oldcert.pem` and `nginx -s reload`. No re-issue needed.
7. **Audit**: log the rotation event (old serial, new serial, expiry, operator, timestamp) to the SIEM / DefectDojo so renewals are traceable.

### What OCSP stapling buys you

OCSP stapling has the *server* periodically fetch a CA-signed "this cert is not revoked" proof and attach it to the TLS handshake, so the client doesn't have to call the CA's OCSP responder itself — that removes a handshake round-trip (latency) and a privacy leak (the CA no longer sees which client visits which site). It's mandatory in production because it makes revocation checking both fast and private, and it's the precondition for OCSP must-staple. It's **disabled here** (`ssl_stapling off`) because a self-signed lab cert has no issuer/OCSP responder URL to staple from — there is literally no CA to query, so stapling is a no-op (nginx would just warn "issuer certificate not found").

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used:** ModSecurity v3.0.16 (`ModSecurity-nginx v1.0.4`) via the `owasp/modsecurity-crs:4.25-nginx-alpine-lts` image.
- **OWASP CRS version:** **4.25.1** (CRS config version v4; 849 rules loaded).
- **Paranoia level:** 1 (blocking + detection), inbound anomaly threshold = 5, `SecRuleEngine On` (blocking, not DetectionOnly).
- **Why ModSecurity v3 over Coraza:** OWASP CRS ships first-class ModSec support and the CRS docs are richer for ModSec, so it's the lower-friction path; Coraza (Go reimplementation, ~70% parity in 2026) would also have worked. Chosen per the lab's recommendation (c).
- **Topology:** `client → waf (:8080) → nginx (:443, TLS 1.3 + headers) → juice (:3000)`. The base stack still exposes Nginx directly on `:443`, giving a clean no-WAF vs with-WAF A/B on the *same* backend.

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded: `q='%20OR%201=1--`)

### Before WAF (Nginx alone, `https://localhost`)

```
no-waf: HTTP 500
```
The request sails through the edge and reaches Juice Shop, which processes the injection and errors (500). The point: **nothing at the edge blocked it** — a benign search returns 200, this one reaches the app.

### After WAF (`http://localhost:8080`)

```
with-waf: HTTP 403
benign-through-waf (q=apple): HTTP 200
```
CRS blocks the SQLi with **403** *before* it reaches Nginx/Juice Shop, while a legitimate query still returns 200 (low false-positive at paranoia 1).

### Audit log excerpt (the rule that fired)

From `labs/lab11/results/waf-audit.txt` (JSON audit, `/var/log/modsec/audit.log`):

```json
{
  "request": "GET /rest/products/search?q='%20OR%201=1--",
  "response_http_code": 403,
  "is_interrupted": true,
  "messages": [
    {
      "ruleId": "942100",
      "message": "SQL Injection Attack Detected via libinjection",
      "matched": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
      "rulefile": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
      "severity": "2",
      "ver": "OWASP_CRS/4.25.1"
    },
    {
      "ruleId": "949110",
      "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
      "rulefile": "REQUEST-949-BLOCKING-EVALUATION.conf",
      "ver": "OWASP_CRS/4.25.1"
    }
  ]
}
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**
(detection). The block itself is issued by **949110** — **Inbound Anomaly Score Exceeded** — once
942100 pushes the anomaly score to the threshold (5).

### Tradeoff analysis

- **What the WAF buys you** that Lecture 5's SAST + DAST + the L7 Conftest gate didn't: those are all *build/deploy-time* gates — they inspect code and config before shipping. The WAF is a *runtime* control that inspects live attacker traffic and blocks payloads against the running app, including exploits in dependencies/routes SAST never modeled and zero-days that appear after deploy. It's virtual-patching for things already in production.
- **What it costs:** false positives at higher paranoia levels (paranoia 3–4 will flag legitimate traffic and need weeks of tuning), added latency + an extra hop/service to operate, and config/cert sprawl (another TLS front door, another log pipeline, another ruleset to keep current). CRS is genuinely a part-time tuning job.
- **When NOT to deploy a WAF:** in front of a service whose traffic you can't model cheaply (e.g. an API that legitimately carries SQL-like or markup-heavy payloads → constant false positives), or where the app is internal/low-risk and the ops overhead + latency outweigh the threat — there, `fail2ban` + tight input validation + the existing SAST/DAST gates are the better cost/benefit.
```
