# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf — SSL + header sections

```nginx
  # ── HTTP → HTTPS redirect ────────────────────────────────────────────
  server {
    listen 80;
    listen [::]:80;
    server_name _;

    return 308 https://$host$request_uri;
  }

  # ── HTTPS server ─────────────────────────────────────────────────────
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2  on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # TLS 1.3 only — eliminates all legacy handshake attack surface
    ssl_protocols             TLSv1.3;
    ssl_prefer_server_ciphers off;
    # TLS 1.3 cipher suites are not configurable via ssl_ciphers (OpenSSL manages them)
    ssl_ecdh_curve            X25519:secp384r1;
    ssl_session_cache         shared:SSL:10m;
    ssl_session_timeout       1d;
    ssl_session_tickets       off;

    # ── Six required security headers ──────────────────────────────────
    add_header Strict-Transport-Security    "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options       "nosniff" always;
    add_header X-Frame-Options              "DENY" always;
    add_header Referrer-Policy              "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy           "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only
                "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
  }
```

### A. HTTPS redirect proof

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Sat, 04 Jul 2026 14:11:27 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
```

### B. TLS 1.3 proof

```
Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
```

### C. Security headers proof (all 6 present)

```
HTTP/2 200 
server: nginx
date: Sat, 04 Jul 2026 14:11:27 GMT
content-type: text/html; charset=UTF-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
```

### What each header defends against (1 sentence each)

- **HSTS**: Forces all future browser connections to use HTTPS for 2 years, preventing protocol-downgrade and SSL-stripping attacks by a network-level adversary.
- **X-Content-Type-Options: nosniff**: Stops browsers from MIME-sniffing a response away from the declared Content-Type, blocking attacks where an attacker uploads a polyglot file (e.g., a PNG that is also valid JavaScript) that the browser would otherwise execute.
- **X-Frame-Options: DENY**: Prevents any site from embedding this page in an `<iframe>`, eliminating clickjacking attacks where the attacker overlays an invisible frame to steal clicks.
- **Referrer-Policy**: Limits the Referer header to origin-only when crossing origins, preventing sensitive URL paths (e.g., `/account/reset?token=…`) from leaking to third-party servers via HTTP Referer.
- **Permissions-Policy**: Explicitly revokes access to camera, microphone, and geolocation APIs for all origins, so even a successfully injected script cannot silently invoke sensitive browser features.
- **Content-Security-Policy-Report-Only**: Declares a content source allowlist and ships violations to a report endpoint without blocking (report-only mode), providing visibility into injection attempts and inline-script abuse while iteratively tightening the policy without breaking the app.

---

## Task 2: Production Posture

### Rate limit proof

60 concurrent POST requests to `/rest/user/login`:

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401       | 6               |
| 429       | 54              |

Rate limiting engaged immediately — 54/60 requests returned 429 (Too Many Requests). Only 6 burst slots + initial tokens passed before the zone was exhausted.

### Timeout enforced

```nginx
client_body_timeout     10s;
client_header_timeout   10s;
proxy_read_timeout      30s;
proxy_connect_timeout    5s;
send_timeout            10s;
```

Nginx closes connections that send partial headers after `client_header_timeout` (10s), protecting against Slowloris-style attacks. `proxy_read_timeout` ensures stalled upstream responses don't hold connections open indefinitely.

### Cipher hardening

```
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

TLS 1.3 with X25519 key exchange (forward secrecy per-session) and AES-256-GCM-SHA384 cipher (AEAD, no separate MAC negotiation). `ssl_session_tickets off` disables session ticket reuse, which would otherwise allow a compromised ticket key to retroactively decrypt recorded sessions.

### Cert rotation runbook (7 steps)

1. **Detect expiry**: Monitor cert expiry with `openssl s_client -connect host:443 </dev/null 2>/dev/null | openssl x509 -noout -enddate` and alert at 30-day and 7-day thresholds via a cron job or Prometheus `ssl_expiry_seconds` metric.
2. **Order new cert**: Request a replacement from the CA (Let's Encrypt: `certbot renew --dry-run` then `certbot renew`; internal CA: submit CSR via ACME or PKI portal) — keep the existing cert live throughout.
3. **Validate**: Verify the new cert chain with `openssl verify -CAfile ca-bundle.crt new.crt` and confirm it covers the correct SANs with `openssl x509 -noout -text -in new.crt | grep -A1 "Subject Alternative Name"`.
4. **Atomic swap**: Copy `new.crt` → `localhost.crt` and `new.key` → `localhost.key` (keep the old files as `.bak`), then reload Nginx without dropping connections: `nginx -s reload` (or `docker exec nginx nginx -s reload`).
5. **Verify**: Confirm the new cert is live with `openssl s_client -connect host:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate` and ensure browsers no longer show cert warnings.
6. **Rollback plan**: If the new cert causes errors (chain mismatch, wrong CN), restore from `.bak` files and `nginx -s reload` — downtime is limited to the reload window (~1 s).
7. **Audit**: Log the rotation event (old serial → new serial, timestamp, operator) to an immutable audit trail (SIEM or append-only S3 bucket) for compliance and post-incident forensics.

### What OCSP stapling buys you

OCSP stapling lets Nginx pre-fetch the CA's "this cert is still valid" response and attach it to the TLS handshake, saving the browser from making a separate real-time OCSP request that leaks browsing intent to the CA and adds 50–200 ms of latency. For a production CA-signed certificate this eliminates the privacy leak and removes the CA as a latency dependency for every new TLS session. For a self-signed lab certificate there is no CA to query, so `ssl_stapling on` is a no-op — the directive is commented out in this config and would only be enabled when a publicly-trusted cert is deployed.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used**: ModSecurity v3.0.16 via `owasp/modsecurity-crs:nginx-alpine` (nginx connector, not Coraza)
- **OWASP CRS version**: 4.28.0 (851 rules loaded)
- **Paranoia level**: 1
- **Mode**: `SecRuleEngine On` (blocking, not detection-only)
- **Stack**: WAF proxies directly to `juice:3000` and is exposed on host port 8080; Nginx (TLS hardened, Tasks 1+2) is on port 443

> Coraza is the modern Go-based rewrite of ModSecurity (~70% feature parity as of 2026). ModSecurity v3 was chosen here because the OWASP CRS documentation is richer and the `owasp/modsecurity-crs:nginx-alpine` image gives a batteries-included demo with minimal config.

### Attack payload sent

```
GET /rest/products/search?q=' OR 1=1-- (URL-encoded)
```

### Before WAF (Nginx alone)

```
no-waf: HTTP 500
```

*(Juice Shop backend received the SQL injection payload — returned 500 from its own error handler, not an Nginx block.)*

### After WAF

```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)

```
2026/07/04 14:12:48 [error] ModSecurity: Access denied with code 403 (phase 2).
  Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5')
  [file "REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"]
  [id "949110"]
  [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
  [ver "OWASP_CRS/4.28.0"] [tag "anomaly-evaluation"]
  [uri "/rest/products/search"]
  [request "GET /rest/products/search?q=%27%20OR%201%3D1-- HTTP/1.1"]
```

**Rule ID: 949110** — OWASP CRS rule: **Inbound Anomaly Score Exceeded** (accumulation rule).  
The SQL injection pattern `' OR 1=1--` first scored against rule **942100** (SQL Injection Attack: Common Injection Testing), accumulating an inbound anomaly score of 5. Rule 949110 then evaluated the total and blocked the request because it reached the paranoia-1 threshold.

### Tradeoff analysis (3 sentences)

**What the WAF buys**: SAST (Lab 5) found the SQL injection vulnerability at the source-code level and DAST sent synthetic attack traffic during testing, but both operate in the development pipeline — neither protects production traffic in real time; the WAF is the only control that inspects and blocks live attack payloads before they reach the vulnerable endpoint, buying time when a patch is not yet deployed or when a zero-day variant wasn't in the DAST wordlist.  
**What it costs**: At paranoia level 1 the false-positive rate is low but non-zero — legitimate requests with SQL-like tokens in search parameters (e.g., `search?q=select`) can be blocked, ops teams must continuously tune exclusions, the WAF config becomes a compliance artifact that needs its own change-management process, and adding a synchronous WAF in the request path increases p99 latency by 5–30 ms per hop.  
**When not to deploy**: A WAF in front of a gRPC or binary-framed API (e.g., Protobuf over HTTP/2) gives near-zero value because the CRS rules were written for HTTP/1.1 text payloads — you would only add latency, false positives, and ops burden without the blocking benefit; in those cases, input validation at the application layer and mTLS between services are the correct controls.
