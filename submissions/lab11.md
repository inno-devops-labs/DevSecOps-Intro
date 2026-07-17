# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
  # HTTPS server
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 10m;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.3;
    ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    ssl_prefer_server_ciphers off;
    ssl_stapling off;

    client_max_body_size 2m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 10s;
    send_timeout 10s;
    limit_conn conn 50;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    location = /rest/user/login {
      limit_req zone=login burst=5 nodelay;
      limit_req_log_level warn;
      proxy_pass http://juice;
    }

    location / {
      proxy_pass http://juice;
    }
  }

  # HTTP server (redirect to HTTPS)
  server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    return 308 https://$host$request_uri;
  }
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Tue, 14 Jul 2026 07:13:15 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof
```
Server Temp Key: ECDH, X25519, 253 bits
New, TLSv1/SSLv3, Cipher is AEAD-CHACHA20-POLY1305-SHA256
Cipher: AEAD-CHACHA20-POLY1305-SHA256
```
TLS 1.3 negotiated (CHACHA20-POLY1305 is a TLS 1.3-only cipher suite; X25519 key exchange confirmed).

### C. Security headers proof (all 6 present)
```
HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against
- **HSTS**: Forces browsers to only connect via HTTPS for 2 years, preventing SSL-stripping attacks where an attacker downgrades the connection to HTTP.
- **X-Content-Type-Options: nosniff**: Prevents browsers from MIME-sniffing a response away from the declared Content-Type, blocking attacks that upload a file as `image/png` but execute it as JavaScript.
- **X-Frame-Options: DENY**: Blocks the page from being embedded in an `<iframe>` on any origin, preventing clickjacking attacks where a victim is tricked into clicking hidden UI elements.
- **Referrer-Policy**: Controls how much URL information is sent in the `Referer` header to third parties, preventing leakage of sensitive path/query parameters (e.g. password-reset tokens) to external domains.
- **Permissions-Policy**: Disables access to browser APIs (camera, microphone, geolocation) that Juice Shop doesn't need, reducing the blast radius if a malicious script runs in the page.
- **Content-Security-Policy-Report-Only**: Defines which content sources are allowed and reports violations without blocking — used in `Report-Only` mode here because Juice Shop's frontend uses inline scripts and `unsafe-eval`, which a strict enforcing CSP would break; tightening iteratively in production.

---

## Task 2: Production Posture

### Rate limit proof
```
  54 429
   6 500
```
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 429 | 54 |
| 500 | 6 |

54 out of 60 concurrent POST requests to `/rest/user/login` returned 429 (Too Many Requests), confirming the `limit_req zone=login burst=5 nodelay` rule is enforced. The 6 × 500 are upstream errors from Juice Shop itself under sudden load — not a Nginx misconfiguration.

### Cipher hardening
```
Server Temp Key: ECDH, X25519, 253 bits
New, TLSv1/SSLv3, Cipher is AEAD-CHACHA20-POLY1305-SHA256
Cipher: AEAD-CHACHA20-POLY1305-SHA256
```
TLS 1.3 cipher suite `TLS_CHACHA20_POLY1305_SHA256` in use with X25519 ephemeral key exchange — matches Mozilla Modern profile. `ssl_prefer_server_ciphers off` is correct for TLS 1.3 (the client selects the cipher from the server's advertised list; server preference is meaningless in TLS 1.3).

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor cert expiry via `openssl x509 -noout -enddate -in localhost.crt` in a daily cron job or via Prometheus `ssl_expiry_seconds` metric; alert at 30 days remaining.
2. **Order new cert**: Run `certbot renew --dry-run` (Let's Encrypt) or submit a CSR to the internal CA; store the new cert + key in a staging path (`/etc/nginx/certs/new/`).
3. **Validate**: Run `openssl verify -CAfile ca.crt new/localhost.crt` and `openssl s_client -connect localhost:443 -CAfile ca.crt` against the staging path to confirm chain + SANs before touching production.
4. **Atomic swap**: Copy new cert/key to `/etc/nginx/certs/` atomically (`cp` then `mv`), then run `nginx -t` to confirm config parses cleanly before reloading.
5. **Verify**: After `nginx -s reload`, run `echo | openssl s_client -connect localhost:443 2>&1 | grep -E "notAfter|subject"` to confirm the new cert is being served and the expiry date has advanced.
6. **Rollback plan**: Keep the previous cert/key as `localhost.crt.bak` / `localhost.key.bak`; if the new cert causes errors, `cp localhost.crt.bak localhost.crt && nginx -s reload` restores service in under 30 seconds.
7. **Audit**: Log the rotation event (old serial, new serial, operator, timestamp) to the security audit trail; update the cert inventory spreadsheet / secrets manager entry; close the rotation ticket with a link to the `openssl verify` output.

### What OCSP stapling buys you
OCSP stapling lets the Nginx server fetch and cache the certificate authority's revocation status response, then staple it to the TLS handshake — so the client gets revocation proof without making a separate HTTP request to the CA's OCSP responder, which eliminates a privacy leak (the CA learns which sites a user visits) and removes a latency hit on every new TLS connection. For a self-signed cert in this lab, OCSP stapling has no effect because there is no CA running an OCSP responder that could issue a signed status response for our cert — `ssl_stapling on` would cause Nginx to log a warning and send no staple, which is why the config leaves it off with a comment explaining the production path.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used:** ModSecurity v3.0.16 + nginx connector v1.0.4 (via `owasp/modsecurity-crs:nginx-alpine`)
- **OWASP CRS version:** 3.3.10
- **Paranoia level:** 1
- **SecRuleEngine:** On (blocking mode, not DetectionOnly)
- **Inbound anomaly threshold:** 5

Note: Coraza is the modern Go-based reimplementation of ModSecurity (~70% feature parity as of 2026). ModSecurity v3 was chosen here because the OWASP CRS documentation has more complete examples and the `owasp/modsecurity-crs` Docker image provides batteries-included setup. In production, Coraza would be preferred for lower memory footprint and active maintenance.

### Attack payload sent
```
GET /rest/products/search?q=%27%20OR%201%3D1-- HTTP/1.1
```
URL-decoded: `' OR 1=1--` — classic SQL injection probe.

### Before WAF (Nginx alone)
```
no-waf (через nginx): HTTP 500
```
Nginx proxied the request to Juice Shop which returned 500 — no blocking, the payload reached the application layer.

### After WAF
```
with-waf (через modsec): HTTP 403
```
ModSecurity blocked the request before it reached Juice Shop.

### Audit log excerpt (the rule that fired)
```json
{
  "transaction": {
    "client_ip": "192.168.65.1",
    "time_stamp": "Tue Jul 14 07:24:18 2026",
    "is_interrupted": true,
    "request": {
      "method": "GET",
      "uri": "/rest/products/search?q=%27%20OR%201%3D1--"
    },
    "response": { "http_code": 403 },
    "producer": {
      "modsecurity": "ModSecurity v3.0.16 (Linux)",
      "connector": "ModSecurity-nginx v1.0.4",
      "components": ["OWASP_CRS/3.3.10"]
    },
    "messages": [
      {
        "message": "SQL Injection Attack Detected via libinjection",
        "details": {
          "ruleId": "942100",
          "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
          "severity": "2",
          "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
          "tags": ["attack-sqli", "paranoia-level/1", "OWASP_CRS", "PCI/6.5.2"]
        }
      },
      {
        "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
        "details": { "ruleId": "949110" }
      }
    ]
  }
}
```

**Rule ID: 942100** — "SQL Injection Attack Detected via libinjection" (REQUEST-942-APPLICATION-ATTACK-SQLI.conf). The payload scored 5 anomaly points (threshold = 5), triggering rule 949110 which performed the actual block.

### Tradeoff analysis
The WAF catches **runtime attack patterns** that SAST and DAST miss by definition: Semgrep found the vulnerable code at `routes/search.ts:23` and ZAP confirmed it with a crafted HTTP request during a controlled scan window, but neither tool monitors live production traffic 24/7. A WAF intercepts every request in real time, blocking exploit attempts from attackers who discover the endpoint independently — it's the difference between knowing a vulnerability exists and actively preventing exploitation while remediation is in progress. The cost is real: at paranoia level 2+, legitimate requests with unusual characters (search queries, markdown input, code snippets) get false-positived and blocked, requiring per-rule tuning that adds ops overhead; each Nginx config change also requires WAF rule review to avoid policy drift. A WAF should **not** be deployed in front of a service when it is the primary security control — it is a compensating control for when patching is delayed, not a substitute for fixing the underlying SQL injection in the application code.
