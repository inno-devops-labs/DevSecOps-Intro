# Lab 11 — BONUS — Submission

> Ports: host `8080`/`8443` map to nginx (80/443 already taken by another stack).
> WAF edge: `http://localhost:9080` (ModSecurity CRS sidecar).

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
  # HTTP → HTTPS redirect
  server {
    listen 8080;
    listen [::]:8080;
    server_name _;
    return 308 https://$host:8443$request_uri;
  }

  server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_ecdh_curve X25519:secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:" always;
    ...
  }
```

### A. HTTPS redirect proof

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Tue, 14 Jul 2026 15:06:22 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
```

### B. TLS 1.3 proof

```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Server Temp Key: X25519, 253 bits
DONE
```

### C. Security headers proof (all 6 present)

```
HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:
```

### What each header defends against (1 sentence each)
- HSTS: Forces browsers to use HTTPS for this host (and subdomains) for ~2 years, blocking SSL-stripping downgrades.
- X-Content-Type-Options: nosniff: Stops MIME sniffing so a crafted response cannot be reinterpreted as executable script/style.
- X-Frame-Options: DENY: Prevents the app from being embedded in iframes (clickjacking).
- Referrer-Policy: Limits cross-origin Referer leakage to same-origin-or-HTTPS downgrade-safe cases.
- Permissions-Policy: Disables camera/mic/geolocation APIs unless explicitly re-enabled, shrinking the browser feature attack surface.
- Content-Security-Policy: Report-Only CSP that monitors script/style/image sources without breaking Juice Shop’s inline scripts; tighten iteratively in production.

---

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

(60 concurrent POSTs to `/rest/user/login`; first burst allowed, then `limit_req` returns 429.)

### Timeout enforced

Slow partial ClientHello/header on TLS caused nginx to drop the connection after `client_header_timeout 10s` (OpenSSL saw unexpected EOF):

```
40A76DDBEB760000:error:0A000126:SSL routines:ssl3_read_n:unexpected eof while reading:../ssl/record/rec_layer_s3.c:316:
```

### Cipher hardening

```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor `openssl x509 -enddate -noout -in localhost.crt` / alerting when <30 days remain (or ACME remaining lifetime).
2. **Order new cert**: For prod, ACME/Let’s Encrypt (`certbot`/`acme.sh`); for this lab, regenerate self-signed with the same CN.
3. **Validate**: Check SAN/CN, chain, dates (`openssl verify` / `openssl x509 -text`) before install.
4. **Atomic swap**: Write new files to a temp path, then `mv` into `/etc/nginx/certs/` (atomic rename) so readers never see a partial write.
5. **Verify**: `nginx -t` then `nginx -s reload`; `openssl s_client -connect ...` confirms the new leaf serial.
6. **Rollback plan**: Keep the previous `.crt`/`.key` pair as `*.prev`; rename back + reload if handshake or clients break.
7. **Audit**: Log rotation time, operator, old/new serials, and verify access logs show successful TLS after cutover.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling lets the server present a fresh CA-signed revocation status during the handshake so clients need not query the CA OCSP endpoint themselves (privacy + latency). It only works with a publicly trusted certificate that has an OCSP responder URL in the AIA extension — a self-signed lab cert has neither, so stapling is documentation-only here. In production with Let’s Encrypt/public CAs, enabling `ssl_stapling` + a DNS resolver closes the “soft-fail ignore revocation” gap many browsers otherwise accept.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: **ModSecurity v3** (`owasp/modsecurity-crs:nginx-alpine`) — choice (c) from the lab (richer CRS docs than Coraza)
- OWASP CRS version: **3.3.10** (what the official image ships as of this run; config path v3)
- Paranoia level: **1**
- Edge: `http://localhost:9080` → Juice Shop; nginx-alone remains on `https://localhost:8443`

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500
```
(Nginx proxied the probe; Juice Shop returned an application error — **no WAF block**.)

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```
ModSecurity: Warning. detected SQLi using libinjection.
 [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]
 [id "942100"] [msg "SQL Injection Attack Detected via libinjection"]
 [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"]
 [ver "OWASP_CRS/3.3.10"] [tag "attack-sqli"] [tag "paranoia-level/1"]
ModSecurity: Access denied with code 403 (phase 2).
 [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection** (blocked via **949110** inbound anomaly score).

### Tradeoff analysis (3 sentences)
A WAF adds a runtime L7 filter for *unknown* request patterns (SQLi/XSS/path traversal) that SAST/DAST already found as *known* vulns and that CI Conftest gates never see in HTTP traffic. The cost is false positives (especially at higher paranoia), another cert/config surface to operate, and latency on every request. Skip a WAF for purely internal trusted-network services with tiny attack surface, or when a managed edge (Cloudflare/AWS WAF) already provides CRS-equivalent coverage.
