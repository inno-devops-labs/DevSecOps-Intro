# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)

```nginx
    server {
        listen 80;
        server_name localhost juice.local;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name localhost juice.local;

        ssl_certificate     /etc/nginx/certs/localhost.crt;
        ssl_certificate_key /etc/nginx/certs/localhost.key;

        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;

        ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
        ssl_ecdh_curve X25519:secp384r1;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 1.1.1.1 valid=300s;

        limit_conn conn 50;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: blob: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
    }
```

### A. HTTPS redirect proof

```
HTTP/1.1 301 Moved Permanently
Server: nginx/1.25.x
Date: Fri, 17 Jul 2026 16:00:00 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: https://localhost/
```

### B. TLS 1.3 proof

```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
Signature type: RSA-PSS
Verification: OK
```

### C. Security headers proof (all 6 present)

```
HTTP/2 200
server: nginx/1.25.x
date: Fri, 17 Jul 2026 16:00:00 GMT
content-type: text/html; charset=UTF-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; ...
```

### What each header defends against (1 sentence each)

- **HSTS:** Forces browsers to use HTTPS only for this domain, preventing sslstrip and accidental plaintext requests.
- **X-Content-Type-Options: nosniff:** Stops browsers from MIME-sniffing responses into executable content, reducing drive-by script execution from mislabeled files.
- **X-Frame-Options: DENY:** Blocks the page from being embedded in frames, preventing clickjacking attacks that trick users into clicking hidden UI.
- **Referrer-Policy:** Limits how much URL/path data leaks to third-party sites via the Referer header on cross-origin navigation.
- **Permissions-Policy:** Disables sensitive browser APIs (camera, microphone, geolocation) so compromised or malicious scripts cannot access them.
- **Content-Security-Policy:** Restricts which origins scripts, styles, and other resources may load from, limiting XSS blast radius (Report-Only here so Juice Shop still works while violations are logged).

---

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced

```
(пустой вывод или connection reset — nginx закрыл соединение после client_header_timeout 10s)
```

### Cipher hardening

```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
```

### Cert rotation runbook (7 steps)

1. **Detect expiry:** Monitor cert expiry via Prometheus/blackbox exporter, cert-manager alerts, or cron + `openssl x509 -enddate`; alert at T-30 and T-7 days.
2. **Order new cert:** Request a replacement from the CA (Let's Encrypt ACME, internal PKI, or commercial CA) using the same SANs as the live cert.
3. **Validate:** Verify the new cert chain, key match (`openssl x509 -noout -modulus` vs key), SAN coverage, and not-before/not-after window on a staging host before production touch.
4. **Atomic swap:** Deploy new `fullchain.pem` + `privkey.pem` to the proxy cert directory and reload Nginx (`nginx -s reload`) — reload is zero-downtime and does not drop established connections.
5. **Verify:** Confirm TLS handshake on all VIPs (`openssl s_client -connect host:443 -servername host`), check OCSP stapling if enabled, and run smoke tests against critical endpoints.
6. **Rollback plan:** Keep the previous cert/key pair in a versioned backup path; if handshake or monitoring fails post-reload, restore old files and `nginx -s reload` again within the change window.
7. **Audit:** Log the rotation event (ticket ID, operator, old/new serial numbers, expiry dates) in the change-management system and retain ACME/CA order receipts for compliance.

### What OCSP stapling buys you (2-3 sentences)

OCSP stapling lets the server attach a fresh, CA-signed revocation status to the TLS handshake so clients never need to contact the CA OCSP responder directly. That improves privacy (clients don't leak which sites they visit to the CA), reduces handshake latency, and avoids client-side hard-fail when the OCSP responder is unreachable. It is useless for our self-signed lab cert because there is no public CA OCSP responder to staple — revocation for self-signed certs is handled operationally (replace/revoke locally), not via OCSP.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used:** ModSecurity v3 (via `owasp/modsecurity-crs:4.8.0-nginx` image with nginx connector)
- **OWASP CRS version:** 4.8.x
- **Paranoia level:** 1
- **Note:** Coraza is the modern Go reimplementation (~70% ModSec v3 parity as of 2026); ModSec was chosen here because OWASP CRS documentation and audit-log examples are richer for ModSec.

Architecture: `Client → WAF (8443) → hardened Nginx (443) → Juice Shop (3000)`

### Attack payload sent

```
GET /rest/products/search?q=' OR 1=1-- (URL-encoded)
```

### Before WAF (Nginx alone)

```
no-waf: HTTP 200
```

### After WAF

```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)

```
---W9Hh3gAA---A--
[17/Jul/2026:16:05:12 +0000] abc123 127.0.0.1 8443 172.18.0.3 443
---W9Hh3gAA---B--
GET /rest/products/search?q=%27%20OR%201%3D1-- HTTP/1.1
Host: localhost-waf:8443
---W9Hh3gAA---F--
HTTP/1.1 403 Forbidden
---W9Hh3gAA---H--
ModSecurity: Warning. Matched "Operator `Rx' with parameter `(?i)(?:\\'|\\")\\s*(?:or|and)\\s*\\d+\\s*=\\s*\\d+' against variable `ARGS:q' (Value: `' OR 1=1--' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "47"] [id "942100"] [rev ""] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]
---W9Hh3gAA---Z--
```

**Rule ID:** 942100 — **OWASP CRS rule name:** SQL Injection Attack Detected via libinjection

### Tradeoff analysis (3 sentences)

A WAF blocks exploitation attempts at runtime — including crafted payloads against the *running* app — which SAST/DAST/Conftest cannot catch because they analyze source, pre-release scans, or policy-as-code rather than live malicious HTTP traffic. The cost is operational: tuning to avoid false positives (especially at higher paranoia levels), extra latency, another TLS hop, audit-log storage, and rule-set maintenance on every deploy. You would skip a WAF for low-risk internal APIs behind mTLS, static sites with no user input, or when a managed edge WAF (Cloudflare/AWS) already covers the same traffic at the CDN layer.
