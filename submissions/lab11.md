# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)
```nginx
  server {
    listen 80;
    listen [::]:80;
    server_name _;

    return 308 https://$host$request_uri;
  }

  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519:secp384r1;
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
    add_header Content-Security-Policy-Report-Only "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' https: data:; connect-src 'self' https:;" always;
```

### A. HTTPS redirect proof
```text
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

### B. TLS 1.3 proof
```text
Connecting to 127.0.0.1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof (all 6 present)
```text
HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' https: data:; connect-src 'self' https:;
```

### What each header defends against
- HSTS: forces browsers to keep using HTTPS and prevents downgrade / SSL stripping after first trusted visit.
- X-Content-Type-Options `nosniff`: stops browsers from MIME-sniffing content into executable types such as script.
- X-Frame-Options `DENY`: blocks clickjacking by preventing the site from being framed.
- Referrer-Policy: limits how much origin and path information is leaked to other sites via the `Referer` header.
- Permissions-Policy: disables sensitive browser features such as camera, microphone, and geolocation unless explicitly allowed.
- Content-Security-Policy: constrains what sources the browser may load active content from; using report-only here avoids breaking Juice Shop while still showing intended policy direction.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced
```text
Configured in nginx with:
client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_connect_timeout 5s;
```

### Cipher hardening
```text
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: monitor certificate expiration in inventory/alerting and trigger renewal before the warning threshold.
2. **Order new cert**: request a replacement certificate from the CA or ACME workflow for the same hostname set.
3. **Validate**: verify SANs, chain, private key match, and staging deployment before production swap.
4. **Atomic swap**: place the new cert/key beside the old pair and update the mounted files or symlink in one controlled step.
5. **Verify**: run `openssl s_client` and `curl -I` checks immediately after reload to confirm the new cert, protocol, and headers are live.
6. **Rollback plan**: keep the previous cert/key pair available so the proxy can be reloaded back to the last known-good state if validation fails.
7. **Audit**: record the rotation date, operator, cert serial/fingerprint, validation evidence, and any incident notes.

### What OCSP stapling buys you
OCSP stapling lets the server attach revocation proof during the TLS handshake so clients do not each need to contact the CA directly, which improves privacy and reduces latency. It is useful in production with publicly trusted certificates, but it does not help in this lab because the certificate is self-signed and has no CA-operated OCSP responder to query.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: `ModSecurity v3 / OWASP CRS docker image`
- OWASP CRS version: `4.25.1`
- Paranoia level: `1`

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)
```text
no-waf: HTTP 500
```

### After WAF
```text
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```text
GET /rest/products/search?q=%27%20OR%201=1-- HTTP/2.0

ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"] [severity "2"] [ver "OWASP_CRS/4.25.1"] [tag "attack-sqli"] [tag "paranoia-level/1"] [uri "/rest/products/search"]
ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [ver "OWASP_CRS/4.25.1"] [uri "/rest/products/search"]
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis
The WAF adds a runtime enforcement layer that can block generic exploit payloads even if SAST, DAST, or config policy did not prevent the vulnerable request path from reaching the service. The cost is operational complexity: more moving parts, more tuning work, and false-positive risk as paranoia levels increase. I would avoid deploying a WAF in front of very latency-sensitive or tightly controlled internal services if the rule-tuning overhead outweighs the actual attack-surface reduction.
