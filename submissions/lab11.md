# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
# HTTP → HTTPS redirect
server {
  listen 80;
  listen [::]:80;
  server_name _;
  return 308 https://$host$request_uri;
}

# HTTPS / TLS + security headers
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name _;

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;
  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

  location / {
    proxy_pass http://juice;
  }
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 13:22:54 GMT
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
Can't use SSL_get_servername
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
```

### C. Security headers proof (all 6 present)
```
HTTP/2 200 
server: nginx
date: Fri, 17 Jul 2026 13:27:51 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 13:22:04 GMT
etag: W/"26af-19f703dc76a"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)
- HSTS: Forces browsers to use HTTPS for this host (and subdomains) for two years, blocking SSL-stripping downgrade attacks after the first successful visit.
- X-Content-Type-Options: nosniff: Stops browsers from MIME-sniffing responses into a different type, which can turn a downloaded file into executable script.
- X-Frame-Options: DENY: Blocks embedding this site in an iframe, which cuts off classic clickjacking overlays.
- Referrer-Policy: Limits how much of the URL is sent in the Referer header on cross-origin navigations, reducing accidental leakage of path/query data.
- Permissions-Policy: Disables camera, microphone, and geolocation APIs for this origin so a compromised page cannot quietly access those sensors.
- Content-Security-Policy: Report-Only mode records (without breaking Juice Shop) which scripts/styles/images would violate a strict policy so we can tighten CSP iteratively without breaking the UI.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced
```
(empty output — `echo "GET / HTTP/1.0" | timeout 15 nc localhost 443` produced no HTTP response body;
Nginx closed the non-TLS/partial connection under client_header_timeout / TLS fail-closed posture)
```

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate NotAfter (Prometheus/`openssl x509 -enddate` checks); alert at 30 days remaining and page at 7 days so renewals are never a surprise outage.
2. **Order new cert**: Renew via Let's Encrypt + certbot (or ACME client) for public hosts; use the org CA/vendor portal for internal or EV certificates.
3. **Validate**: Inspect the new leaf with `openssl x509 -in new.crt -noout -text` and verify the chain with `openssl verify -CAfile ca-bundle.crt new.crt` before touching production paths.
4. **Atomic swap**: Stage new cert+key beside the live files, then flip a symlink (`ln -sfn new.crt current.crt`) and `nginx -s reload` so the swap is atomic and does not require a full container recreate.
5. **Verify**: Confirm the live handshake presents the new serial (`echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -serial -dates`) and spot-check posture with `curl -skI https://host` / optional `testssl.sh`.
6. **Rollback plan**: Keep the previous cert+key on disk for ~7 days; re-point the symlink to the old pair and reload Nginx if the new cert misbehaves.
7. **Audit**: Record rotation time, cert serial, issuer, and expiry in the change log / SIEM (and DefectDojo if that is the course inventory) so audits can prove controlled renewals.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling lets the server fetch and attach a recent CA revocation response during the TLS handshake, so clients do not need a separate round-trip to the CA's OCSP responder (lower latency and less privacy leakage to the CA). Reading 11 also notes the must-staple foot-gun: if stapling fails on a must-staple cert, browsers refuse the connection. On this lab's self-signed `localhost` cert there is no public CA OCSP responder to query, so enabling `ssl_stapling` would have no useful effect — it is a production control for publicly trusted certificates, not for this playground cert.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (via `owasp/modsecurity-crs:nginx`; lab option c — richer CRS docs than Coraza for this exercise)
- OWASP CRS version: 4.28.0
- Paranoia level: 1
- Engine: `SecRuleEngine On` (blocking, not DetectionOnly)
- Audit log path in container: `/var/log/modsecurity/audit/audit.log` (writable by the nginx user; parent dir is root-owned)

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500
```

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```
"uri":"/rest/products/search?q='%20OR%201=1--"
"http_code":403
"components":["OWASP_CRS/4.28.0"]

messages:
- ruleId "942100"
  message: "SQL Injection Attack Detected via libinjection"
  data: "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"
  file: REQUEST-942-APPLICATION-ATTACK-SQLI.conf
  tags: attack-sqli, paranoia-level/1, OWASP_CRS/ATTACK-SQLI

- ruleId "949110"
  message: "Inbound Anomaly Score Exceeded (Total Score: 5)"
  file: REQUEST-949-BLOCKING-EVALUATION.conf
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**  
(Block decision enforced by **949110** — Inbound Anomaly Score Exceeded.)

### Tradeoff analysis (3 sentences)
A WAF buys runtime request inspection for attack classes (SQLi/XSS/path traversal) that Lecture 5's SAST/DAST and a CI Conftest gate never see on live traffic — here Nginx alone returned HTTP 500 while CRS blocked the same probe with 403. The cost is false-positive risk as paranoia rises, plus ops overhead for rule tuning, audit-log storage, and another TLS/config surface to keep patched. Skip a WAF when the service is internal-only with strong network policy and little attack surface, or when latency/budget cannot absorb another hop and you already terminate abuse controls elsewhere (API gateway / managed cloud WAF).
