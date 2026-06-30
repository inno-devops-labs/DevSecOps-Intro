# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
  # HTTP server (redirect to HTTPS)
  server {
    listen 8080;
    listen [::]:8080;
    server_name _;

    # Core headers (also on redirects)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    return 308 https://$host:8443$request_uri;
  }

  # HTTPS server
  server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.3;
    ssl_ciphers "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384";
    ssl_ecdh_curve X25519:secp384r1;
    ssl_prefer_server_ciphers on;
    ssl_stapling off;
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Tue, 30 Jun 2026 19:48:07 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
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
depth=0 CN = juice.local
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = juice.local
verify return:1
CONNECTED(00000006)
write W BLOCK
```

### C. Security headers proof (all 6 present)
```
HTTP/2 200 
server: nginx
date: Tue, 30 Jun 2026 19:48:07 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)
- HSTS: Forces the browser to strictly connect via HTTPS, mitigating man-in-the-middle downgrade attacks.
- X-Content-Type-Options: nosniff: Prevents the browser from MIME-sniffing the response away from the declared content-type, mitigating drive-by download attacks.
- X-Frame-Options: DENY: Prevents the site from being embedded in iframes on other domains, defending against clickjacking attacks.
- Referrer-Policy: Controls how much referrer information is passed to external sites, preventing leakage of sensitive URL tokens or parameters.
- Permissions-Policy: Restricts the application's ability to use powerful browser features like the camera or microphone, minimizing the impact of XSS.
- Content-Security-Policy: Enforces an allowlist of trusted domains from which scripts, styles, and images can be loaded, fundamentally mitigating Cross-Site Scripting (XSS).

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced
```
# Sent a partial HTTP request and waited 15 seconds; nginx forcefully closes the connection
```

### Cipher hardening
```
Server Temp Key: ECDH, X25519, 253 bits
New, TLSv1/SSLv3, Cipher is AEAD-AES256-GCM-SHA384
    Cipher    : AEAD-AES256-GCM-SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor the current certificate using an automated tool like Prometheus or Datadog, triggering an alert when it's < 30 days from expiration.
2. **Order new cert**: Generate a new CSR and private key, and request a fresh signed certificate from the CA (e.g., Let's Encrypt or an internal PKI).
3. **Validate**: Verify the newly received certificate chain using `openssl verify -CAfile` against the root CA to ensure it was properly signed and is cryptographically sound.
4. **Atomic swap**: Stage the new certificate alongside the old one in the file system and perform a zero-downtime hot reload of the reverse proxy (e.g., `nginx -s reload`).
5. **Verify**: Use an external testing tool (like `testssl.sh` or `openssl s_client`) to confirm the server is successfully serving the new certificate in production.
6. **Rollback plan**: If the new certificate is rejected or broken, immediately run a script to swap the symlinks back to the old certificate paths and execute a hot reload to restore service.
7. **Audit**: Log the successful rotation event in the centralized audit system (or Slack/Jira) and destroy the old private key securely to prevent future compromise.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling allows the web server (Nginx) to proactively fetch and cache the certificate revocation status from the CA, securely "stapling" it directly to the TLS handshake. This prevents clients from having to make a slow, privacy-leaking DNS/HTTP call to the CA to check if the cert was revoked. However, it requires a publicly trusted certificate signed by a real CA; for a self-signed lab certificate, there is no CA endpoint to query for revocation status, meaning stapling will simply fail.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (owasp/modsecurity-crs:nginx-alpine image)
- OWASP CRS version: 4.x
- Paranoia level: 1

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500
```
*(Juice Shop returns a 500 error because the SQL injection crashes the backend DB query, but Nginx happily proxies the attack).*

### After WAF
```
with-waf: HTTP 403
```
*(The WAF intercepts the SQL injection before it reaches Juice Shop and immediately returns a 403 Forbidden).*

### Audit log excerpt (the rule that fired)
```json
{
  "message":"SQL Injection Attack Detected via libinjection",
  "details":{
    "match":"detected SQLi using libinjection.",
    "reference":"v28,10",
    "ruleId":"942100",
    "file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "lineNumber":"46",
    "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
    "severity":"2",
    "ver":"OWASP_CRS/4.27.0"
  }
}
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)
Deploying a WAF with OWASP CRS gives us immediate, zero-code protection against zero-day exploits (like Log4Shell) and standard OWASP Top 10 attacks that might slip past our SAST/DAST pipeline or Conftest gates. However, it costs significant operational overhead: higher paranoia levels will inevitably block legitimate user traffic (False Positives), requiring constant tuning of rule exclusions and performance monitoring. You should NOT deploy a WAF in front of internal, highly-trusted backend-to-backend microservice communication where the performance penalty of deep packet inspection outweighs the negligible risk of inbound attacks.
