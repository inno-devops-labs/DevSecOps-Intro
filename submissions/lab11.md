# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name localhost;

    ssl_certificate /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # ssl_protocols TLSv1.3 only & ssl_prefer_server_ciphers off
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # 3. Six required headers, all with the `always` keyword
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
```

### A. HTTPS redirect proof
```
HTTP/1.1 301 Moved Permanently
Server: nginx/1.30.3
Date: Thu, 09 Jul 2026 23:15:52 GMT
Content-Type: text/html
Content-Length: 169
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
```

### C. Security headers proof (all 6 present)
```
HTTP/1.1 200 OK
Server: nginx/1.30.3
Date: Thu, 09 Jul 2026 23:16:05 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Connection: keep-alive
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 09 Jul 2026 23:12:20 GMT
ETag: W/"26af-19f49274cfa"
Vary: Accept-Encoding
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
```

### What each header defends against (1 sentence each)
- HSTS: Forces browsers to interact with the site only over secure HTTPS connections, preventing downgrade attacks and cookie hijacking.
- X-Content-Type-Options: nosniff: Prevents the browser from trying to MIME-sniff the content type, mitigating drive-by download attacks and certain types of XSS.
- X-Frame-Options: DENY: Prevents the site from being rendered within an iframe, effectively protecting the application from clickjacking attacks.
- Referrer-Policy: Controls how much referrer information is passed to other sites, protecting user privacy and preventing accidental leakage of sensitive tokens in URLs.
- Permissions-Policy: Restricts the APIs and browser features (like the camera or geolocation) that the web application is allowed to access, reducing the overall attack surface.
- Content-Security-Policy: Mitigates Cross-Site Scripting (XSS) and data injection attacks by explicitly defining which dynamic resources and scripts are trusted to load and execute.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 58 |
| 5xx | 2 |
*(Note: The 500 errors occur because the allowed burst requests bypass the rate limit and reach Juice Shop's login endpoint as malformed GET requests).*

### Timeout enforced
```
(Empty output)
```
# Explanation: Sending plaintext HTTP to the HTTPS port causes Nginx to wait for a TLS ClientHello. After `client_header_timeout` (10s), Nginx silently drops the connection. `nc` exits with no output, proving the fail-closed timeout works.


### Cipher hardening
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Set up automated monitoring (e.g., Prometheus, Datadog, or a simple cron script using `openssl`) to alert the operations team 30 days before certificate expiration.
2. **Order new cert**: Generate a new Certificate Signing Request (CSR) and submit it to the Certificate Authority (CA), or use an automated ACME client like Certbot to fetch the new certificate.
3. **Validate**: Verify the new certificate matches the private key using `openssl x509 -noout -modulus` and ensure the CA chain of trust is intact.
4. **Atomic swap**: Place the new certificate and key files on the server alongside the old ones, update the Nginx configuration to point to the new files, test syntax with `nginx -t`, and perform a graceful reload using `nginx -s reload`.
5. **Verify**: Use an external tool like `testssl.sh` or `curl -vI` to confirm the server is actively presenting the new certificate with the updated expiration date.
6. **Rollback plan**: If validation fails or production issues occur, immediately revert the file paths in `nginx.conf` to the previous valid certificate and issue another `nginx -s reload`.
7. **Audit**: Log the rotation event in the security audit trail, update internal tracking dashboards, and mark the initial expiration monitoring alert as resolved.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling improves both performance and user privacy by having the web server proactively query the CA for revocation status and "staple" this signed response directly into the TLS handshake. This prevents the client's browser from having to make a separate, blocking HTTP request to the CA, which speeds up connection times and stops the CA from tracking which sites users are visiting. OCSP stapling requires a real Certificate Authority running an active OCSP responder URL to query; a self-signed lab certificate lacks a legitimate CA infrastructure, so there is no responder for Nginx to contact.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (via official `owasp/modsecurity-crs` Docker image)
- OWASP CRS version: 4.x
- Paranoia level: 1

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500
```
# Explanation: Nginx blindly proxied the SQLi payload to the backend. The Juice Shop database choked on the syntax, resulting in a 500 Internal Server Error.

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```
[client 172.18.0.1] ModSecurity: Warning. Pattern match "(?i)([\\'\\\"\\`\\´\\’\\‘]\\s*?(?:and|or|div|xor|between|like|rlike|regexp|is)\\s+[^\\s]+.*)" at ARGS:q. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack: Common Injection Testing"] [severity "CRITICAL"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "OWASP_CRS"]
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack: Common Injection Testing**

### Tradeoff analysis (3 sentences)
What does the WAF buy you? A WAF provides critical runtime defense ("virtual patching") that actively blocks malicious payloads and zero-day exploits in production, catching attacks that might have slipped past earlier SAST/DAST scans or logic tests.
What does it COST you? It introduces significant operational overhead (tuning rules to prevent False Positives that block legitimate users), increases request latency, and adds complexity to the infrastructure stack.
When would you NOT deploy a WAF? You would generally avoid putting a WAF in front of internal, backend-to-backend microservices secured by mutual TLS (where trust is already established), or on highly latency-sensitive data-streaming endpoints where the performance penalty outweighs the security benefit.
