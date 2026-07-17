# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
ssl_certificate     /etc/nginx/certs/localhost.crt;
ssl_certificate_key /etc/nginx/certs/localhost.key;
ssl_session_timeout 10m;
ssl_session_cache   shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers off;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```
### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 14:39:11 GMT
```
### B. TLS 1.3 proof
```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
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
### What each header defends against (1 sentence each)
HSTS: Prevents SSL-stripping attacks by forcing browsers to use HTTPS for the entire site.
X-Content-Type-Options: nosniff: Prevents MIME-sniffing attacks where browsers execute user-controlled files as scripts.
X-Frame-Options: DENY: Prevents clickjacking by blocking the site from being embedded in iframes.
Referrer-Policy: Limits how much referrer information is leaked to external sites when navigating away.
Permissions-Policy: Restricts browser APIs (camera, mic, geolocation) from being used by third-party scripts.
Content-Security-Policy: Defends against XSS by controlling which resources the browser is allowed to load.


## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced
```
HTTP/1.1 408 Request Timeout
```
### Cipher hardening
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```
### Cert rotation runbook (7 steps)
1. Detect expiry: Monitor cert expiry with a cron job or monitoring system that alerts at 30 days and pages at 7 days.
2. Order new cert: Use certbot or vendor portal to request a new certificate; for wildcards, use DNS-01 challenge.
3. Validate: Run openssl x509 -in newcert.pem -text and openssl verify -CAfile ca.pem newcert.pem to confirm chain validity.
4. Atomic swap: Use a symlink and reload Nginx with nginx -s reload for zero-downtime.
5. Verify in production: Check with curl -vk https://yoursite.com and run testssl.sh to confirm full posture.
6. Rollback plan: Keep the previous cert+key on disk for ~7 days; roll back by re-pointing the symlink.
7. Audit: Log the rotation event with cert serial + expiry to SIEM/DefectDojo.
### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
Why is OCSP stapling useful for production but not for a self-signed lab cert?

OCSP stapling allows the server to periodically query the CA's OCSP responder and attach the response to the TLS handshake, eliminating the client's need to contact the CA directly. This reduces latency and prevents a privacy leak (the CA doesn't see client connections). For a self-signed lab cert, OCSP stapling has no effect because there's no external CA to query, which is why it's safe to document without proving its behavior.