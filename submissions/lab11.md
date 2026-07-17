# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 10m;
    ssl_session_cache   shared:SSL:10m;
    ssl_protocols TLSv1.3;
    ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:EECDH+AESGCM:EDH+AESGCM";
    ssl_prefer_server_ciphers off;
    ssl_stapling off;
    # If using a publicly-trusted certificate, you may enable OCSP stapling:
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # resolver 1.1.1.1 8.8.8.8 valid=300s;
    # resolver_timeout 5s;
    # ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

    client_max_body_size 2m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 10s;
    send_timeout 10s;

    # Security headers (include HSTS here only)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self';" always;
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 17:39:00 GMT
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
```
HTTP/2 200 
server: nginx
date: Fri, 17 Jul 2026 17:40:01 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 17:38:10 GMT
etag: W/"26af-19f71283eba"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self';
```

### What each header defends against (1 sentence each)
- HSTS: prevent SSL-stripping, force to communicate through HTTPS.
- X-Content-Type-Options: nosniff: prevent MIME-sniffing.
- X-Frame-Options: DENY: prevent clickjacking.
- Referrer-Policy: Prevent full URLs from leaking to external origins.
- Permissions-Policy: disable access tp some features like camera and microphone, prevent from permission-based exploits.
- Content-Security-Policy: against XSS and data injection attacks, blocks untrusted scripts, styles, etc.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 500 | 6 |

### Timeout enforced
```

```

### Cipher hardening
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: set a daily cron job, checking the cert expiry date and send alert when the date is in less than 30 days.
2. **Order new cert**: generate a new private key and CSR, submit CSR to CA.
3. **Validate**: check chain with openssl verify, check domain name and that private and public keys match.
4. **Atomic swap**: place new cert and key to nginx cert folder, old files become nackup
5. **Verify**: reload nginx and test with a client.
6. **Rollback plan**: in case of something breaking revert to backup and reload nginx
7. **Audit**: record cert's number, isser, expiry and replacement date in changelog.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
Why is OCSP stapling useful for production but not for a self-signed lab cert?
