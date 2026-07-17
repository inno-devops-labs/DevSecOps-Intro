# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
server {
    listen 8443 ssl;
    http2 on;
    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Location: https://localhost:8443/
```

### B. TLS 1.3 proof
```
CONNECTED(00000003)
Certificate chain
 0 s:CN = localhost
```

### C. Security headers proof (all 6 present)
```
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
- HSTS: informs browsers that the host should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be upgraded to HTTPS
- X-Content-Type-Options: nosniff: prevents XSS-attacks where user-uploaded content is executed as an HTML document, even if the browser has specified that it should be treated as plain text. 
- X-Frame-Options: DENY: sites can use this to avoid clickjacking attacks and some cross-site leaks, by ensuring that their content is not embedded into other sites.
- Referrer-Policy: controls how much referrer information (sent with the Referer header) should be included with requests, preventing data leakage via URL.
- Permissions-Policy: disables browser features that could be abused by injected scripts.
- Content-Security-Policy: helps guard against cross-site scripting attacks.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced
```
(Connection closed by nginx — client_header_timeout triggered, no response sent)
```

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: `openssl x509 -enddate -noout -in file.pem`.
2. **Order new cert**: generate new key and CSR, submit to CA.
3. **Validate**: Check new cert with `openssl x509 -text -noout` and verify CN, SAN, expiry, chain
4. **Atomic swap**: Swap cert files on disk, reload nginx gracefully, active connections stay open.
5. **Verify**: Run curl to confirm HTTPS works, then check the new cert's expiry with openssl.
6. **Rollback plan**:  Keep old cert and key backup. If issues appeared, restore files and run `nginx -s reload`.
7. **Audit**: Log rotation date, new cert fingerprint, update CMDB/inventory.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
Why is OCSP stapling useful for production but not for a self-signed lab cert?

The OCSP stapling mechanism allows Nginx to obtain certificate revocation status information from a Certificate Authority (CA) and transmit it to clients directly during the TLS handshake. This enhances privacy and improves connection speed by eliminating unnecessary data exchange. Since contacting a CA is not required for self-signed certificates used in test environments, OCSP is not applicable in such cases - this information is provided solely for preparing the system for a production environment.

