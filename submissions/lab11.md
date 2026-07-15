# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
        listen 443 ssl;
        http2 on;
        server_name juice.local localhost;

        ssl_certificate     /etc/nginx/certs/localhost.crt;
        ssl_certificate_key /etc/nginx/certs/localhost.key;

        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; report-uri /csp-report" always;
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Wed, 15 Jul 2026 10:58:22 GMT
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
HTTP/2 200 
server: nginx
date: Wed, 15 Jul 2026 10:58:45 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Wed, 15 Jul 2026 10:48:12 GMT
etag: W/"26af-19f65642df6"
vary: Accept-Encoding
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against
- **HSTS**: forces the browser to only ever speak HTTPS to this host for the given max-age, closing the window an attacker has to strip TLS on a downgrade/sslstrip attempt.
- **X-Content-Type-Options: nosniff**: stops the browser from guessing ("sniffing") a different MIME type than the one declared, which blocks attacks that smuggle a script inside a file served as e.g. an image.
- **X-Frame-Options: DENY**: prevents the page from being rendered inside an `<iframe>` on another site, killing clickjacking overlays.
- **Referrer-Policy: strict-origin-when-cross-origin**: keeps the full URL (which can contain tokens or query params) from leaking to third-party sites via the Referer header on cross-origin navigation.
- **Permissions-Policy**: explicitly disables browser features (camera, mic, geolocation) the app doesn't use, shrinking the attack surface if a script is ever injected.
- **Content-Security-Policy**: restricts which origins scripts/styles/images/connections can load from, so even a successful injection (XSS) has nowhere off-origin to execute or exfiltrate to.

---

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

401 — requests that passed the rate limiter and reached Juice Shop; the service responded "invalid password" (expected, since fake credentials `test@test.com` / `wrong` were used).
429 — requests rejected by nginx via the `limit_req zone=login burst=5 nodelay;` directive before they ever reached the backend.


### Timeout enforced
```
Server responded: b''
Elapsed: 10.02s
```

### Cipher hardening
```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: monitor cert `notAfter` on a schedule (`openssl x509 -enddate -noout -in localhost.crt`) or via a monitoring probe (e.g. Prometheus blackbox exporter `probe_ssl_earliest_cert_expiry`); alert at 30/14/3 days out.
2. **Order new cert**: request a new cert from the CA (Let's Encrypt/ACME in prod, or re-run the `openssl req -x509` self-signed command in this lab) using the same CN/SANs as the one being replaced.
3. **Validate**: confirm the new cert's chain, SAN list, and expiry with `openssl x509 -noout -text -in new.crt`, and check the private key matches (`openssl x509 -noout -modulus | md5sum` vs `openssl rsa -noout -modulus | md5sum`).
4. **Atomic swap**: write the new `.crt`/`.key` to a staging path, then `mv` (atomic rename) them over the live `certs/localhost.crt` and `.key` so nginx never reads a half-written file; follow with `nginx -s reload` (not a full restart) to avoid dropping connections.
5. **Verify**: re-run the TLS proof commands (`openssl s_client -connect ... -tls1_3`) against the running server to confirm the new cert (check serial number/expiry) is actually being served.
6. **Rollback plan**: keep the previous cert/key pair backed up until the new one is verified in production; if the swap breaks TLS, `mv` the old files back and reload nginx immediately.
7. **Audit**: log the rotation event (who/when/old serial/new serial) to the change log or SIEM, so cert history is reconstructable during an incident.

### What OCSP stapling buys you
OCSP stapling lets the server fetch the CA's revocation status once and attach ("staple") it to the TLS handshake, so clients don't have to make their own OCSP call to the CA — this is faster and avoids leaking the visitor's browsing to the CA. It's meaningless here because a self-signed cert has no CA to query for revocation status in the first place; in production, with a cert from a real CA, stapling matters because it's what actually lets clients detect a revoked cert without a slow (and privacy-leaking) live OCSP round trip.

