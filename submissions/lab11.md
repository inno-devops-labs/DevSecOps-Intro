# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
# ...
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 10m;
    ssl_session_cache   shared:SSL:10m;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers off;
    ssl_stapling off;
# ...
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'" always;
# ...
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 18:20:14 GMT
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
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'
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
Server: nginx
Date: Fri, 17 Jul 2026 18:20:44 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Connection: keep-alive
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 17 Jul 2026 18:19:25 GMT
ETag: W/"26af-19f714e0056"
Vary: Accept-Encoding
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'
```

### What each header defends against (1 sentence each)
- HSTS: MitM attacks due to unencrypted connections over HTTP.
- X-Content-Type-Options: nosniff: MIME confusion attacks due to MIME‑type sniffing.
- X-Frame-Options: DENY: embedding the website into unauthorized malicious pages to steal data or manipulate user actions.
- Referrer-Policy: leaking any sensitive URL details to other origins.
- Permissions-Policy: getting access to browser features not used by the website.
- Content-Security-Policy: XSS and data injection attacks through resources loaded from other origins.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced
Instead of `nc`, I used `openssl`. The unexpected end of file is caused by nginx closing the connection due to timeout.
```
Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=juice.local
verify return:1
18600000:error:0A000126:SSL routines::unexpected eof while reading:../openssl-3.5.4/ssl/record/rec_layer_s3.c:696:

```

### Cipher hardening
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Cipher    : TLS_AES_256_GCM_SHA384
    Cipher    : TLS_AES_256_GCM_SHA384

```
Additionally, I ran `docker run --rm drwetter/testssl.sh --quiet --color 0 host.docker.internal:443 2>&1 | grep "TLS_AES_256_GCM_SHA384.*X25519" | head -1` which gave this result:
```
 Java 8u442 (OpenJDK)         TLSv1.3   TLS_AES_256_GCM_SHA384            253 bit ECDH (X25519)
```
**Conclusion:** The TLS 1.3 cipher `TLS_AES_256_GCM_SHA384` is negotiated, and the key exchange uses the X25519 elliptic curve (as confirmed by the `ECDH (X25519)` annotation).

### Cert rotation runbook (7 steps)

1. **Detect expiry**  
   Continuously monitor certificate expiration dates (e.g., `openssl x509 -enddate -noout -in cert.pem` or automated alerts). Alert at 30 days, page at 7 days before expiry.

2. **Order new cert**  
   Generate a new certificate signing request (CSR) and obtain a fresh certificate. Use Let's Encrypt + certbot (or an internal CA) to produce the new `fullchain.pem` and `privkey.pem`.

3. **Validate**  
   Inspect the new certificate (`openssl x509 -in newcert.pem -text`) and verify the chain (`openssl verify -CAfile ca.pem newcert.pem`). Ensure the CN/SANs, expiry, and key match expectations.

4. **Atomic swap**  
   Place the new certificate and key in a staging directory, then atomically replace the live files. Use a symlink swap (`ln -sf newcert.pem live/cert.pem`) or a rename operation, followed by a graceful reload (`nginx -s reload`).

5. **Verify**  
   Confirm the new certificate is served: `curl -vk https://yoursite.com | head -1` should show the new serial/expiry. Run `testssl.sh` for a full posture check. Test application functionality.

6. **Rollback plan**  
   Keep the previous certificate and key on disk for at least 7 days. If the new certificate causes issues, revert the symlink (or restore the old files) and reload Nginx. Document the rollback procedure.

7. **Audit**  
   Log the rotation event with the certificate serial number, expiry date, timestamp, and operator. Send the audit record to your SIEM or defect tracker for traceability.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)

OCSP stapling allows the server to periodically fetch the certificate's revocation status from the issuing CA and attach (“staple”) that signed response to the TLS handshake. This eliminates the extra client round-trip to the CA's OCSP responder, improving performance and preventing the CA from learning which sites each user visits (privacy). In a production environment with a publicly‑trusted certificate, stapling provides fast, privacy‑preserving revocation checking; for a self‑signed lab certificate there is no CA to respond to OCSP queries, so `ssl_stapling` has no effect (it's just documentation‑only).