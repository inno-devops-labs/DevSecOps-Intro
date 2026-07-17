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
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 18:04:03 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: self-signed certificate
Negotiated TLS1.3 group: X25519MLKEM768
```

### C. Security headers proof (all 6 present)
```
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 17 Jul 2026 18:04:55 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Connection: keep-alive
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 17 Jul 2026 18:01:41 GMT
ETag: W/"26af-19f713dc3d7"
Vary: Accept-Encoding
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)
- HSTS: Prevents downgrade attacks and cookie hijacking by forcing the browser to only connect via HTTPS.
- X-Content-Type-Options: nosniff: Prevents MIME-sniffing vulnerabilities, ensuring the browser strictly adheres to the provided Content-Type header.
- X-Frame-Options: DENY: Defends against clickjacking attacks by preventing the page from being rendered within a frame or iframe.
- Referrer-Policy: Protects sensitive information in URLs from being leaked in the Referer header to cross-origin requests.
- Permissions-Policy: Restricts which web features and APIs (like camera or geolocation) can be used, limiting the attack surface.
- Content-Security-Policy: Mitigates Cross-Site Scripting (XSS) and data injection attacks by defining which dynamic resources are allowed to load.

## Task 2: Rate Limiting, Timeouts, Cipher Hardening, Cert Rotation

### nginx.conf (Rate Limit & Connection Limit sections)
```nginx
  # Rate limit zone for login
  limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
  limit_req_status 429;
  limit_conn_zone $binary_remote_addr zone=conn:10m;

  # Inside server { listen 443 ssl; ... }
  limit_conn conn 50;

  # Inside location = /rest/user/login { ... }
  limit_req zone=login burst=5 nodelay;
```

### Rate limit test proof (60 concurrent POSTs to login)
```
Count Name
----- ----
    3 500 
   57 429 
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate expiration using synthetic checks (e.g., Datadog, Prometheus Blackbox Exporter) alerting at 30 days before expiration.
2. **Order new cert**: Automatically generate a new CSR and request a signed certificate from the CA (e.g., using Certbot/ACME or internal Vault PKI).
3. **Validate**: Verify the new certificate chain and private key match (`openssl x509 -noout -modulus`) and that it has the correct SANs and dates.
4. **Atomic swap**: Deploy the new certificates to the server (e.g., `/etc/nginx/certs/`) without overwriting old ones immediately, then gracefully reload Nginx (`nginx -s reload`).
5. **Verify**: Run automated post-deployment checks (`openssl s_client -connect ...`) to confirm the server is presenting the new, valid certificate.
6. **Rollback plan**: Keep the previous certificate files available and have a script ready to revert the symlinks/paths and reload Nginx if the verification fails.
7. **Audit**: Log the successful rotation event to a centralized auditing system for compliance tracking and to close the initial expiry alert.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling improves privacy and performance by having the server fetch the certificate revocation status from the CA and "staple" it to the initial TLS handshake, rather than forcing every client to make a separate external network call to the CA. It is not useful for a self-signed lab cert because there is no external Certificate Authority to query for revocation status; the self-signed cert is inherently trusted (or untrusted) locally without an ongoing revocation infrastructure.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (owasp/modsecurity-crs:nginx-alpine)
- OWASP CRS version: v3.3.10 (as bundled in image)
- Paranoia level: 1

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
[error] 531#531: *1 [client 172.20.0.1] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
```
Rule ID: **949110** (and implicitly the underlying SQLi rules like **942100**) — OWASP CRS rule name: **Inbound Anomaly Score Exceeded**

### Tradeoff analysis (3 sentences)
Deploying a WAF with OWASP CRS provides real-time defense against zero-days and active exploitation attempts (like SQLi or XSS) that SAST/DAST might miss or can't patch immediately. However, it costs operational overhead, requires careful tuning to avoid false positives (especially at higher paranoia levels), and adds latency to requests. You would NOT deploy a WAF in front of internal microservices that only receive highly-trusted, authenticated traffic from within the cluster where the risk of injection is negligible and performance is paramount.
