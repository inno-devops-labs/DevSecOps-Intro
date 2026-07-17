# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 10 Jul 2026 21:36:55 GMT
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
date: Fri, 10 Jul 2026 21:36:55 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 10 Jul 2026 21:36:49 GMT
etag: W/"26af-19f4df63820"
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

### What each header defends against
- HSTS: Forces browsers to use HTTPS for a specified period, preventing SSL stripping attacks.
- X-Content-Type-Options: nosniff: Prevents the browser from MIME-sniffing a response away from the declared content-type, mitigating drive-by downloads.
- X-Frame-Options: DENY: Prevents the page from being rendered in an iframe, protecting against clickjacking.
- Referrer-Policy: Controls how much referrer information is passed during navigation, protecting user privacy.
- Permissions-Policy: Restricts the use of browser features (camera, microphone) to prevent unauthorized access.
- Content-Security-Policy: Defines which dynamic resources are allowed to load, mitigating XSS and data injection attacks.

---

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced
```
(Connection reset or timeout occurs when sending partial requests)
```

### Cipher hardening
```
Ciphersuite: TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate expiry via monitoring tools (e.g., Prometheus) or cron jobs using `openssl x509 -enddate`.
2. **Order new cert**: Generate a new CSR (Certificate Signing Request) and submit it to the CA.
3. **Validate**: Verify the new certificate's validity and chain using `openssl verify`.
4. **Atomic swap**: Update the certificate and key files in the proxy's configuration directory and reload Nginx using `nginx -s reload` to avoid downtime.
5. **Verify**: Use `openssl s_client` or an external tool (like SSL Labs) to confirm the new certificate is served.
6. **Rollback plan**: Keep the previous certificate and key as backups to quickly revert the symlink or file and reload Nginx if issues arise.
7. **Audit**: Log the rotation event and update the certificate inventory/tracking system.

### What OCSP stapling buys you
OCSP stapling improves privacy and performance by allowing the server to provide a signed, time-stamped proof of the certificate's validity, removing the need for the client to contact the CA's OCSP responder. It's not useful for self-signed lab certificates because there is no CA responder to provide the status.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (owasp/modsecurity-crs:nginx)
- OWASP CRS version: 3.3.10
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
[error] ... ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
...
{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.","ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"46","data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--" ...}}
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis
A WAF provides a generic security layer that can block common attack patterns (like SQLi and XSS) without requiring changes to the application code, acting as a "virtual patch". However, it introduces latency and the risk of false positives (blocking legitimate traffic), especially at higher paranoia levels. I would NOT deploy a WAF in front of a service where extreme low-latency is critical and the application is already strictly hardened and validated via rigorous SAST/DAST.
