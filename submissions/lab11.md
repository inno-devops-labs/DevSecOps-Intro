# Lab 11 — BONUS — Submission

## Environment

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
Compose: Docker Compose version 5.1.4
OpenSSL: OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
Nginx: nginx:stable-alpine
Juice Shop: bkimminich/juice-shop:v20.0.0
WAF: owasp/modsecurity-crs:4.25-nginx-lts
```

## Task 1: TLS + Security Headers

### TLS configuration

```nginx
ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;
```

### Security headers

```nginx
add_header Strict-Transport-Security
        "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy
        "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```

### HTTP → HTTPS redirect

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 18:17:40 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### TLS 1.3 negotiation

```text
Connecting to ::1
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: self-signed certificate
Peer Temp Key: X25519, 253 bits
DONE
```

### Header evidence

```text
HTTP/2 200 
server: nginx
date: Fri, 17 Jul 2026 18:17:40 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
access-control-allow-origin: *
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 18:17:38 GMT
etag: W/"26af-19f714c605d"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Header rationale

- **HSTS:** forces future browser requests to HTTPS and reduces downgrade exposure.
- **X-Content-Type-Options:** prevents MIME-sniffing reinterpretation.
- **X-Frame-Options:** blocks framing and reduces clickjacking.
- **Referrer-Policy:** limits URL disclosure through the `Referer` header.
- **Permissions-Policy:** disables unused camera, microphone, and geolocation APIs.
- **CSP Report-Only:** measures policy violations before enforcement can break the app.

## Task 2: Production Posture

### Login rate limiting

| HTTP code | Count |
|---|---:|
| 200 | 0 |
| 400 | 0 |
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

```text
6 401
     54 429
```

### Slow/incomplete-header timeout

```text
elapsed_seconds=10.02
result=server closed or rejected incomplete headers
```

### Cipher and key exchange

```text
Connecting to ::1
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: self-signed certificate
Peer Temp Key: X25519, 253 bits
DONE
```

TLS 1.3 suites are configured through OpenSSL `Ciphersuites`; Nginx
`ssl_ciphers` applies to TLS 1.2 and earlier, which are disabled here.

### Seven-step certificate-rotation runbook

1. Monitor `notAfter` continuously; alert 30, 14, and 7 days before expiry.
2. Obtain the replacement certificate through ACME or the approved enterprise CA.
3. Validate SANs, chain, key match, permissions, expiry, and `nginx -t`.
4. Write versioned files and atomically switch symlinks.
5. Reload Nginx without terminating established connections.
6. Verify the served fingerprint, TLS protocol, headers, and application health.
7. Roll back symlinks and reload on failure; record approver, fingerprint, and next expiry.

### OCSP stapling

Public CA certificates can staple a signed OCSP response, reducing client-to-CA
requests while preserving revocation checks. The lab certificate is self-signed
and has no CA OCSP responder, so stapling is intentionally disabled rather than
claimed as functioning.

## Bonus: ModSecurity + OWASP CRS v4

- Image: `owasp/modsecurity-crs:4.25-nginx-lts`
- Blocking paranoia level: 1
- Audit log: `/var/log/modsec/audit.log`
- Probe: `GET /rest/products/search?q=' OR 1=1--`

### Same request without and with WAF

```text
no-waf: HTTP 500
with-waf: HTTP 403
```

### Audit evidence

```text
{"transaction":{"client_ip":"172.20.0.1","time_stamp":"Fri Jul 17 18:18:21 2026","server_id":"488eabffba1022f0d067be8e49e910dbda7cf1ed","client_port":58650,"host_ip":"172.20.0.4","host_port":8443,"unique_id":"178431230118.628678","is_interrupted":true,"request":{"method":"GET","http_version":"2.0","hostname":"localhost","uri":"/rest/products/search?q=%27%20OR%201%3D1--","headers":{"user-agent":"curl/8.20.0","accept":"*/*","host":"localhost:9443"}},"response":{"body":"<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n","http_code":403,"headers":{"Server":"nginx\u0000","Date":"Fri, 17 Jul 2026 18:18:21 GMT","Content-Length":"146","Content-Type":"text/html","Access-Control-Allow-Origin":"*","Connection":"close","Access-Control-Max-Age":"3600","Access-Control-Allow-Methods":"GET, POST, PUT, DELETE, OPTIONS","Access-Control-Allow-Headers":"*"}},"producer":{"modsecurity":"ModSecurity v3.0.16 (Linux)","connector":"ModSecurity-nginx v1.0.4","secrules_engine":"Enabled","components":["OWASP_CRS/4.25.1\""]},"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.","reference":"v28,10","ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"46","data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--","severity":"2","ver":"OWASP_CRS/4.25.1","rev":"","tags":["application-multi","language-multi","platform-multi","attack-sqli","paranoia-level/1","OWASP_CRS","OWASP_CRS/ATTACK-SQLI","capec/1000/152/248/66"],"maturity":"0","accuracy":"0"}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"match":"Matched \"Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )","reference":"","ruleId":"949110","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf","lineNumber":"222","data":"","severity":"0","ver":"OWASP_CRS/4.25.1","rev":"","tags":["modsecurity","anomaly-evaluation","OWASP_CRS"],"maturity":"0","accuracy":"0"}}]}}
```

Detected CRS rule ID: **942100**

### Trade-offs

The WAF supplies a runtime request-inspection layer and can temporarily block
known exploit patterns while application fixes are prepared. It also introduces
latency, false positives, tuning work, another patching surface, and operational
ownership. It is most justified for exposed legacy/high-value services and less
justified for low-risk internal services already isolated by stronger controls.

## Completion checklist

- [x] HTTP redirects to HTTPS.
- [x] TLS 1.3 is the only enabled protocol.
- [x] All six required headers are present with `always`.
- [x] Login throttling produces HTTP 429.
- [x] Connection and request timeouts are configured.
- [x] TLS 1.3 AEAD suites and X25519 are verified.
- [x] Certificate rotation and OCSP behavior are documented.
- [x] OWASP CRS v4 blocks the SQL-injection probe with HTTP 403.
- [x] Audit evidence contains a CRS SQLi rule.
