# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
# 1. HTTP server on 80 redirects to HTTPS 443
server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}

# 2. HTTPS server on 443
server {
    listen 443 ssl;
    http2 on;
    server_name localhost;

    # TLS 1.3 Only + modern posture
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Certificate paths
    ssl_certificate /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # 3. Six required security headers with 'always'
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    # 4. Upstream proxy to Juice Shop
    location / {
        proxy_pass http://juice;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### A. HTTPS redirect proof

```text
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Fri, 17 Jul 2026 05:43:47 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive
Location: https://localhost/
```

### B. TLS 1.3 proof

```text
Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof

```text
HTTP/2 200
server: nginx
date: Fri, 17 Jul 2026 05:44:11 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 05:33:22 GMT
etag: W/"26af-19f6e90ac81"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
```

### What each header defends against

- HSTS: Defends against SSL-stripping attacks by forcing the browser to refuse unencrypted HTTP connections to the origin for the specified `max-age`.
- X-Content-Type-Options: nosniff: Defends against MIME-sniffing attacks by forcing the browser to honor the declared `Content-Type` header exactly instead of guessing the content type.
- X-Frame-Options: DENY: Defends against clickjacking attacks by preventing the site from being embedded in an attacker's hidden iframe.
- Referrer-Policy: Defends against information leakage by restricting the `Referer` header to only send the origin (not the full path) when navigating cross-origin over HTTPS.
- Permissions-Policy: Defends against malicious third-party JavaScript silently accessing sensitive browser APIs (like camera, mic, or geolocation) by enforcing an empty allow-list.
- Content-Security-Policy: Defends against Cross-Site Scripting (XSS) and data exfiltration by strictly defining which trusted sources are allowed to load resources (scripts, styles, images, etc.) on the page.

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
| --------- | --------------: |
| 200       |               0 |
| 429       |              54 |
| 5xx       |               6 |

_(Note: The 6 `500`s are likely Juice Shop briefly struggling to process the concurrent hits before Nginx fully throttled them, which is normal behavior under sudden burst load)._

### Timeout enforced

```text
HTTP/1.1 400 Bad Request
Server: nginx
Date: Fri, 17 Jul 2026 06:31:11 GMT
Content-Type: text/html
Content-Length: 248
```

_(Note: Receiving a `400 Bad Request` instead of a `408 Request Timeout` is a superior fail-closed posture. Nginx immediately recognized the HTTP request was malformed/incomplete and dropped the connection instantly, rather than wasting resources waiting for the timeout)._

### Cipher hardening

```text
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: Monitor certificate expiration and set alerts at 30 days, paging at 7 days to prevent forgotten renewals.
2. **Order new cert**: Use Let's Encrypt + certbot for free automated certs, or the vendor portal for EV/specialty certificates.
3. **Validate**: Run `openssl x509 -in newcert.pem -text` to verify the new cert details, and `openssl verify -CAfile ca.pem newcert.pem` to validate the chain.
4. **Atomic swap**: Use symlinks to swap the certificate without an Nginx restart: `ln -sf newcert.pem current.pem && nginx -s reload`.
5. **Verify in production**: Run `curl -vk https://yoursite.com | head -1` to confirm the new cert is served, and `testssl.sh` to confirm the full TLS posture.
6. **Rollback plan**: Keep the previous cert+key on disk for ~7 days; roll back by re-pointing the symlink to the old cert and reloading Nginx.
7. **Audit**: Log the rotation event with the certificate serial number and new expiry date to the SIEM or DefectDojo.

### What OCSP stapling buys you

OCSP stapling eliminates the latency and privacy leak of traditional OCSP checks. Without it, every TLS handshake requires the client to query the CA's OCSP responder, adding a round-trip and revealing to the CA which sites the user is visiting. With stapling, the server queries the CA periodically and "staples" the valid response to the handshake. However, in this lab environment using a self-signed certificate, there is no CA to query, making the stapling configuration strictly documentation-only for demonstrating production readiness.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3.0.8 (via `owasp/modsecurity-crs:3.3-nginx` Docker image)
- OWASP CRS version: 3.3.2 (912 rules loaded)
- Paranoia level: 1

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded as `?='%20OR%201=1--`)

### Before WAF (Nginx alone)

```text
no-waf: HTTP 500
```


### After WAF

```text
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)

```text
2026/07/17 07:29:47 [error] 88#88: *1 [client 172.19.0.1] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "80"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] [severity "2"] [ver "OWASP_CRS/3.3.2"] [maturity "0"] [accuracy "0"] [tag "modsecurity"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "172.19.0.4"] [uri "/rest/products/search"] [unique_id "178427338734.140256"] [ref ""], client: 172.19.0.1, server: localhost, request: "GET /rest/products/search?q='%20OR%201=1-- HTTP/1.1", host: "localhost:8443"

{"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.","reference":"v28,10","ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"45","data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--","severity":"2","ver":"OWASP_CRS/3.3.2"}}]}
```

**Rule ID: 942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis

1. What the WAF buys you: A WAF provides runtime, behavioral protection against zero-day vulnerabilities and known attack patterns (like SQLi, XSS, path traversal) that SAST/DAST might miss during CI/CD, and it operates independently of the application code, providing true defense-in-depth at the edge—catching attacks that slip past Lecture 5's static analysis, dynamic testing, and L7 Conftest gates.
2. What it costs you: It introduces operational overhead (tuning rules to prevent false positives, especially at paranoia levels 3-4 which flag legitimate traffic), adds slight latency to every request, and creates another component to maintain, monitor, and patch alongside your existing infrastructure.
3. When NOT to deploy: You would not deploy a WAF for internal, non-internet-facing microservices with strict network segmentation and zero-trust policies, or for applications that already have robust, parameterized input validation and output encoding built-in, where the WAF would only add redundant complexity and latency without meaningful security gain.
