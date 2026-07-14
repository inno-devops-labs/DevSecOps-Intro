# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
  server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 308 https://$host$request_uri;
  }

  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_protocols       TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    location / {
      proxy_pass http://juice;
    }
  }
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx/1.30.3
Date: Tue, 14 Jul 2026 14:17:53 GMT
Content-Type: text/html
Content-Length: 171
Connection: keep-alive
Location: https://localhost/
```

### B. TLS 1.3 proof
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof (all 6 present)
```
HTTP/1.1 200 OK
Server: nginx/1.30.3
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)
- HSTS: Tells the browser to always use HTTPS for this site.
- X-Content-Type-Options: nosniff: Stops the browser from guessing file types and running them as scripts.
- X-Frame-Options: DENY: Blocks other sites from putting this page in an iframe (clickjacking).
- Referrer-Policy: Limits how much URL info is sent to other sites in the Referer header.
- Permissions-Policy: Blocks camera, microphone, and geolocation access in the browser.
- Content-Security-Policy: Limits what scripts and resources the page can load (report-only here, so it logs but does not block).

---

## Task 2: Production Posture

### nginx.conf — rate limits, timeouts, and TLS hardening
```nginx
  limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
  limit_conn_zone $binary_remote_addr zone=conn:10m;
  limit_req_status 429;
  client_body_timeout 10s;
  client_header_timeout 10s;
  proxy_read_timeout 30s;
  proxy_connect_timeout 5s;

  ssl_ecdh_curve X25519:secp384r1;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 8.8.8.8 1.1.1.1 valid=300s;
  limit_conn conn 50;

  location = /rest/user/login {
    limit_req zone=login burst=5 nodelay;
    proxy_pass http://juice;
  }
```

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced
```
(no response - connection closed by server)
```

### Cipher hardening
```
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Cipher    : TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Set alerts when the cert is 30 days from expiring (page at 7 days).
2. **Order new cert**: Renew with certbot/Let's Encrypt or your CA.
3. **Validate**: Check the new cert with `openssl x509 -in newcert.pem -text`.
4. **Atomic swap**: Point a symlink to the new cert/key and run `nginx -s reload`.
5. **Verify**: Confirm the live site serves the new cert with `curl -vk`.
6. **Rollback plan**: Keep the old cert for ~7 days; swap the symlink back if something breaks.
7. **Audit**: Log who rotated what, cert serial, and new expiry date.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
The server attaches cert revocation status to the TLS handshake, so the client does not query the CA separately. That is faster and the CA does not see every visitor. With our self-signed lab cert there is no CA OCSP to staple, so it only documents prod practice.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (`owasp/modsecurity-crs:nginx-alpine` sidecar)
- OWASP CRS version: 3.3.10 (bundled in the image)
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
"ruleId":"942100"
"message":"SQL Injection Attack Detected via libinjection"
"data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--"
"ruleId":"949110"
"message":"Inbound Anomaly Score Exceeded (Total Score: 5)"
```
Rule ID: **942100** - OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)
A WAF blocks bad requests at runtime; SAST/DAST and Conftest only check code and config before deploy. The downside is tuning effort, false positives, and extra ops. Skip a WAF for simple internal services or when a CDN WAF already covers you.
