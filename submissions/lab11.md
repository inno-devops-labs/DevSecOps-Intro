# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
  # HTTP server (redirect to HTTPS)
  server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Core headers (also on redirects)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    return 308 https://$host$request_uri;
  }

  # HTTPS server TLS 1.3 only
  server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 10m;
    ssl_session_cache   shared:SSL:10m;

    # TLS 1.3 ONLY
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 2m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 10s;
    send_timeout 10s;

    # Security header (always)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    # Rate-limited login
    location = /rest/user/login {
      limit_req zone=login burst=5 nodelay;
      limit_req_log_level warn;
      proxy_pass http://juice;
    }
    
    # Everything else
    location / {
      proxy_pass http://juice;
    }
  }
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Tue, 30 Jun 2026 09:47:32 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';

```

### B. TLS 1.3 proof
```
openssl : Connecting to ::1
строка:1 знак:11
+ echo "" | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 ...
+           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (Connecting to ::1:String) [], Remote 
   Exception
    + FullyQualifiedErrorId : NativeCommandError
 
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
Date: Tue, 30 Jun 2026 09:48:06 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Connection: keep-alive
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 30 Jun 2026 09:46:07 GMT
ETag: W/"26af-19f17ebf39c"
Vary: Accept-Encoding
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';


```

### What each header defends against (1 sentence each)
- HSTS: Forces browsers to always use HTTPS for the domain, preventing SSL stripping and man-in-the-middle downgrade attacks.
- X-Content-Type-Options: nosniff: Prevents the browser from MIME-sniffing a response away from the declared Content-Type, stopping drive-by download and XSS attacks via maliciously crafted files.
- X-Frame-Options: DENY: Protects against clickjacking and UI redressing attacks by preventing the page from being embedded in an iframe on any other domain.
- Referrer-Policy: Controls how much referrer information is sent with cross-origin requests, preventing leakage of sensitive URL parameters to third-party sites.
- Permissions-Policy: Disables access to sensitive browser features (camera, microphone, geolocation) for the page, reducing the attack surface for XSS and device-based privacy risks.
- Content-Security-Policy: Prevents XSS, data injection, and code execution attacks by restricting which sources the browser is allowed to load and execute on the page.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 |               0 |
| 429 |              54 |
| 5xx |               6 |

### Timeout enforced
```
connection closed by nginx
```

### Cipher hardening
```
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Cipher    : TLS_AES_256_GCM_SHA384
    Cipher    : TLS_AES_256_GCM_SHA384



```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate expiry daily with `openssl x509 -enddate -noout -in /etc/nginx/certs/localhost.crt`, alert at 30 days and page at 7 days.
2. **Order new cert**: Generate a new certificate using `openssl req -x509 -nodes -newkey rsa:4096 -keyout localhost.key.new -out localhost.crt.new -subj "/CN=juice.local" -days 3650`.
3. **Validate**: `openssl verify -CAfile ca.pem localhost.crt.new` and confirm the key matches using openssl `x509 -noout -modulus -in localhost.crt.new | openssl md5` vs `openssl rsa -noout -modulus -in localhost.key.new | openssl md5`.
4. **Atomic swap**: Replace the old certificate with the new one using symlinks `ln -sf localhost.crt.new localhost.crt && ln -sf localhost.key.new localhost.key` and reload Nginx with nginx -s reload.
5. **Verify**: Confirm the new certificate is served using `openssl s_client -connect localhost:443 -showcerts < /dev/null` and check that all security headers are still present with `curl -skI https://localhost`.
6. **Rollback plan**: Keep the previous certificate and key as *.old for 7 days and roll back by copying them back `cp localhost.crt.old localhost.crt && cp localhost.key.old localhost.key` and reloading Nginx.
7. **Audit**: Log the rotation event with timestamp, operator name, certificate serial number, and expiry date to logs/cert-rotation.log or SIEM/DefectDojo.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
Why is OCSP stapling useful for production but not for a self-signed lab cert?

OCSP stapling allows the web server to pre-fetch and cache the certificate revocation status from the CA, then staple it into the TLS handshake so the client doesn't have to contact the CA themselves, which improves privacy and reduces latency. For a self-signed certificate, there is no external Certificate Authority to query for revocation status, so OCSP stapling has no effect and cannot be used because the server is its own CA and does not provide an OCSP responder.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (via `owasp/modsecurity-crs:nginx` image
- OWASP CRS version: 4.7.0
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
{"transaction":{"client_ip":"172.21.0.1",
"time_stamp":"Tue Jun 30 13:16:00 2026",
"server_id":"7ff7216cca51e9a139d6085d343e7b4b81a71b75",
"client_port":36760,"host_ip":"172.21.0.3",
"host_port":8443,"unique_id":"178282536033.401684",
"is_interrupted":true,"request":{"method":"GET","http_version":"1.1",
"hostname":"localhost","uri":"/rest/products/search?q='%20O
R%201=1--",
"headers":{"Host":"localhost:8443","User-Agent":"curl/8.19.0","Accept":"*/*"}},
"response":{"body":"<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<cen
ter><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
"http_code":403,"headers":{"Server":"nginx\u0000","Date":"Tue, 30 Jun 2026 13:16:00 GM
T","Content-Length":"146","Content-Type":"text/html","Access-Control-Allow-Origin":"*",
"Connection":"keep-alive","Access-Control-Max-Age":"3600","Access-Control-Allow-Methods":"GE
T, POST, PUT, DELETE, OPTIONS","Access-Control-Allow-Headers":"*"}},"producer":{"modsecurity":"ModSecurity v3.0.16 (Linux)",
"connector":"ModSecurity-nginx v1.0.4","secrules_engine
":"Enabled","components":["OWASP_CRS/4.25.0\""]},
"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.",
"reference":"v28,10",
"ruleId":"942100",
"file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"46","data":"Matched Data: s&1c found within 
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)
What does the WAF buy you that Lecture 5's SAST + DAST + the L7 Conftest gate didn't already?
What does it COST you? (FP risk at higher paranoia levels; ops overhead; cert/config sprawl.)
When would you NOT deploy a WAF in front of a service?

WAF buys runtime protection - it blocks attacksin real time, which SAST/DAST/Conftest can't do because they operate before deployment and can't prevent a live attack against a running app. The cost is increased false positives (especially at higher paranoia levels), operational overhead and added latency. Don't deploy a WAF if the service is internal-only, has extremely low latency requirements, or is already protected by an upstream gateway/firewall that provides equivalent L7 inspection, making the extra complexity unnecessary.