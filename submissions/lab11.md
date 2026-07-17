# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
# HTTP server headers and HTTPS redirect
server {
  listen 80;
  listen [::]:80;
  server_name _;

  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

  return 308 https://$host$request_uri;
}

# HTTPS SSL posture and required headers
ssl_certificate     /etc/nginx/certs/localhost.crt;
ssl_certificate_key /etc/nginx/certs/localhost.key;
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519:secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Wed, 08 Jul 2026 14:19:02 GMT
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
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

### B. TLS 1.3 proof
```
Connecting to 192.168.65.254
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
```

### C. Security headers proof (all 6 present)
```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 08 Jul 2026 14:19:02 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Connection: keep-alive
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 08 Jul 2026 14:16:26 GMT
ETag: W/"26af-19f42165095"
Vary: Accept-Encoding
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

### What each header defends against (1 sentence each)
- HSTS: Forces browsers to use HTTPS for the host and subdomains, reducing SSL-stripping downgrade risk after the first trusted response.
- X-Content-Type-Options: nosniff: Prevents browsers from MIME-sniffing a response into an executable type when the declared content type says otherwise.
- X-Frame-Options: DENY: Blocks framing of the site and reduces clickjacking risk.
- Referrer-Policy: Limits cross-origin referrer leakage to the origin only and suppresses referrers on HTTPS-to-HTTP downgrades.
- Permissions-Policy: Disables camera, microphone, and geolocation access unless explicitly re-enabled.
- Content-Security-Policy: Runs a report-only policy that records unsafe resource-loading patterns before enforcing a stricter XSS and data-exfiltration defense.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

Note: the first 6 requests reached Juice Shop but returned 5xx because the login request body was intentionally empty; the remaining 54 requests were blocked by Nginx rate limiting with HTTP 429.

### Timeout enforced
```
Connecting to 192.168.65.254
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=juice.local
verify return:1
289B592F80750000:error:0A000126:SSL routines::unexpected eof while reading:ssl/record/rec_layer_s3.c:698:
```

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
Cipher: TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate expiry continuously, alert at 30 days, and page at 7 days.
2. **Order new cert**: Renew through Let's Encrypt/certbot or the production CA used for the service.
3. **Validate**: Inspect the new certificate and chain with `openssl x509 -in newcert.pem -text` and `openssl verify -CAfile ca.pem newcert.pem`.
4. **Atomic swap**: Place the new cert/key beside the old pair, switch the active symlink atomically, then run `nginx -s reload`.
5. **Verify**: Confirm the served certificate and TLS posture with `curl -vk https://service.example` and `testssl.sh`.
6. **Rollback plan**: Keep the previous cert/key for at least 7 days and roll back by repointing the active symlink and reloading Nginx.
7. **Audit**: Record the rotation time, operator, certificate serial, issuer, and new expiry in the security log or SIEM.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling lets the server fetch revocation status from the CA and staple it into the TLS handshake, which removes a client-side OCSP lookup, reduces latency, and avoids leaking client browsing activity to the CA. Reading 11 notes that this matters for publicly trusted production certificates, but it does not help this lab certificate because the cert is self-signed and has no CA OCSP responder to query.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 with Nginx connector
- OWASP CRS version: 4.25.1
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
---FyNlDcNp---B--
GET /rest/products/search?q='%20OR%201=1-- HTTP/1.1
Host: localhost:8443
User-Agent: curl/8.19.0
Accept: */*

---FyNlDcNp---F--
HTTP/1.1 403
Server: nginx
Date: Wed, 08 Jul 2026 14:28:02 GMT
Content-Length: 146
Content-Type: text/plain

---FyNlDcNp---H--
ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"] [severity "2"] [ver "OWASP_CRS/4.25.1"] [tag "attack-sqli"] [tag "paranoia-level/1"]
ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [ver "OWASP_CRS/4.25.1"]
```
Rule ID: **942100** - OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)
The WAF blocks exploit-shaped traffic at runtime, so it catches attack strings that SAST, DAST, and an L7 policy gate can miss after deployment or after a new payload variant appears. It costs operational tuning time, false-positive handling at higher paranoia levels, audit-log storage, extra TLS/proxy configuration, and another component in the request path. I would not deploy it in front of a purely internal low-risk service with strict authentication, low exposure, and a team that cannot monitor or tune WAF alerts.
