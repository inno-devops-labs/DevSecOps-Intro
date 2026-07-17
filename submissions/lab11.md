# Lab 11 - BONUS - Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)

```nginx
server {
  listen 80;
  listen [::]:80;
  server_name _;

  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
  add_header Cross-Origin-Opener-Policy "same-origin" always;
  add_header Cross-Origin-Resource-Policy "same-origin" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

  return 308 https://$host$request_uri;
}

server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name _;
  limit_conn conn 50;

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;
  ssl_session_timeout 1d;
  ssl_session_cache   shared:SSL:10m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256;
  ssl_ecdh_curve X25519:secp384r1;
  ssl_prefer_server_ciphers off;
  ssl_stapling off;

  client_max_body_size 2m;
  client_body_timeout 10s;
  client_header_timeout 10s;
  keepalive_timeout 10s;
  send_timeout 10s;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
  add_header Cross-Origin-Opener-Policy "same-origin" always;
  add_header Cross-Origin-Resource-Policy "same-origin" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
}
```

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 13:50:16 GMT
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

```text
Connecting to ::1
Can't use SSL_get_servername
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
```

### C. Security headers proof (all 6 present)

```text
HTTP/2 200
server: nginx
date: Fri, 17 Jul 2026 13:50:17 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 13:48:28 GMT
etag: W/"26af-19f7055f2e1"
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

- HSTS: forces browsers to use HTTPS for this origin after the first trusted response, reducing SSL-stripping and accidental HTTP downgrade risk.
- X-Content-Type-Options: `nosniff` prevents browsers from guessing a different MIME type and executing content in an unsafe context.
- X-Frame-Options: `DENY` blocks framing entirely, which reduces clickjacking risk.
- Referrer-Policy: `strict-origin-when-cross-origin` avoids leaking full paths and query strings to other origins while preserving useful same-origin referrers.
- Permissions-Policy: disables camera, microphone, and geolocation APIs for this origin unless they are explicitly re-enabled later.
- Content-Security-Policy: the report-only policy starts restricting script, style, and image sources without breaking Juice Shop while violations are collected and tuned.

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

Raw output:

```text
  54 429
   6 500
```

The six `500` responses were the first requests allowed through to Juice Shop for this unauthenticated `GET /rest/user/login` probe; the remaining 54 requests were blocked by Nginx with `429`, proving the rate limiter was active.

### Timeout enforced

```text
Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=juice.local
verify return:1
801E60FA01000000:error:0A000126:SSL routines::unexpected eof while reading:ssl/record/rec_layer_s3.c:703:
```

### Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: monitor certificate expiry continuously, alert at 30 days, and page at 7 days before expiration.
2. **Order new cert**: renew through Let's Encrypt/certbot for public domains or the organization's approved CA for managed certificates.
3. **Validate**: inspect the new certificate with `openssl x509 -in newcert.pem -text -noout` and verify the chain with `openssl verify -CAfile ca.pem newcert.pem`.
4. **Atomic swap**: write the new cert/key next to the old pair, update the `current` symlink or mounted secret atomically, then run `nginx -s reload`.
5. **Verify**: confirm production serves the new serial and expiry with `openssl s_client` or `curl -vk`, and re-check TLS posture with a scanner such as `testssl.sh`.
6. **Rollback plan**: keep the previous cert/key available for at least 7 days and roll back by repointing the symlink or restoring the previous secret followed by `nginx -s reload`.
7. **Audit**: record the rotation time, actor, certificate serial, issuer, expiry, validation output, and rollback artifact location in the operations log or SIEM.

### What OCSP stapling buys you

OCSP stapling lets the edge server periodically fetch revocation status from the CA and attach that signed status to TLS handshakes, which removes client-side OCSP latency and avoids leaking every visitor's connection to the CA responder. It is useful with publicly trusted certificates because clients can validate revocation status against the issuing CA. It is not meaningful for this lab's self-signed `localhost` certificate because there is no public CA responder or trusted revocation chain to staple.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: Coraza WAF via `ghcr.io/coreruleset/coraza-crs:caddy-alpine`
- OWASP CRS version: 4.25.0
- Paranoia level: 1 (`BLOCKING_PARANOIA=1`, `PARANOIA=1`)
- Rule engine: blocking mode (`CORAZA_RULE_ENGINE=On`)
- Audit log configured at `/var/log/coraza/audit.log`; Coraza Caddy emitted the rule events to the `waf` container log during verification.

### Attack payload sent

`GET /rest/products/search?q=<script>alert(1)</script>` (URL-encoded)

### Before WAF (Nginx alone)

```text
no-waf-xss: HTTP 200
```

### After WAF

```text
with-coraza-xss: HTTP 403
```

### Audit log excerpt (the rule that fired)

```text
GET /rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: localhost:8080

HTTP/1.1 403

Coraza: Warning. XSS Attack Detected via libinjection [file "/opt/coraza/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [id "941100"] [msg "XSS Attack Detected via libinjection"] [data "Matched Data: XSS data found within ARGS:q: <script>alert(1)</script>"] [ver "OWASP_CRS/4.25.0"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [uri "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"]
Coraza: Warning. XSS Filter - Category 1: Script Tag Vector [file "/opt/coraza/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [id "941110"] [msg "XSS Filter - Category 1: Script Tag Vector"] [data "Matched Data: <script> found within ARGS:q: <script>alert(1)</script>"] [ver "OWASP_CRS/4.25.0"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [uri "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"]
Coraza: Warning. Inbound Anomaly Score Exceeded (Total Score: 20) [file "/opt/coraza/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 20)"] [ver "OWASP_CRS/4.25.0"] [tag "OWASP_CRS"] [uri "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"]
```

Rule ID: **941100** - OWASP CRS rule name: **XSS Attack Detected via libinjection**

### Tradeoff analysis

A WAF buys runtime request inspection at the edge, so it can block exploit payloads against code paths that SAST, DAST, and policy-as-code either missed or only reported earlier in the pipeline. The cost is operational tuning: false positives increase as paranoia rises, audit logs need review, and the edge now has another certificate/configuration surface to maintain. I would not deploy a WAF in front of a service where protocol semantics are not HTTP-compatible, where latency is the dominant product requirement and compensating controls are stronger, or where the team cannot monitor and tune the WAF after rollout.

## Checklist

- [x] Task 1 - HTTPS serves through Nginx
- [x] Task 1 - HTTP redirects to HTTPS with 301 or 308
- [x] Task 1 - TLS 1.3 only is configured and negotiated
- [x] Task 1 - all 6 required security headers are present with `always`
- [x] Task 1 - each header purpose is explained in one truthful sentence
- [x] Task 2 - login rate limit returns 429 under load
- [x] Task 2 - connection limit is configured
- [x] Task 2 - fail-closed timeouts are configured and timeout behavior is captured
- [x] Task 2 - TLS 1.3 cipher and X25519 curve are verified
- [x] Task 2 - 7-step cert rotation runbook is present
- [x] Task 2 - OCSP stapling explanation states why production and self-signed lab behavior differ
- [x] Bonus - Coraza WAF stack runs in front of Nginx
- [x] Bonus - OWASP CRS 4.x and paranoia level 1 are documented
- [x] Bonus - same attack payload is not blocked by Nginx alone and is blocked by WAF
- [x] Bonus - audit log excerpt includes the CRS rule ID and rule name
- [x] Bonus - WAF tradeoff analysis covers value, false positives/ops cost, and when not to deploy
