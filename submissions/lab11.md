# Lab 11 - BONUS - Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

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

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;
  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256;
  ssl_ecdh_curve X25519:secp384r1;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;

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

Note: Nginx applies `ssl_ciphers` to TLS 1.2 and below. For TLS 1.3, the working configuration uses OpenSSL's `ssl_conf_command Ciphersuites ...`; the live proof below shows the negotiated TLS 1.3 suite.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Mon, 06 Jul 2026 18:08:06 GMT
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

### C. Security headers proof

```text
HTTP/2 200
server: nginx
date: Mon, 06 Jul 2026 18:08:06 GMT
content-type: text/html; charset=UTF-8
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

- HSTS: forces future browser requests to use HTTPS, reducing SSL stripping and accidental plaintext downgrade risk.
- X-Content-Type-Options: nosniff: prevents browsers from interpreting a response as a different content type than the server declared.
- X-Frame-Options: DENY: blocks framing of the application and reduces clickjacking exposure.
- Referrer-Policy: limits how much URL context leaks to other origins through the `Referer` header.
- Permissions-Policy: denies browser access to camera, microphone, and geolocation APIs unless explicitly re-enabled.
- Content-Security-Policy: reports script, style, image, and origin violations before enforcing a strict policy that might break Juice Shop.

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced

```text
Partial HTTP request closed after 12 seconds; response bytes: 0
```

### Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: monitor certificate expiry with `openssl x509 -checkend`, synthetic HTTPS checks, and alert at 30/14/7 days before expiry.
2. **Order new cert**: issue the replacement through ACME or the production CA using the existing SAN list and key policy.
3. **Validate**: verify chain, SANs, key type, expiry, and private-key match in staging before touching production.
4. **Atomic swap**: write the new cert and key to versioned files, update the symlink atomically, and run `nginx -t`.
5. **Verify**: reload Nginx, then confirm TLS 1.3, chain validity, HSTS, and expected cert fingerprint from an external client.
6. **Rollback plan**: keep the previous cert/key pair and symlink target available so a bad deploy can be reverted and reloaded quickly.
7. **Audit**: record issuer, serial, fingerprint, operator, time, validation output, and rollback status in the change record.

### What OCSP stapling buys you

OCSP stapling lets Nginx fetch and staple the CA's revocation status so clients can validate revocation without calling the CA directly on every connection. That improves privacy, latency, and reliability for public certificates. It does not help this lab's self-signed certificate because there is no trusted issuer OCSP responder or real revocation chain to staple.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3 with the official OWASP CRS Nginx image
- Image: `owasp/modsecurity-crs:4.28.0-nginx-alpine-202607051007`
- OWASP CRS version: `4.28.0`
- Paranoia level: 1
- Audit log: `/var/log/modsec/audit.log`

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--`

### Before WAF (Nginx alone)

```text
no-waf: HTTP 500
```

This reached Juice Shop through Nginx and was not blocked by the reverse proxy. The application returned an error for the deliberately hostile query.

### After WAF

```text
with-waf: HTTP 403
```

### Audit log excerpt

```text
GET /rest/products/search?q='%20OR%201=1-- HTTP/2.0
host: localhost:8443

HTTP/2.0 403
Server: nginx

ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"] [severity "2"] [ver "OWASP_CRS/4.28.0"] [tag "attack-sqli"] [tag "paranoia-level/1"] [tag "OWASP_CRS/ATTACK-SQLI"]
ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [ver "OWASP_CRS/4.28.0"]
```

Rule ID: **942100** - OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**.

### Tradeoff analysis

The WAF buys a runtime compensating control: it can block whole attack classes such as SQLi probes even when SAST, DAST, or policy gates missed a specific route or payload. The cost is operational complexity: another TLS endpoint, more logs to tune, possible false positives, and rule updates that need change control. I would avoid putting this WAF in front of a small internal single-tenant service with low exposure and strong authenticated inputs; the operational cost would likely exceed the risk reduction.
