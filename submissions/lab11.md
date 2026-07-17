# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_conn_zone $binary_remote_addr zone=conn:10m;
limit_req_status 429;

server {
  listen 80;
  listen [::]:80;
  server_name _;
  limit_conn conn 50;

  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  add_header Cross-Origin-Opener-Policy "same-origin" always;
  add_header Cross-Origin-Resource-Policy "same-origin" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

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
  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;
  ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
  ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
  ssl_ecdh_curve X25519:secp384r1;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;
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
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  add_header Cross-Origin-Opener-Policy "same-origin" always;
  add_header Cross-Origin-Resource-Policy "same-origin" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

  location = /rest/user/login {
    limit_req zone=login burst=5 nodelay;
    limit_req_log_level warn;
    proxy_pass http://juice;
  }

  location / {
    proxy_pass http://juice;
  }
}
```

Note: this Nginx image rejects TLS 1.3 names in `ssl_ciphers` with `no cipher match`, so `ssl_ciphers` is kept as the legacy-safe list and the real TLS 1.3 suites are pinned with `ssl_conf_command Ciphersuites`.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 20:09:47 GMT
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

### B. TLS 1.3 proof

```text
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
```

### C. Security headers proof

```text
HTTP/2 200
server: nginx
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

### What each header defends against

- HSTS: prevents SSL stripping by forcing browsers back to HTTPS after the first trusted HTTPS response.
- X-Content-Type-Options: nosniff: stops the browser from guessing a more dangerous MIME type than the server declared.
- X-Frame-Options: DENY: prevents clickjacking by refusing to load the app inside any frame.
- Referrer-Policy: limits cross-site `Referer` leakage so full paths and query strings do not spill to other origins.
- Permissions-Policy: disables camera, microphone, and geolocation APIs for this origin unless explicitly allowed later.
- Content-Security-Policy: report-only CSP gives XSS and data-exfiltration telemetry without breaking Juice Shop while the policy is tuned.

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

The 6 unblocked requests reached Juice Shop first and returned app-side `500`; the proxy then blocked the rest with `429`.

### Timeout enforced

```text
172.64.154.109 - - [17/Jul/2026:20:12:14 +0000] "POST / HTTP/1.1" 408 0 "-" "-" rt=10.005 uct=- urt=-
```

### Cipher hardening

```text
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
```

### Cert rotation runbook

1. **Detect expiry**: alert at 30 days before expiry and page at 7 days using cert monitoring or a scheduled `openssl x509 -checkend` job.
2. **Order new cert**: renew through Let's Encrypt/certbot for public hosts, or through the company CA for internal domains.
3. **Validate**: check subject, SANs, issuer chain, expiry, and key match with `openssl x509`, `openssl verify`, and `openssl pkey`.
4. **Atomic swap**: deploy new cert and key beside the old pair, switch the `current` symlink, then run `nginx -t && nginx -s reload`.
5. **Verify**: confirm the served cert, TLS version, cipher, and headers with `curl -vk`, `openssl s_client`, and preferably `testssl.sh`.
6. **Rollback plan**: keep the previous cert and key for at least a week and switch the symlink back if reload or client verification fails.
7. **Audit**: record serial number, fingerprint, issuer, expiry, approver, deploy time, and verification output in the change log/SIEM.

### What OCSP stapling buys you

OCSP stapling lets the server fetch certificate revocation proof from the CA and staple it into the TLS handshake, so clients avoid an extra CA lookup and leak less browsing metadata. It matters for public CA certificates, especially high-traffic sites. It does not help this lab cert because the cert is self-signed, so there is no real CA OCSP responder or issuer chain for Nginx to staple.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3 via `owasp/modsecurity-crs:4-nginx-202607160307`
- OWASP CRS version: 4.28.0
- Paranoia level: 1
- Rule engine: `SecRuleEngine On`
- Audit log: `/var/log/modsec/audit.log`

I used ModSecurity v3 because the lab allowed it as the richer-documented CRS path. Coraza would be the modern Go option, but the rule behavior and anomaly-scoring idea are the same for this payload.

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--`

### Before WAF (Nginx alone)

```text
no-waf: HTTP 500
```

The request reached Juice Shop and produced an app response. Nginx did not block it.

### After WAF

```text
with-waf: HTTP 403
```

### Audit log excerpt

```text
GET /rest/products/search?q='%20OR%201=1-- HTTP/2.0
host: localhost:8443

HTTP/2.0 403

ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"] [ver "OWASP_CRS/4.28.0"] [tag "paranoia-level/1"] [tag "OWASP_CRS/ATTACK-SQLI"]
ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [ver "OWASP_CRS/4.28.0"]
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**.

### Tradeoff analysis

The WAF adds runtime protection for malicious requests that static checks, DAST, and deployment policy gates do not see at the exact moment of attack. It costs tuning time, false-positive risk at higher paranoia levels, extra logs to review, and another TLS/proxy config surface to maintain. I would not put a blocking WAF in front of a low-risk internal service or a service already covered by a managed edge WAF unless the team has time to monitor and tune it.
