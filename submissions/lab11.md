# Lab 11 — BONUS — Submission

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

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.3;
  # ssl_ciphers only controls TLS <= 1.2; configure TLS 1.3 suites via OpenSSL.
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
  ssl_prefer_server_ciphers off;
  ssl_ecdh_curve X25519:secp384r1;

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

`ssl_conf_command Ciphersuites` is used because current Nginx/OpenSSL applies `ssl_ciphers` only to TLS 1.2 and older and rejects TLS 1.3 suite names there. TLS 1.3 is the only enabled protocol, and the negotiated suite proof below confirms the required modern suite.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/
```

### B. TLS 1.3 proof

```text
Connecting to 127.0.0.1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

The verification error is expected because this lab intentionally uses a self-signed certificate.

### C. Security headers proof (all 6 present)

```text
HTTP/2 200
server: nginx
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)

- HSTS: It prevents SSL stripping after the first trusted HTTPS visit by making the browser refuse HTTP for the host and its subdomains.
- X-Content-Type-Options: `nosniff` stops browsers from interpreting a response as a more dangerous content type than the server declared.
- X-Frame-Options: `DENY` prevents any site from framing the application, reducing clickjacking risk.
- Referrer-Policy: It limits cross-origin referrers to the origin so paths and query-string data are not leaked to other sites.
- Permissions-Policy: It denies camera, microphone, and geolocation access to the page and embedded content unless the policy is deliberately relaxed.
- Content-Security-Policy: Report-only CSP records resource-policy violations so XSS and data-exfiltration controls can be tightened safely before enforcement.

## Task 2: Production Posture

### Rate limit proof

Sixty concurrent JSON login POSTs were sent after restarting Nginx to clear the in-memory rate zone.

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

The six admitted requests reached Juice Shop and were rejected as invalid credentials; Nginx rejected the remaining 54 at the edge with 429.

### Timeout enforced

```text
verify return:1
depth=0 CN=juice.local
verify return:1
error:0A000126:SSL routines::unexpected eof while reading
Connection closed after 12 seconds (client_header_timeout = 10s).
```

The client held an incomplete header open; Nginx closed the TLS connection after its 10-second header timeout (the two extra seconds are the test producer's sleep duration and process timing).

### Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

OpenSSL 3.5 labels the server's ephemeral key as `Peer Temp Key`; this is the required X25519 key exchange.

### Cert rotation runbook (7 steps)

1. **Detect expiry**: Monitor every public endpoint and certificate inventory, alert at 30 days remaining, and page the owner at 7 days.
2. **Order new cert**: Renew with ACME/Certbot for an automated public certificate, or order from the approved CA when policy requires a specialty certificate.
3. **Validate**: Inspect subject, SANs, serial, validity, and key match with OpenSSL, then run `openssl verify` against the intended CA chain before deployment.
4. **Atomic swap**: Stage the new certificate and key with least-privilege permissions, atomically repoint the `current` symlinks, run `nginx -t`, and reload Nginx without dropping connections.
5. **Verify**: Connect to the production hostname with `openssl s_client` and `curl`, confirm the new serial and dates, and rerun the TLS posture check.
6. **Rollback plan**: Retain the previous known-good certificate and key securely for about seven days; if verification fails, repoint both symlinks to that pair, validate, and reload.
7. **Audit**: Record the change ticket, operator/automation identity, deployment time, certificate serial, issuer, expiry, verification results, and rollback disposition in the SIEM or DefectDojo.

### What OCSP stapling buys you

As Reading 11 explains, stapling lets the server periodically fetch the CA-signed revocation status and attach it to the TLS handshake, avoiding a client-to-CA round trip and reducing the client's privacy leak to the CA. A self-signed lab certificate has no public CA OCSP responder or trusted issuer chain, so there is no meaningful response to staple; production CA-issued certificates can use stapling, provided resolver and renewal failures are monitored.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3 with the official OWASP CRS Nginx image
- OWASP CRS version: 4.25.1 (pinned image tag)
- Paranoia level: 1
- Rule engine: `On`
- Audit log: `/var/log/modsec/audit.log`, bind-mounted to the host

ModSecurity v3 was selected because the lab explicitly recommends it as the gentler, better-documented CRS integration; Coraza is the modern Go reimplementation but is not required for this accepted alternative.

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)

```text
no-waf: HTTP 500
```

The application returned an error, but Nginx itself did not recognize or block the SQL injection pattern.

### After WAF

```text
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)

```text
GET /rest/products/search?q='%20OR%201=1-- HTTP/2.0
user-agent: curl/8.18.0
host: localhost:8443

HTTP/2.0 403
Server: nginx
Content-Type: text/plain
Connection: close

ModSecurity: Warning. detected SQLi using libinjection.
[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]
[id "942100"] [msg "SQL Injection Attack Detected via libinjection"]
[data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"]
[ver "OWASP_CRS/4.25.1"] [tag "paranoia-level/1"] [tag "attack-sqli"]
ModSecurity: Access denied with code 403 (phase 2).
[id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**.

### Tradeoff analysis

A WAF adds a runtime, request-aware compensating control that can block exploit patterns before they reach the application, whereas SAST, DAST, and policy gates find defects or configuration drift before deployment but do not filter each live request. That protection costs latency, rule tuning, monitoring, upgrade work, certificate/configuration ownership, and false-positive risk—especially as paranoia rises. I would not deploy one where the threat model does not justify that operational burden, where strict latency or protocol requirements make interception unsuitable, or where the team cannot monitor and tune blocking safely; fixing the underlying application flaws remains mandatory either way.
