# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)

```nginx
# HTTP redirect
server {
  listen 80;
  listen [::]:80;
  server_name _;

  return 308 https://$host$request_uri;
}

# HTTPS TLS and security-header excerpt
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name _;

  ssl_certificate /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;

  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;

  ssl_ciphers "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384";
  ssl_conf_command Ciphersuites "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
  ssl_ecdh_curve X25519:secp384r1;

  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;
  ssl_stapling off;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "DENY" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

  # Location blocks are omitted from this submission excerpt.
}
```

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 12:54:08 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
```

### B. TLS 1.3 proof

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

The certificate-verification warning is expected because this isolated lab intentionally uses a self-signed certificate.

### C. Security headers proof (all 6 present)

```text
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=UTF-8
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

### What each header defends against (1 sentence each)

- HSTS: It prevents protocol-downgrade and SSL-stripping attacks by requiring the browser to use HTTPS for the declared period.
- X-Content-Type-Options: `nosniff` prevents browsers from guessing a different MIME type and executing content in an unintended context.
- X-Frame-Options: `DENY` prevents other pages from framing the application and using it for clickjacking.
- Referrer-Policy: It limits cross-origin referrer information to the origin and suppresses it during an HTTPS-to-HTTP downgrade.
- Permissions-Policy: It disables access to the camera, microphone, and geolocation browser APIs for this application.
- Content-Security-Policy: Report-only mode records violations of the allowed resource policy so XSS and unsafe resource-loading paths can be identified without breaking the application.

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 6 |
| 429 | 54 |
| 5xx | 0 |

The login endpoint accepted the configured initial burst and rejected the remaining requests with HTTP 429.

### Timeout enforced

```text
Elapsed seconds: 9.2
Connection closed by Nginx without an HTTP response.

--- Nginx access-log confirmation ---
172.23.0.1 - - [17/Jul/2026:12:59:59 +0000] "GET / HTTP/1.1" 408 0 "-" "-" rt=9.925 uct=- urt=-
```

The TLS client deliberately left its request headers incomplete; Nginx closed the connection after approximately ten seconds and recorded HTTP 408.

### Cipher hardening

```text
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Cipher: TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: Monitor certificate expiry continuously, create a warning at 30 days, and page the responsible team at 7 days.
2. **Order new cert**: Renew through the approved CA or ACME client and place the new certificate, chain, and protected private key in a versioned staging location.
3. **Validate**: Check the subject, SANs, issuer, validity dates, chain, key pairing, and intended hostname with `openssl x509`, `openssl verify`, and a public-key fingerprint comparison.
4. **Atomic swap**: Point the stable certificate and key symlinks to the validated version, run `nginx -t`, and perform a graceful Nginx reload without dropping active connections.
5. **Verify**: Confirm the served serial number, expiry, chain, TLS version, cipher, and application availability using `openssl s_client`, `curl`, monitoring, and `testssl.sh`.
6. **Rollback plan**: Retain the previous certificate and key for at least seven days so the symlinks can be restored and Nginx gracefully reloaded if verification fails.
7. **Audit**: Record the change identifier, operator, certificate serial number, issuer, expiry date, validation results, and rollback status in the change log and SIEM.

### What OCSP stapling buys you

In production, OCSP stapling lets the server periodically retrieve a signed revocation response and attach it to the TLS handshake, reducing client latency and preventing the CA from observing every client visit. It provides no useful result for this lab certificate because a self-signed certificate has no issuing CA or public OCSP responder, so stapling remains disabled here.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3.0.16 with the official OWASP CRS Nginx container
- OWASP CRS version: 4.25.1 LTS
- Paranoia level: 1
- WAF endpoint: `https://localhost:8443`
- Protected backend: hardened Nginx at `https://nginx:443`

ModSecurity v3 was selected because it is explicitly permitted by the lab and has mature OWASP CRS integration and documentation.

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)

```text
no-waf: HTTP 500
```

Nginx forwarded the request instead of blocking it; the HTTP 500 response was generated by the deliberately vulnerable Juice Shop application while processing the payload.

### After WAF

```text
with-waf: HTTP 403
```

### Audit log excerpt (the rules that fired)

```text
Access-Control-Allow-Origin: *
Connection: keep-alive
Access-Control-Max-Age: 3600
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *

---LpebCnh6---H--
ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"] [severity "2"] [ver "OWASP_CRS/4.25.1"] [tag "paranoia-level/1"] [tag "OWASP_CRS/ATTACK-SQLI"] [uri "/rest/products/search"]
ModSecurity: Access denied with code 403 (phase 2). [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [ver "OWASP_CRS/4.25.1"] [tag "anomaly-evaluation"] [uri "/rest/products/search"]

---LpebCnh6---I--

---LpebCnh6---J--

---LpebCnh6---Z--
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**.
Blocking rule: **949110** — **Inbound Anomaly Score Exceeded (Total Score: 5)**.

### Tradeoff analysis (3 sentences)

The WAF adds runtime inspection that can stop a malicious request after deployment, complementing SAST, DAST, and policy gates that do not evaluate every live request. Its costs include false-positive risk, request-processing overhead, continuous rule tuning, and additional certificate, configuration, and logging operations. A WAF should not be added when the service does not process compatible HTTP traffic, when its operational and latency costs exceed the threat reduction, or when an existing managed gateway already provides the same carefully tuned protection.
