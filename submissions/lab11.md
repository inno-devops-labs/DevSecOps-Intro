# Lab 11 — BONUS — Submission

Runtime evidence was collected automatically on **2026-07-17 14:27:00 UTC** by `labs/lab11/run-and-collect.sh`. The script aborts instead of rendering this report if a required control fails.

## Task 1: TLS + Security Headers

### nginx.conf — redirect, TLS, and response-header sections

```nginx
# Port 80
return 308 https://$host$request_uri;

# Port 443
listen 443 ssl;
listen [::]:443 ssl;
http2 on;
ssl_certificate     /etc/nginx/certs/localhost.crt;
ssl_certificate_key /etc/nginx/certs/localhost.key;
ssl_protocols TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_prefer_server_ciphers off;
ssl_ecdh_curve X25519:secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
ssl_early_data off;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss:; upgrade-insecure-requests" always;
```

Nginx uses `ssl_conf_command Ciphersuites` for TLS 1.3 suites because `ssl_ciphers` configures TLS 1.2 and older suites. TLS 1.2 is disabled, while the non-empty `ssl_ciphers` fallback keeps the configuration compatible with Nginx's OpenSSL initialization.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 14:26:45 GMT
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
Content-Security-Policy-Report-Only: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss:; upgrade-insecure-requests
```

### B. TLS 1.3 proof

```text
depth=0 CN = juice.local
verify error:num=18:self signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
Signature type: RSA-PSS
Verification error: self signed certificate
Server Temp Key: X25519, 253 bits
DONE
```

### C. Security headers proof

```text
HTTP/2 200 
server: nginx
date: Fri, 17 Jul 2026 14:26:45 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 14:26:44 GMT
etag: W/"26af-19f7078f9f9"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss:; upgrade-insecure-requests
```

### What each header defends against

- **HSTS:** forces future browser connections onto HTTPS, preventing SSL-stripping and accidental clear-text access after the first trusted response.
- **X-Content-Type-Options: nosniff:** prevents browsers from reinterpreting a response as an executable MIME type different from the declared `Content-Type`.
- **X-Frame-Options: DENY:** prevents the application from being embedded in an attacker-controlled frame and therefore reduces clickjacking risk.
- **Referrer-Policy:** limits cross-origin referrers to the origin so sensitive paths and query strings are not leaked to other sites.
- **Permissions-Policy:** denies camera, microphone, and geolocation access to the page and its embedded content unless the policy is deliberately relaxed.
- **Content-Security-Policy-Report-Only:** reports resource loads that violate the strict same-origin policy so XSS and exfiltration controls can be tuned before enforcement.

## Task 2: Production Posture

### Rate limit proof

The test sent an invalid login payload, so accepted requests may return an application-level 4xx instead of 200; HTTP 429 is the edge rejection that proves the Nginx control fired.

| HTTP category | Count out of 60 |
|---|---:|
| 200 | 0 |
| 429 | 54 |
| Other 4xx | 6 |
| 5xx | 0 |

Raw summary:

```text
6 401
54 429
```

### Timeout enforced

This proof uses a TLS socket that sends an incomplete HTTP header and then waits. A plaintext `nc localhost 443` request would only test rejection of non-TLS traffic, not `client_header_timeout`.

```text
Outcome: connection closed
Elapsed: 10.01 seconds
```

### Cipher hardening

```text
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook

1. **Detect expiry:** monitor every production certificate and alert at 30 days, escalating to an on-call page at 7 days; also monitor failed automated renewals.
2. **Order new cert:** renew through ACME/Let's Encrypt or the approved CA, generating the private key in the secret-management boundary rather than in the repository.
3. **Validate:** inspect subject, SANs, issuer, serial, validity period, key usage, and chain with `openssl x509` and `openssl verify`; confirm that the key matches the certificate.
4. **Atomic swap:** stage versioned certificate and key files, atomically repoint the `current` symlinks, run `nginx -t`, and perform a zero-downtime `nginx -s reload`.
5. **Verify:** connect from outside the service with `openssl s_client`, `curl`, and `testssl.sh`; confirm the new serial, full chain, TLS 1.3, headers, and application health.
6. **Rollback plan:** retain the previous known-good certificate and key for at least seven days and restore their symlinks followed by another tested Nginx reload if validation fails.
7. **Audit:** record the operator or automation identity, change/ticket ID, certificate serial, expiry, validation output, deployment time, and rollback status in the SIEM/change log.

### What OCSP stapling buys you

In production, stapling lets Nginx periodically obtain a CA-signed revocation response and attach it to the TLS handshake, reducing client latency and preventing the CA from learning each client's browsing destination. A self-signed lab certificate has no issuing CA or OCSP responder, so there is no authoritative revocation response to staple; enabling it here would produce warnings without adding security.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used:** ModSecurity v3 with the official OWASP CRS Nginx image
- **OWASP CRS version:** 4.25.1 LTS, pinned by the WAF Dockerfile
- **Paranoia level:** blocking 1, detection 1
- **Topology:** the lab exposes Nginx directly on 443 for the before/after comparison and the WAF on 8443; the WAF forwards allowed traffic to Nginx over TLS

ModSecurity v3 was selected because the assignment explicitly accepts it and its official OWASP CRS container provides a reproducible CRS v4 deployment. Coraza would be a valid modern alternative, but using ModSecurity here keeps the exercise aligned with the task's documented examples and audit-log format.

### Attack payload sent

`GET /rest/products/search?q='%20OR%201=1--` (URL-encoded by `curl --data-urlencode`)

### Before and after the WAF

```text
no-waf: HTTP 500
with-waf: HTTP 403
```

### Audit log excerpt

```text
Access-Control-Max-Age: 3600
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: *

---fSlATGKO---H--
ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [rev ""] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"] [severity "2"] [ver "OWASP_CRS/4.25.1"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "OWASP_CRS/ATTACK-SQLI"] [tag "capec/1000/152/248/66"] [hostname "localhost"] [uri "/rest/products/search"] [unique_id "178429841966.395850"] [ref "v28,10"]
ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] [severity "0"] [ver "OWASP_CRS/4.25.1"] [maturity "0"] [accuracy "0"] [tag "modsecurity"] [tag "anomaly-evaluation"] [tag "OWASP_CRS"] [hostname "localhost"] [uri "/rest/products/search"] [unique_id "178429841966.395850"] [ref ""]

---fSlATGKO---I--

---fSlATGKO---J--

---fSlATGKO---Z--
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis

The WAF adds a runtime compensating control that can reject exploit patterns before they reach Juice Shop; SAST, DAST, and Conftest find source, runtime, or deployment problems but do not sit inline on every production request. The cost is latency, rule/configuration and certificate ownership, audit-log operations, and false positives that increase as paranoia levels rise. I would not deploy a self-managed WAF where the team cannot monitor and tune it, where strict API schemas and application controls already provide a smaller reliable attack surface, or where an inline availability dependency would create more risk than it removes.


