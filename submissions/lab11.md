# Lab 11 -- BONUS -- Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

    server {
      listen 443 ssl;
      http2 on;
      ssl_protocols TLSv1.3;
      ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
      ssl_prefer_server_ciphers off;
      ssl_ecdh_curve X25519:secp384r1;
      ssl_session_tickets off;

      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
      add_header X-Frame-Options "DENY" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header Referrer-Policy "strict-origin-when-cross-origin" always;
      add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
      add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
    }

The HTTP server on :80 issues a 308 redirect to HTTPS.

### A. HTTPS redirect proof

    HTTP/1.1 308 Permanent Redirect
    Server: nginx
    Location: https://localhost/

### B. TLS 1.3 proof

    CONNECTION ESTABLISHED
    Protocol version: TLSv1.3
    Ciphersuite: TLS_AES_256_GCM_SHA384
    Peer Temp Key: X25519, 253 bits

### C. Security headers proof (all 6 present)

    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    Referrer-Policy: strict-origin-when-cross-origin
    Permissions-Policy: camera=(), geolocation=(), microphone=()
    Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

### What each header defends against
- **HSTS:** Forces browsers to use HTTPS for all future requests, defeating SSL-strip / downgrade man-in-the-middle attacks even if a user types `http://`.
- **X-Content-Type-Options: nosniff:** Stops the browser from MIME-sniffing a response away from its declared Content-Type, blocking attacks where a `.txt` upload is executed as JavaScript.
- **X-Frame-Options: DENY:** Prevents the page from being embedded in any iframe, defeating clickjacking overlays.
- **Referrer-Policy:** Strips the full URL (path, query) from the Referer header on cross-origin requests, preventing leakage of tokens or session IDs embedded in URLs.
- **Permissions-Policy:** Disables access to camera, microphone, and geolocation APIs, so even injected/compromised scripts can't reach those sensors.
- **Content-Security-Policy:** Restricts which origins scripts/styles/images may load from, the primary defense against XSS; used in Report-Only here so Juice Shop's inline scripts keep working while violations are logged for iterative tightening.

## Task 2: Production Posture

### Rate limit proof
60 requests to `/rest/user/login` (limit 10r/m + burst 5):
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 429 (rate-limited) | 54 |
| 500 (passed to upstream) | 6 |

The `limit_req zone=login burst=5 nodelay` rule allowed an initial burst then returned `429` (set via `limit_req_status 429`) for the remaining 54 requests, exactly as designed.

### Timeout enforced
Slowloris-style protection is enforced by `client_header_timeout 10s` and `client_body_timeout 10s` in the HTTPS server block — a client that opens a connection but sends headers slowly is dropped after 10s. (A clean partial-request reproduction needs a raw socket tool like `nc`, unavailable in the PowerShell test environment; the control is present in config and active.)

### Cipher hardening

    Peer Temp Key: X25519, 253 bits
    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Cipher    : TLS_AES_256_GCM_SHA384

TLS 1.3 with an AEAD cipher (AES-256-GCM) and X25519 ECDHE key exchange — the Mozilla "Modern" profile.

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor with `openssl x509 -enddate -noout -in localhost.crt` on a cron/alert (e.g. alert at 30 days remaining); in production use ACME/cert-manager which tracks expiry automatically.
2. **Order new cert**: Request the replacement (Let's Encrypt via certbot/ACME, or internal CA) into a staging path, never overwriting the live cert.
3. **Validate**: Verify the new cert/key pair match (`openssl x509 -noout -modulus | md5` vs the key's modulus) and that the chain is complete before deploying.
4. **Atomic swap**: Write the new cert to a temp file and `mv` it over the live path (atomic rename), so nginx never reads a half-written file.
5. **Verify**: `nginx -t` to test config, then `nginx -s reload` (graceful — keeps existing connections), then confirm the served cert with `openssl s_client -connect host:443 | openssl x509 -enddate`.
6. **Rollback plan**: Keep the previous cert/key as `*.bak`; if the reload fails validation, `mv` the backup back and reload again — recovery is seconds, not a re-issue.
7. **Audit**: Log the rotation (who, when, old/new serial numbers) to the change-management record and update the expiry-monitoring baseline for the new cert.

### What OCSP stapling buys you
OCSP stapling lets the server fetch and attach ("staple") a CA-signed proof of non-revocation to the TLS handshake, so the browser doesn't have to make a separate, latency-adding, privacy-leaking call to the CA's OCSP responder — and the connection still works if the responder is down. It's disabled here because a self-signed lab cert has no issuing CA and no OCSP responder URL, so there's nothing to staple; in production with a publicly-trusted cert, stapling is a clear latency and privacy win and should be on.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3.0.16 (nginx connector v1.0.4), via the `owasp/modsecurity-crs:nginx-alpine` image
- OWASP CRS version: 4.27.0
- Paranoia level: 1
- SecRuleEngine: On (blocking, not DetectionOnly)
- Deployed as a `waf` sidecar on port 8080, proxying to the same Juice Shop upstream as the Task 1/2 nginx.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded as `q=%27%20OR%201=1--`)

### Before WAF (Nginx alone, port 443)

    no-waf: HTTP 500

The Task 1/2 nginx proxied the injection straight through to Juice Shop, which choked on it (500) — nginx itself applied no inspection.

### After WAF (port 8080)

    with-waf: HTTP 403

OWASP CRS blocked the request before it reached the app.

### Audit log excerpt (the rule that fired)

    "message":"SQL Injection Attack Detected via libinjection",
    "ruleId":"942100",
    "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
    "tags":["attack-sqli","paranoia-level/1","OWASP_CRS/ATTACK-SQLI"]
    ---
    "message":"Inbound Anomaly Score Exceeded (Total Score: 5)",
    "ruleId":"949110"

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**. The anomaly score reached the blocking threshold (5) at rule **949110**, producing the 403.

### Tradeoff analysis
The WAF buys you a **generic, signature-independent net** that catches attack *classes* (SQLi, XSS, path traversal) at the edge regardless of application code — something Lab 5's SAST/DAST (which find specific flaws at build/test time) and the Lab 9 Conftest gate (which validates manifests, not traffic) cannot do at runtime against live requests. The cost is **false positives** — at higher paranoia levels CRS flags legitimate traffic (Juice Shop's own complex queries would trip rules), so you pay in tuning effort, plus the ops overhead of another proxy hop, audit-log volume, and cert/config sprawl. You would **not** deploy a WAF in front of a service when latency budgets are razor-thin, when the app already does rigorous server-side validation and the WAF only adds FP noise, or for purely internal/mutual-TLS services where the threat model doesn't include untrusted HTTP input.