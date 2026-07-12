# Lab 11 — BONUS — Submission

> Stack: `nginx:stable-alpine` reverse proxy in front of Juice Shop v20 (docker-compose), self-signed
> cert (`CN=juice.local`). WAF layer: `owasp/modsecurity-crs:nginx-alpine` (ModSecurity v3.0.16 +
> OWASP CRS 3.3.10). Verified with curl + `openssl s_client`.

## Task 1: TLS + Security Headers

### nginx.conf — SSL + header sections
```nginx
ssl_protocols TLSv1.3;                 # TLS 1.3 only
ssl_prefer_server_ciphers off;         # TLS 1.3 ignores server preference
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
ssl_ecdh_curve X25519:secp384r1;
ssl_session_cache shared:SSL:10m; ssl_session_timeout 1d; ssl_session_tickets off;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```
> Note: TLS 1.3 cipher suites are set via `ssl_conf_command Ciphersuites`, **not** `ssl_ciphers`
> (which only governs TLS ≤ 1.2 — using it for TLS 1.3 names throws `no cipher match` at startup).

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

### B. TLS 1.3 proof (`openssl s_client -tls1_3`)
```
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
```

### C. Security headers proof (all 6 present)
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against
- **HSTS:** forces the browser to use HTTPS for the next 2 years, defeating SSL-strip / downgrade MITM on subsequent visits.
- **X-Content-Type-Options: nosniff:** stops the browser from MIME-sniffing a response into an executable type (e.g. treating an uploaded `.txt` as JS).
- **X-Frame-Options: DENY:** blocks the page being embedded in an `<iframe>`, killing clickjacking.
- **Referrer-Policy:** trims the `Referer` header on cross-origin navigations so URLs (which may carry tokens/paths) don't leak to third parties.
- **Permissions-Policy:** disables powerful browser features (camera/mic/geolocation) so a compromised page can't silently request them.
- **Content-Security-Policy(-Report-Only):** constrains where scripts/styles/images may load from, the primary defense against XSS (Report-Only here so Juice Shop's inline scripts still work while we tune it).

---

## Task 2: Production Posture

### Rate limit proof (60 concurrent POSTs to `/rest/user/login`, zone = 10r/m burst 5)
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 (passed rate limit, auth failed) | 6 |
| 429 (rate limited) | 54 |
| 5xx | 0 |

### Timeout enforced (slowloris: partial header, no terminating CRLF)
```
nginx closed the connection after exactly 10.0s (client_header_timeout 10s → 408 + close)
```
(The timeout directives are set at the `http` level so they apply to both `:80` and `:443`.)

### Cipher hardening
```
Cipher is TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
```

### Cert-rotation runbook (7 steps)
1. **Detect expiry** — a monitor (`openssl x509 -enddate` cron / cert-manager / Prometheus blackbox exporter) alerts at T-30 days.
2. **Order new cert** — request from the CA (ACME/Let's Encrypt `certbot`, or the internal PKI); reuse or rotate the key.
3. **Validate** — verify the new chain before deploying: `openssl verify -CAfile chain.pem newcert.pem` and confirm SAN/CN + dates.
4. **Atomic swap** — write the new cert/key beside the old, then `mv` (atomic on the same filesystem) into place so nginx never reads a half-written file.
5. **Verify** — `nginx -t` then `nginx -s reload` (zero-downtime); confirm live with `openssl s_client -connect host:443 | openssl x509 -noout -dates`.
6. **Rollback plan** — keep the previous cert/key one version back; if the new cert fails verification, `mv` the old pair back and reload.
7. **Audit** — record who rotated, when, the new serial/fingerprint, and expiry in the change log / secrets manager.

### What OCSP stapling buys you
OCSP stapling lets the server fetch and *staple* a signed, time-stamped CA revocation proof to the TLS handshake, so the client doesn't have to make its own OCSP call to the CA — that's faster and stops the CA from learning who visits the site. It's disabled here because the cert is **self-signed**: there's no CA/OCSP responder to staple from, so `ssl_stapling` is a no-op. In production with a publicly-trusted cert it's a clear win and effectively mandatory for good TLS posture.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used:** OWASP ModSecurity v3.0.16 (via `owasp/modsecurity-crs:nginx-alpine`) — chosen over
  Coraza because the OWASP CRS docs/examples are richer for ModSecurity, per the lab's own guidance.
- **OWASP CRS version:** 3.3.10 (the version this image ships; rule 942100 used below is identical in CRS 4.x).
- **Paranoia level:** 1 · `SecRuleEngine On` (blocking) · inbound anomaly threshold 5.

### Attack payload
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded `%27%20OR%201=1--`)

### Before WAF (plain Nginx, `:443`)
```
no-waf (:443): HTTP 500
```
The request **passes the proxy** and reaches Juice Shop, which 500s while processing the injection —
Nginx alone does nothing about the payload.

### After WAF (`:8443`)
```
with-waf (:8443): HTTP 403
```
Blocked at the edge before it ever reaches the app.

### Audit log excerpt (the rule that fired)
```json
"messages":[
 {"message":"SQL Injection Attack Detected via libinjection",
  "details":{"ruleId":"942100",
             "file":".../rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
             "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
             "tags":["attack-sqli","paranoia-level/1","OWASP_CRS","PCI/6.5.2"]}},
 {"message":"Inbound Anomaly Score Exceeded (Total Score: 5)",
  "details":{"ruleId":"949110"}}]
```
Rule ID **942100** — *SQL Injection Attack Detected via libinjection*; it pushed the inbound anomaly
score to 5, which rule **949110** (blocking evaluation) turned into the 403.

### Tradeoff analysis
The WAF buys a **generic, signature/anomaly-based edge filter** that catches whole *classes* of attack
(SQLi, XSS, path traversal) on traffic the SAST/DAST/Conftest gates never saw — including zero-days in
dependencies and payloads aimed at endpoints those gates don't cover — and it does so at runtime, in
front of the app, with no code change. It **costs** false positives (climbing paranoia levels flags
legitimate traffic — e.g. a user whose input looks like an injection), extra ops (rule tuning, an audit
log to watch, another cert/config to manage), and latency per request. I would **not** deploy a WAF in
front of a purely internal, single-tenant service with no untrusted input (it's pure overhead there),
or as a substitute for fixing the actual vulnerability — a WAF is defense-in-depth, not a patch.
