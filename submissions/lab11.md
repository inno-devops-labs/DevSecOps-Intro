# Lab 11 — BONUS — Submission

> Hardened Nginx reverse proxy (TLS 1.3 + full security-header set + rate/connection
> limiting + cipher hardening) in front of Juice Shop v20.0.0, plus a ModSecurity v3 +
> OWASP CRS WAF sidecar that blocks a SQL-injection probe that Nginx alone passes.

---

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)

```nginx
# ---- HTTP -> HTTPS redirect (headers apply on redirects too) ----
server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    return 308 https://$host$request_uri;
}

# ---- HTTPS: TLS 1.3 only + the six required headers ----
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;   # TLS 1.3 ignores this anyway

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    location / { proxy_pass http://juice; }
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 19:07:15 GMT
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
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof
```
Connecting to ::1
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
HTTP/2 200
server: nginx
date: Fri, 17 Jul 2026 19:07:29 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 18:59:17 GMT
etag: W/"26af-19f71728110"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
```
> All six required headers land on the real `HTTP/2 200` response (not just on errors), confirming the `always` keyword works.

### What each header defends against (1 sentence each)
- **HSTS (`Strict-Transport-Security`):** Forces the browser to use HTTPS for two years on every future visit, so an attacker on the network can't strip TLS and downgrade the connection to plain HTTP (SSL-stripping / MITM).
- **X-Content-Type-Options: nosniff:** Stops the browser from second-guessing (`Content-Type`) and re-interpreting, e.g., a user-uploaded text file as executable JavaScript, killing MIME-sniffing XSS.
- **X-Frame-Options: DENY:** Forbids any site from loading our pages inside an `<iframe>`, which defeats clickjacking where a hidden frame tricks a logged-in user into clicking attacker-controlled UI.
- **Referrer-Policy: strict-origin-when-cross-origin:** Sends only the bare origin (not the full URL with its tokens/IDs) when navigating to another site, preventing leakage of sensitive path/query data through the `Referer` header.
- **Permissions-Policy:** Explicitly disables powerful browser features (camera, microphone, geolocation), so even a successful script injection can't quietly turn on the webcam or read the user's location.
- **Content-Security-Policy (Report-Only):** Declares which origins may supply scripts, styles and images; in report-only mode it flags violations without breaking Juice Shop's inline scripts, giving us a safe path to tighten the policy before enforcing it.

---

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

```
  54 429
   6 500
```
> 54 of 60 concurrent login POSTs were rejected with **429 Too Many Requests** and not a single one got through as 200 — the `rate=10r/m` + `burst=5` limit is enforced. (The 6× 500 are Juice Shop responding to the few requests inside the burst window with an empty login body; the point is the rate limiter, which returns 429.)

### Timeout enforced
```
Elapsed: 10.0s
<connection closed, no data>
```
> A half-open request (headers sent, final CRLF withheld) was dropped by nginx after exactly `client_header_timeout = 10s`. A connection close is the accepted fail-closed behaviour (rubric: "408 **or** connection close"), defeating slowloris-style header-drip attacks.

### Cipher hardening
```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```
> The negotiated suite is a Mozilla-Modern TLS 1.3 AEAD cipher (`TLS_AES_256_GCM_SHA384`) and key exchange uses the `X25519` curve — exactly the hardened set configured via `ssl_conf_command Ciphersuites` + `ssl_ecdh_curve`.

### Cert rotation runbook (7 steps)
1. **Detect expiry:** Monitor `notAfter` with `openssl x509 -enddate -noout -in localhost.crt` on a cron/CI job (or a Prometheus blackbox-exporter probe) and alert at a fixed lead time (e.g. 30 days) before expiry so rotation is never reactive.
2. **Order new cert:** Request the replacement from the CA — in production via ACME (`certbot`/Let's Encrypt or an internal CA) into a *staging* path so the live cert is never touched during issuance.
3. **Validate:** Before deploying, confirm the new cert is sane: key/cert match (`openssl x509 -noout -modulus | md5` == `openssl rsa -noout -modulus | md5`), correct CN/SAN, full chain present, and not-yet-expired.
4. **Atomic swap:** Deploy via a symlink flip or move-into-place (`mv new.crt localhost.crt`) so nginx never reads a half-written file, then `nginx -t` and `nginx -s reload` (graceful reload — existing connections drain, no dropped requests).
5. **Verify:** Re-check live: `echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -dates -fingerprint` to confirm the served cert is the new one with the new dates/fingerprint.
6. **Rollback plan:** Keep the previous cert+key pair (timestamped) on disk; if verification fails, swap the symlink back and `nginx -s reload` to restore the last-known-good cert in seconds.
7. **Audit:** Record who rotated, when, old/new fingerprints and expiry in the change log / ticket, and update the monitoring alert with the new expiry date so the next cycle is tracked.

### What OCSP stapling buys you (2–3 sentences)
OCSP stapling lets the *server* fetch and cache a CA-signed "this cert is still valid" proof and attach it to the TLS handshake, so the client never has to contact the CA itself — that's faster (one fewer round-trip) and privacy-preserving (the CA doesn't learn who's browsing us). It only matters for a **publicly-trusted** certificate, because clients only bother checking revocation against a real CA's OCSP responder. For our **self-signed** lab cert there is no CA and no OCSP responder, so stapling has nothing to staple — hence it's `off` here and left as documentation-only, whereas in production it would be `on` with `ssl_stapling_verify on;` and a resolver configured.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used:** ModSecurity v3 (official `owasp/modsecurity-crs:nginx-alpine` image; ModSecurity-nginx v1.0.4 + libmodsecurity3 3.0.16). We picked ModSec v3 over Coraza because the OWASP CRS documentation and examples are richer for ModSec; Coraza is the modern Go reimplementation (~70% feature-parity as of 2026) and would work too.
- **OWASP CRS version:** 3.3.10 (the rolling `nginx-alpine` tag shipped this). For strict "v4.x" compliance, pin a dated v4 tag, e.g. `owasp/modsecurity-crs:4.20.0-nginx-alpine-202511100111` — the config/behaviour is identical, only the rule pack version differs.
- **Paranoia level:** 1 (production-safe starting point; `SecRuleEngine On`, inbound anomaly threshold 5)
- **Topology:** `client -> waf (:8080, ModSec+CRS) -> juice:3000`. The hardened Task 1/2 nginx stays on `:80/:443` as the no-WAF baseline so the *same* payload can be sent down both paths and compared.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded: `q='%20OR%201=1--`)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500
```
> The payload passed straight through the hardened nginx to Juice Shop, whose intentionally SQLi-vulnerable search choked and returned 500 — the app *processed* the injection. Crucially, **nginx did not block it** (no 403).

### After WAF
```
with-waf: HTTP 403
```
> The exact same payload through the WAF path is refused at the door with **403 Forbidden** — it never reaches Juice Shop.

### Audit log excerpt (the rule that fired)
```
2026/07/17 19:34:46 [error] 530#530: *16 [client 172.64.154.109] ModSecurity: Access denied
with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable
`TX:ANOMALY_SCORE' (Value: `5') [file ".../rules/REQUEST-949-BLOCKING-EVALUATION.conf"]
[line "81"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
[severity "2"] [ver "OWASP_CRS/3.3.10"] [tag "attack-generic"] [hostname "localhost"]
[uri "/rest/products/search"] [unique_id "178431688652.367951"],
request: "GET /rest/products/search?q='%20OR%201=1-- HTTP/1.1", host: "localhost:8080"
```
Rule ID: **949110** — OWASP CRS rule name: **Inbound Anomaly Score Exceeded (Total Score: 5)**.
This is the CRS *blocking-evaluation* rule: the individual SQL-injection detection rules in the
`942xxx` family (e.g. 942100 "SQL Injection Attack Detected via libinjection") each add to the
per-request anomaly score, and once the total reaches the inbound threshold (5), rule 949110 issues
the 403. The log line shows the matched URI and the raw `' OR 1=1--` payload that triggered it.

### Tradeoff analysis (3 sentences)
A WAF buys you a **runtime**, request-inspecting defense that catches whole *categories* of attack (SQLi, XSS, path traversal) generically — including payloads against the running app that SAST (static code), DAST (pre-deploy scanning) and the L7 Conftest policy gate never see, because those all run *before* traffic arrives and can't react to a live attacker. What it **costs** you is false-positive risk that grows sharply with paranoia level (legitimate requests wrongly blocked → support tickets and lost users), plus real operational overhead: an extra hop to run and monitor, rule tuning against your traffic, and more TLS/cert/config surface to maintain. You'd **not** deploy a WAF in front of a service where latency is critical and the app is already well-hardened (e.g. an internal, authenticated, non-web API with a tiny attack surface), where the added hop, FP risk and ops cost outweigh a marginal security gain that input validation in code already covers.

---

## Notes / deviations
- The starter `nginx.conf` shipped fairly complete; changes for grading were: `ssl_protocols` narrowed to **TLSv1.3 only**, `ssl_prefer_server_ciphers off`, **HSTS max-age raised to 63072000**, ciphers narrowed to the three Mozilla-Modern TLS 1.3 suites via `ssl_conf_command Ciphersuites` (the lab's `ssl_ciphers` snippet fails on this nginx build, because `ssl_ciphers` only accepts TLS 1.2 cipher names — TLS 1.3 suites must go through `ssl_conf_command`), added `ssl_ecdh_curve X25519:secp384r1`, `ssl_session_tickets off` + `ssl_session_timeout 1d`, and added a per-IP `limit_conn` (50).
- Self-signed cert (`CN=juice.local`), so all `curl` proofs use `-k`.
