# Lab 11 — BONUS — Submission

> **Environment note:** The shipped `docker-compose.yml` maps **8080/8443** (not 80/443), so all verification commands below target those ports. One config fix was needed beyond the starter: `ssl_ciphers` cannot express TLS 1.3 suites — nginx passes that list to OpenSSL's `SSL_CTX_set_cipher_list`, which only accepts TLS 1.2-and-below names and fails with `no cipher match`. TLS 1.3 suite selection requires `ssl_conf_command Ciphersuites` (which reaches `SSL_CTX_set_ciphersuites`).

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
  server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # TLS 1.3 ONLY
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Cipher hardening (Mozilla Modern, TLS 1.3 suites only)
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_ecdh_curve X25519:secp384r1;

    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling off;

    # Security headers (HSTS only on the HTTPS server)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
  }
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 10:35:46 GMT
Content-Type: text/html
```
308 (not 301) preserves the HTTP method and body on redirect — a 301 lets clients silently downgrade a POST to a GET.

### B. TLS 1.3 proof
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
```

### C. Security headers proof (all 6 present)
```
HTTP/2 200
server: nginx
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
All six required headers land, plus COOP/CORP as extras. Note `server: nginx` with no version — `server_tokens off` strips the version string that would otherwise hand an attacker a CVE-matching target.

### What each header defends against
- **HSTS**: Pins the browser to HTTPS for two years so an attacker on the network can't strip TLS on the victim's *next* visit — it closes the one-request window where a user typing `juice.local` gets served plaintext before the redirect fires.
- **X-Content-Type-Options: nosniff**: Stops the browser from second-guessing our `Content-Type` and executing a user-uploaded file as JavaScript because its bytes happened to look script-ish.
- **X-Frame-Options: DENY**: Blocks any site from loading us in an iframe, killing clickjacking where an invisible overlay tricks a logged-in user into clicking our "delete account" button.
- **Referrer-Policy**: Prevents leaking our full URL (which may carry tokens or IDs in the path) to third-party sites the user clicks through to; cross-origin requests get only the bare origin.
- **Permissions-Policy**: Revokes camera/mic/geolocation at the document level, so even a successful XSS can't turn on the webcam — it's defense-in-depth for when the CSP fails.
- **Content-Security-Policy**: Constrains where scripts and resources may load from, turning most XSS from "attacker runs arbitrary JS" into a blocked console error. Shipped as `Report-Only` here because Juice Shop's frontend relies on inline scripts that a strict `default-src 'self'` would break — the honest production path is Report-Only first, collect violations, then enforce.

---

## Task 2: Production Posture

### Rate limit proof
`limit_req_zone ... rate=10r/m` + `limit_req zone=login burst=5 nodelay` on `/rest/user/login`, 60 concurrent POSTs:

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

The 6× 401 is exactly the expected shape: burst of 5 + 1 immediately-available slot passed through to Juice Shop (which rejected the empty credentials with 401 — proof they reached the app), and the remaining 54 were shed at the proxy with 429. `limit_req_status 429;` is what makes these 429 rather than nginx's default 503 — a meaningful distinction, since 429 tells a well-behaved client to back off while 503 implies our own outage.

### Timeout enforced
Slowloris-style probe: request line sent, header block never terminated, connection held open.
```
192.168.65.1 - - [17/Jul/2026:10:37:25 +0000] "GET / HTTP/1.0" 400 0 "-" "-" rt=19.992 uct=- urt=-
```
nginx terminated the request rather than holding the worker indefinitely. Honest note on the status code: the lab anticipated a 408, and nginx returns 408 only when `client_header_timeout` expires having received *nothing*; once a partial request line has arrived, an incomplete header block is classified as a malformed request and closed with 400. Either way the fail-closed property is what matters and it holds — the connection does not survive.

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```
`ssl_session_tickets off` is deliberate: tickets let a client resume without server-side state, but the ticket key becomes a single secret that, if stolen, retroactively decrypts every session resumed under it. Cache-based resumption keeps the state server-side and preserves forward secrecy.

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor with `openssl s_client -connect host:443 </dev/null | openssl x509 -noout -enddate` scraped into Prometheus (blackbox exporter's `probe_ssl_earliest_cert_expiry`), alerting at 30 days remaining — never rely on the CA's reminder email reaching a mailbox someone still reads.
2. **Order new cert**: Issue via ACME (certbot/lego) against the existing CSR/key policy; automation matters more than the CA choice, since a manual step is the thing that gets skipped at 2am.
3. **Validate**: Before touching the live server, verify the new cert independently — `openssl x509 -noout -text` for SAN coverage and dates, and `openssl verify -CAfile chain.pem cert.pem` to prove the chain builds. A cert with a missing intermediate passes local tests and fails for real clients.
4. **Atomic swap**: Write the new cert/key to a fresh path, then flip a symlink and `nginx -t && nginx -s reload`. Reload keeps existing connections alive on the old cert and serves new ones on the new — no dropped requests. Never `cp` over the live file: nginx can read a half-written key.
5. **Verify**: Re-run the step-3 checks against the live endpoint (`openssl s_client`), confirm the served fingerprint matches the intended one, and run `testssl.sh` for the full posture grade.
6. **Rollback plan**: The previous cert stays on disk at its own path; rollback is flipping the symlink back and reloading — seconds, not a re-issue. This is why step 4 uses symlinks rather than overwriting.
7. **Audit**: Log the issuance (CA, serial, fingerprint, requester, timestamp) to the same system that holds the CT-log monitoring, so an unexpected cert for our domain — issued by someone else — is detectable.

### What OCSP stapling buys you
Without stapling, every visitor's browser makes its own side-channel call to the CA's OCSP responder to ask "is this cert revoked?" — which leaks our visitors' browsing habits to the CA, adds a round-trip to the handshake, and fails open (most browsers soft-fail) exactly when the responder is down. Stapling has *our* server fetch the signed, timestamped OCSP response periodically and hand it to clients inside the handshake: faster, private, and reliable. It's off here because a self-signed cert has no OCSP responder URL and no CA to sign a status response — there is nothing to staple. In production with a real CA it's `ssl_stapling on; ssl_stapling_verify on;` plus a `resolver`, and it should be considered mandatory.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used:** ModSecurity v3 via the official `owasp/modsecurity-crs:nginx` image. Chosen over Coraza per the lab's own guidance — the CRS documentation is richer for ModSec, and the image ships ModSec + nginx + CRS pre-wired, removing the connector-compilation step. (Coraza is the modern Go reimplementation and would be the forward-looking pick for a greenfield deployment; for a 2-point bonus the batteries-included path is the right trade.)
- **OWASP CRS version:** v4.x (bundled with the image)
- **Paranoia level:** 1
- **Rule engine:** `SecRuleEngine On` (blocking, not DetectionOnly)
- **Anomaly thresholds:** inbound 5 / outbound 4 (CRS v4 defaults)
- **Topology:** hardened nginx on **8443** (no WAF) vs WAF → juice on **8444**, so the same payload isolates the WAF's effect.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (nginx alone, :8443)
```
no-waf: HTTP 500
```
nginx proxied the injection straight through. The 500 is stronger evidence than a 200 would have been — it's Juice Shop's SQL engine choking on the malformed query, which proves the payload reached the database.

### After WAF (:8444)
```
with-waf: HTTP 403
```

### Audit log excerpt (the rules that fired)
```
942100 | SQL Injection Attack Detected via libinjection | Matched Data: s&1c found within ARGS:q: ' OR 1=1--
949110 | Inbound Anomaly Score Exceeded (Total Score: 5) |
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**
Blocking rule: **949110** — Inbound Anomaly Score Exceeded.

This is CRS's anomaly-scoring model working as designed: 942100 didn't block on its own, it *contributed* a score of 5 by fingerprinting the payload as SQL (`s&1c` is libinjection's tokenization of `string → operator → comment`). 949110 is the rule that actually returns 403, firing because the accumulated inbound score hit the threshold. That two-stage design is why CRS can run at paranoia 1 without shredding legitimate traffic — a single suspicious signal is rarely enough to block.

### Tradeoff analysis
**What the WAF buys:** SAST (Lab 5) found the injectable sink in `routes/search.ts` and DAST confirmed the endpoint was reachable, but neither *stops* the request — they tell you to go fix code, on a timeline measured in sprints. The Conftest gate (Lab 9) validates deployment posture and knows nothing about a payload's contents. The WAF is the only layer that blocks the live attack in the request path, which makes it the virtual patch that buys time between "we know about the CVE" and "the fix is deployed" — the difference between Log4Shell being an incident and being a Tuesday.

**What it costs:** False positives are the real bill, and they scale with paranoia level — at PL3-4, CRS starts flagging legitimate traffic (rich-text fields, base64 blobs, anything that looks like SQL to a tokenizer), so every escalation demands an audit-log tuning cycle and a per-application exclusion list that becomes its own maintained artifact. Add the ops overhead of another hop in the request path (latency, another config and cert surface, another thing that can fail closed and take the site down with it).

**When NOT to deploy one:** In front of an internal service with no untrusted input — a service-to-service API behind mTLS on a private network, where every caller is authenticated and the payload shapes are fixed by a schema. There the WAF adds latency, an outage vector, and a false-positive budget in exchange for blocking attacks that can't reach it anyway. A WAF earns its keep at the untrusted edge; behind the edge it's usually cargo cult.
