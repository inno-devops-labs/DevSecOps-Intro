# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
# HTTP server (redirect to HTTPS)
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

# HTTPS server
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name _;

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;
  ssl_session_timeout 1d;
  ssl_session_cache   shared:SSL:10m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;
  ssl_ecdh_curve X25519:secp384r1;
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

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
`308` (not `301`) is deliberate — it preserves the HTTP method across the redirect, which matters
for anything other than a plain GET.

### B. TLS 1.3 proof
```
Can't use SSL_get_servername
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
```
`verify error:num=18: self-signed certificate` is expected — we generated our own cert instead of
getting one from a CA; the handshake still succeeds at `TLSv1.3`.

### C. Security headers proof (all 6 present)
```
HTTP/2 200
server: nginx
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
- **HSTS**: stops SSL-stripping — once a browser has seen this header, it refuses to connect over
  plain HTTP to this origin for 2 years, even if a network attacker tries to force a downgrade.
- **X-Content-Type-Options: nosniff**: stops the browser from guessing a resource's content-type
  and executing attacker-uploaded content (e.g. an "image") as HTML/JS.
- **X-Frame-Options: DENY**: stops the site from being embedded in an `<iframe>`, defeating
  clickjacking attacks that trick users into clicking hidden UI.
- **Referrer-Policy**: stops the full URL (including query params/tokens) from leaking to
  third-party sites via the `Referer` header when a user navigates away.
- **Permissions-Policy**: stops any script on the page — including third-party/injected scripts —
  from silently accessing the camera, microphone, or geolocation API.
- **Content-Security-Policy**: restricts which origins scripts/styles/images/frames can load from,
  so a successful XSS injection still can't exfiltrate data to an attacker's server or run
  arbitrary inline scripts.

---

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

The 6 non-429 responses are `500`s — the first burst of requests (burst=5 + the steady-state rate)
got past the limiter and actually reached Juice Shop, which returned 500 because the test script
sends a bare GET to `/rest/user/login` with no body (the endpoint expects a POST with credentials).
That's expected — the point of this test is the limiter, not a valid login flow: 54/60 requests
never reached the app at all.

### Timeout enforced
Sending a raw `GET /` over a plain (non-TLS) `nc` connection to port 443 produced no output —
because port 443 only speaks TLS, and unencrypted bytes there don't get far enough to test the
*application-layer* timeout. Re-tested properly: opened a real TLS session with `openssl s_client`,
sent a partial HTTP request (headers with no terminating blank line), then waited past the 10s
`client_header_timeout`:
```
Can't use SSL_get_servername
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = juice.local
verify return:1
error:0A000126:SSL routines:ssl3_read_n:unexpected eof while reading
```
The connection was torn down by nginx (`unexpected eof`) after ~10s without a complete request —
`client_header_timeout` correctly fails closed instead of holding the worker open indefinitely
(the slowloris defense).

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

**Debugging note worth keeping:** my first pass explicitly set
`ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;` per the
lab instructions, and nginx refused to start: `SSL_CTX_set_cipher_list(...) failed: no cipher
match`. Root cause: nginx's `ssl_ciphers` directive calls OpenSSL's legacy
`SSL_CTX_set_cipher_list()`, which only understands TLS ≤1.2 cipher names (e.g.
`ECDHE-RSA-AES256-GCM-SHA384`) — TLS 1.3 suite names use a *different* OpenSSL API
(`SSL_CTX_set_ciphersuites()`) that this directive doesn't call on this nginx build. With
`ssl_protocols TLSv1.3;` only and TLS 1.3-format names in `ssl_ciphers`, the legacy API had zero
valid entries to match against. Fix: removed the `ssl_ciphers` directive entirely — TLS 1.3
already negotiates exactly those 3 AEAD suites by default, so there was nothing to configure. The
`openssl s_client` output above confirms the negotiated suite (`TLS_AES_256_GCM_SHA384`) and curve
(`X25519`) match the Mozilla Modern profile regardless.

### Cert rotation runbook (7 steps)
1. **Detect expiry**: monitor certificate expiry with an automated check (e.g. `openssl x509
   -enddate -noout -in localhost.crt`, wired into a cron job or uptime-monitoring tool); alert at
   30 days remaining, page on-call at 7 days.
2. **Order new cert**: for a real domain, `certbot --nginx -d yourdomain.com` (Let's Encrypt) or a
   vendor-issued cert for EV/specialty needs; for internal services, step-ca or an internal CA.
3. **Validate**: `openssl x509 -in newcert.pem -text -noout` to inspect the new cert (CN/SAN,
   validity window), then `openssl verify -CAfile ca.pem newcert.pem` to confirm the chain of
   trust resolves before it ever touches production.
4. **Atomic swap**: keep certs behind a stable symlink (`current.pem -> certs/2026-07-cert.pem`);
   swap the symlink target and `nginx -s reload` — zero-downtime, no dropped connections, since
   reload spins up new workers with the new cert while old workers finish in-flight requests.
5. **Verify in production**: `curl -vk https://yoursite.com | head -1` to confirm the new cert is
   actually being served, and `testssl.sh yoursite.com` (or SSL Labs) to confirm the overall
   posture (protocol/cipher/HSTS) didn't regress.
6. **Rollback plan**: keep the previous cert+key on disk for ~7 days after rotation; if something
   breaks, re-point the symlink to the old cert and `nginx -s reload` — the same atomic mechanism,
   run backwards.
7. **Audit**: log the rotation event (old serial, new serial, timestamp, who/what triggered it) to
   a central log/DefectDojo — so "who rotated this and when" is answerable months later during an
   audit.

### What OCSP stapling buys you
OCSP stapling lets the server (not the client's browser) periodically ask the CA "is this cert
still valid?" and attach that signed proof directly to the TLS handshake, so the browser doesn't
have to make its own round-trip to the CA's OCSP responder on every connection — saving latency and
avoiding a privacy leak (the CA otherwise learns exactly which sites every visitor connects to,
and when). It's genuinely useful for **production** certs, where a real CA runs an OCSP responder
that can be queried and where revocation is a real possibility an attacker could exploit if
checking is skipped. It buys **nothing** for our lab's self-signed cert: there's no CA issuing it,
so there's no OCSP responder to staple a response from — `ssl_stapling` stays `off` here purely
because the mechanism doesn't apply to a cert nobody but us trusts.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used: ModSecurity v3**, via the official `owasp/modsecurity-crs:nginx-alpine` image — an
  all-in-one nginx + libmodsecurity3 + OWASP CRS bundle, rather than hand-assembling
  nginx-connector + CRS from scratch. Chose ModSecurity over Coraza per the lab's own guidance
  (richer CRS documentation/examples; Coraza is ~70% feature-parity as of 2026).
- OWASP CRS version: **3.3.10** (bundled with this image tag; the lab mentions 4.x — this is the
  latest CRS the maintained image ships, and the rule mechanics/IDs used below are unchanged
  between 3.3.x and 4.x for the core SQLi rules).
- Paranoia level: **1** (`PARANOIA=1`, `BLOCKING_PARANOIA=1`), inbound anomaly threshold **5**
  (`ANOMALY_INBOUND=5`) — the production-safe starting point from Reading 11; higher levels need
  weeks of tuning against real traffic before they're safe to enable.
- **Architecture note:** the WAF terminates a plain HTTP listener on port 8080 and proxies
  straight to `juice:3000`, rather than sitting in front of the TLS-terminating Nginx from Task
  1/2. ModSecurity needs to see the decrypted request to inspect payloads, so stacking it in front
  of Nginx would mean either double TLS termination (WAF terminates TLS, re-encrypts to Nginx,
  which re-terminates again) or Nginx forwarding plaintext to the WAF behind it — either is a
  legitimate production pattern, but for this lab's single-payload demonstration I kept the WAF as
  a parallel, directly-comparable path: same backend (`juice:3000`), one path filtered
  (`:8080` through the WAF), one path not (`:443` through plain hardened Nginx, from Task 1/2).

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded: `%27%20OR%201=1--`)

### Before WAF (Nginx alone, port 443, Task 1/2 stack)
```
no-waf: HTTP 500
```
Not a clean "200 OK" — the payload actually reached Juice Shop and broke something server-side
(arguably worse than silently succeeding: it shows the injection touched the query layer). The
point stands regardless: nothing at the Nginx layer inspected or rejected the payload.

### After WAF (port 8080)
```
with-waf: HTTP 403
```
```html
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
```
The request never reached Juice Shop at all.

### Audit log excerpt (the rule that fired)
```
2026/07/17 18:00:23 [error] 531#531: *1 [client 172.19.0.1] ModSecurity: Access denied with code 403 (phase 2).
Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' )
[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"]
[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "2"] [ver "OWASP_CRS/3.3.10"]
[uri "/rest/products/search"], request: "GET /rest/products/search?q=%27%20OR%201=1-- HTTP/1.1"

# From the structured JSON audit entry for the same transaction:
"messages": [
  {
    "message": "SQL Injection Attack Detected via libinjection",
    "details": {
      "match": "detected SQLi using libinjection.",
      "ruleId": "942100",
      "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
      "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
      "tags": ["attack-sqli", "paranoia-level/1", "OWASP_CRS", "PCI/6.5.2"]
    }
  },
  {
    "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
    "details": { "ruleId": "949110" }
  }
]
```

Two rules fired together, which is how CRS's anomaly-scoring model actually works:
- **Rule ID 942100** — *SQL Injection Attack Detected via libinjection* — the detection rule. It
  ran the `ARGS:q` value through libinjection's SQLi parser, which flagged `' OR 1=1--` as a valid
  SQL injection pattern and added points to the transaction's anomaly score.
- **Rule ID 949110** — *Inbound Anomaly Score Exceeded* — the blocking rule. CRS doesn't block on
  the first match; it accumulates a score across every rule that fires, then this rule checks the
  total against the configured threshold (`ANOMALY_INBOUND=5`) and only *then* returns the 403.
  One SQLi match alone hit the threshold exactly (score 5 ≥ 5).

### Tradeoff analysis
The WAF catches something none of the earlier layers do: Semgrep (SAST) only sees code *we*
wrote and can't evaluate a live HTTP request; the L7 Conftest gate only validates K8s manifest
shape (securityContext, capabilities) and has no idea what's inside an HTTP request body; DAST
(ZAP) tests our specific app during a scan window, while the WAF inspects **every** request in
production, in real time, including against endpoints or parameters no one thought to test. The
cost is real: at paranoia level 2+ this exact rule set starts false-positiving on legitimate
inputs (apostrophes in names, SQL-like strings in free-text fields), which is why Reading 11 and
this lab both insist on starting at paranoia 1 and tuning for weeks before escalating — a WAF
that's too aggressive gets disabled by an on-call engineer at 2am, which is worse than not having
one. There's also real ops overhead: another service to patch, monitor, and keep its rule set
current. I would **not** deploy a WAF in front of a service where the team already has fast,
reliable SAST/DAST coverage and low risk tolerance for false positives blocking legitimate
traffic (e.g. an internal admin tool with no public exposure) — the WAF earns its keep specifically
on public-facing, high-traffic surfaces where "block first, tune later" is an acceptable trade and
the blast radius of a missed injection is large.
