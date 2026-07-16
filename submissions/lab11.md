# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)
```nginx
  # HTTP server (redirect to HTTPS)
  server {
    listen 8080;
    listen [::]:8080;
    server_name _;
    return 308 https://$host:8443$request_uri;
  }

  # HTTPS server
  server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 10m;
    ssl_session_cache   shared:SSL:10m;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Security headers (all with `always`)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    location / {
      proxy_pass http://juice;
    }
  }
```

### A. HTTPS redirect proof
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Thu, 16 Jul 2026 13:52:47 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

### B. TLS 1.3 proof
Can't use SSL_get_servername
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256

### C. Security headers proof (all 6 present)
HTTP/2 200
server: nginx
date: Thu, 16 Jul 2026 13:52:57 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Thu, 16 Jul 2026 13:44:43 GMT
etag: W/"26af-19f6b2c2864"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

All six required headers are present on a real 200 response (HSTS, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Permissions-Policy, CSP-Report-Only), plus two extras the starter
config adds (COOP, CORP). Note the redirect response in (A) also carries the headers except HSTS,
which is deliberately scoped to the HTTPS server only.

### What each header defends against (1 sentence each)
- **HSTS**: Forces the browser to speak HTTPS to this host for the next two years, killing
  SSL-stripping attacks where a network attacker downgrades the victim's first plaintext request
  before the redirect can fire.
- **X-Content-Type-Options: nosniff**: Stops the browser second-guessing the declared Content-Type,
  so an attacker-uploaded file served as `text/plain` cannot be re-interpreted and executed as
  JavaScript.
- **X-Frame-Options: DENY**: Forbids any site from embedding these pages in an iframe, defeating
  clickjacking where a victim is tricked into clicking an invisible overlay of the real UI.
- **Referrer-Policy: strict-origin-when-cross-origin**: Sends only the bare origin (not path or
  query) when navigating off-site, so session tokens or IDs sitting in a URL don't leak to third
  parties via the Referer header.
- **Permissions-Policy**: Explicitly revokes camera, microphone and geolocation access for this
  origin and anything it embeds, so an injected script cannot silently request those sensors.
- **Content-Security-Policy (Report-Only)**: Declares which script/style/image origins are
  legitimate so XSS payloads from untrusted origins get flagged; it runs Report-Only here because
  Juice Shop's frontend relies on inline scripts that a strict `default-src 'self'` would break —
  in production you'd iterate on the reports, then switch to enforcing.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

The zone is `rate=10r/m` with `burst=5 nodelay`, so exactly 6 requests were admitted (1 immediate +
5 burst) and the remaining 54 were rejected with `429` before ever reaching the upstream. The 6
admitted requests returned 500 rather than 200 because Juice Shop's `/rest/user/login` expects a POST
body while the probe sends a bodyless GET — irrelevant to the limiter, which is proven by the 54×429.

### Timeout enforced
--- server closed connection after 10s (client_header_timeout = 10s) ---
(no response body — Nginx dropped the connection silently)

A deliberately incomplete request header (`GET / HTTP/1.0\r\nX-Incomplete: ` with no terminating
blank line) was held open on the HTTP listener. Nginx waited exactly 10 seconds — the configured
`client_header_timeout` — then closed the connection without a response. This is the Slowloris
defense failing closed: a client that never finishes its headers cannot hold a worker slot
indefinitely. Note the timeouts were moved into the `http {}` block so they apply to both listeners
(they were originally scoped to the HTTPS server only, leaving port 8080 on Nginx's 60s default).
The probe runs against 8080 because sending plaintext to the TLS port is rejected during the
handshake and never reaches the header-parsing stage.

### Cipher hardening
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384

Both controls confirmed: the negotiated suite is `TLS_AES_256_GCM_SHA384` from the pinned
Mozilla-Modern set, and key exchange uses `X25519` from `ssl_ecdh_curve X25519:secp384r1`.
Implementation note: the lab's suggested `ssl_ciphers TLS_AES_128_GCM_SHA256:...` fails to load with
`SSL_CTX_set_cipher_list(...) failed (no cipher match)` — OpenSSL applies `ssl_ciphers` only to
TLS ≤1.2, so TLS 1.3 suites must be pinned via `ssl_conf_command Ciphersuites`, which is what this
config uses. Session resumption is hardened alongside: `ssl_session_cache shared:SSL:10m`,
`ssl_session_timeout 1d`, `ssl_session_tickets off`.

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor `notAfter` continuously — a cron job or blackbox exporter running
   `openssl s_client -connect host:443 | openssl x509 -noout -enddate`, alerting at T-30 days so
   rotation is planned work rather than an incident.
2. **Order new cert**: Request the replacement from the CA (ACME/certbot for Let's Encrypt, or the
   internal PKI) with the same subject/SANs, generating a **fresh private key** instead of reusing
   the old one.
3. **Validate**: Verify the material off-line before touching the server — the cert parses, the key
   matches (`openssl x509 -modulus | md5sum` vs `openssl rsa -modulus | md5sum`), the chain is
   complete, and dates/SANs are correct.
4. **Atomic swap**: Write the new files alongside the old (`localhost.crt.new`), then swap by rename
   and reload — `nginx -t && nginx -s reload`. Reload keeps existing connections alive; a restart
   drops them.
5. **Verify**: Confirm from outside — `openssl s_client -connect host:443` shows the new serial and
   `notAfter`, TLS 1.3 still negotiates, and the app answers through the proxy.
6. **Rollback plan**: Keep the previous cert/key pair for one rotation cycle; if verification fails,
   rename back and reload — recovery is one rename plus one reload, no CA round-trip needed.
7. **Audit**: Record who rotated what and when (serial, fingerprint, expiry, operator, ticket) so the
   next expiry alert has provenance and the change is traceable in an incident review.

### What OCSP stapling buys you
OCSP stapling has the server fetch its own CA-signed revocation status and attach it to the TLS
handshake, so the browser learns the cert isn't revoked without a separate round-trip to the CA's
responder — removing a latency hit on every fresh connection and stopping the leak of which sites a
user visits to the CA. It also makes revocation checking reliable: without stapling browsers commonly
soft-fail when the responder is slow or unreachable, silently defeating revocation altogether.
None of this applies to this lab: a self-signed cert has no issuing CA, hence no OCSP responder to
query and nothing to staple — so `ssl_stapling off` here is documented but inert. In production with
a publicly-trusted cert it becomes mandatory (`ssl_stapling on; ssl_stapling_verify on;` plus a
`resolver`).

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: **ModSecurity v3** (`owasp/modsecurity-crs:nginx` — libmodsecurity3 3.0.16 +
  ModSecurity-nginx v1.0.4), deployed as a reverse-proxy sidecar in front of the hardened Nginx —
  option (c) from the lab, chosen because the OWASP CRS documentation is richest for ModSec.
- OWASP CRS version: **3.3.10** (929 rules loaded). The lab asks for 4.x; the `:nginx` rolling tag
  resolved to the 3.3.10 build in this environment even after an explicit `docker pull`
  (`Status: Image is up to date`). CRS 4.x requires a dated stable tag (`4-nginx-YYYYMMDDHHMM`),
  which is the form you'd pin in production anyway.
- Paranoia level: **1** (production-safe starting point), inbound anomaly threshold 5.
- Engine: `SecRuleEngine On` (blocking, not DetectionOnly); audit log JSON, parts `ABIJDEFHZ`.
- Topology: `waf:8081` → `nginx:8443` (the Task 1+2 hardened proxy) → `juice:3000`.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded: `q='%20OR%201=1--`)

### Before WAF (Nginx alone)
no-waf: HTTP 500

The payload went straight through the hardened proxy and reached Juice Shop, where it broke the SQL
query and produced a 500 — the injection actually hit the database layer. TLS, HSTS, rate limits and
timeouts don't inspect payload content, so Nginx had no reason to stop it.

### After WAF
with-waf: HTTP 403

### Audit log excerpt (the rules that fired)
From `/var/log/modsec/audit.log` (JSON):
```json
[
  {
    "id": "942100",
    "msg": "SQL Injection Attack Detected via libinjection",
    "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"
  },
  {
    "id": "949110",
    "msg": "Inbound Anomaly Score Exceeded (Total Score: 5)",
    "data": ""
  }
]
```
And the corresponding denial in the error log:
2026/07/16 14:25:12 [error] 505#505: *9 [client 172.21.0.1] ModSecurity: Access denied with code 403
(phase 2). Matched "Operator Ge' with parameter 5' against variable TX:ANOMALY_SCORE' (Value: 5')
[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"]
[id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "2"]
[ver "OWASP_CRS/3.3.10"] [uri "/rest/products/search"],
request: "GET /rest/products/search?q='%20OR%201=1-- HTTP/1.1", host: "localhost:8081"

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**.
Two rules form the chain, which is exactly how CRS is designed: **942100** is the detector — CRS's
libinjection engine fingerprinted the payload as `s&1c` inside `ARGS:q` and added its score to
`TX:ANOMALY_SCORE` — and **949110** in `REQUEST-949-BLOCKING-EVALUATION.conf` is the enforcer that
denies once the inbound score reaches the threshold of 5. Blocking on an aggregate score rather than
any single regex is what lets CRS run at paranoia 1 without one noisy rule causing false positives on
its own.

### Tradeoff analysis
**What the WAF buys:** SAST (Semgrep, Lab 5) found the vulnerable `models.sequelize.query()` string
concatenation in source, and DAST (ZAP) proved it was exploitable — but neither *stops* an attack in
production, and the Conftest gate only validates manifests, never traffic. The WAF is the only layer
that blocked the live request: 500 became 403 and the payload never reached the database. It also
covers code you can't patch today — a no-fix dependency, a legacy endpoint — acting as a virtual
patch while remediation is scheduled.

**What it costs:** false positives. At paranoia 1 the noise is tolerable, but escalating to 3–4 starts
flagging legitimate traffic (Juice Shop's own inline scripts and base64 payloads would trip rules),
and every FP is either a broken user flow or an exclusion rule someone must write and maintain
forever. Add ops overhead: another hop, another config and cert surface, extra latency, and an audit
log nobody reads until an incident.

**When not to deploy one:** in front of a service speaking a protocol CRS can't parse (gRPC, binary
APIs, end-to-end encrypted payloads) — the rules see opaque bytes, so you pay the full cost with none
of the protection. Also never as a substitute for fixing the code: if the SQLi is a one-line
dependency bump away, patch it — a WAF in front of a known-vulnerable endpoint is a delay tactic, not
remediation, and each accepted FP exclusion quietly widens the hole it was meant to cover.
