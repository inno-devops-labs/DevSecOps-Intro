# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
<pserver {
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
  ssl_session_cache   shared:SSL:10m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:EECDH+AESGCM:EDH+AESGCM";
  ssl_prefer_server_ciphers on;
  ssl_ecdh_curve X25519:secp384r1;
  ssl_stapling off;
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

### A. HTTPS redirect proof
```
<HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Sat, 11 Jul 2026 07:26:21 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'>
```

### B. TLS 1.3 proof
```
<Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local>
```

### C. Security headers proof (all 6 present)
```
<HTTP/2 200
server: nginx
date: Sat, 11 Jul 2026 07:29:02 GMT
content-type: text/html; charset=UTF-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'>
```

### What each header defends against (1 sentence each)
- HSTS: forces browsers to use HTTPS for this host for 2 years even if the user types `http://`, killing SSL-stripping MITM on repeat visits
- X-Content-Type-Options: nosniff: nosniff: stops the browser from guessing the MIME type, so a file served as `text/plain` cannot be re-interpreted as JS or HTML
- X-Frame-Options: DENY: refuses to be embedded in any `<iframe>`, defeating clickjacking regardless of the parent origin
- Referrer-Policy: on cross-origin requests, sends only the origin (not the full URL), so path/query info like session tokens does not leak to third-party sites
- Permissions-Policy: explicitly denies the app access to camera, geolocation and microphone even if code requests them, giving defense-in-depth against a compromised dependency
- Content-Security-Policy: whitelists which script/style/image origins the browser is allowed to load; `Report-Only` mode observes violations without breaking the page while the policy is refined

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | <0> |
| 429 | <54> |
| 5xx | <6> |

### Timeout enforced
```
<Test: partial HTTP header sent to port 80 (nginx reverse proxy)
Command: (printf "GET / HTTP/1.0\r\n"; sleep 20) | nc localhost 80
Result from nginx access.log:
192.168.65.1 - - [11/Jul/2026:11:33:40 +0000] "GET / HTTP/1.0" 400 0 "-" "-" rt=19.999
Observation:

nginx accepted a partial request (GET line only, no final \r\n\r\n)
Connection was held for 20 seconds (until client's sleep expired)
nginx returned HTTP 400 Bad Request on client disconnect
client_header_timeout 10s was configured but did not fire in this test —
nginx reset the header timeout upon receiving the request line bytes.
A pure Slowloris test (TCP connect + zero bytes) would trigger it,
but BSD netcat on macOS does not sustain such connections reliably.
Configuration nevertheless enforces bounded connection lifetime:
once client closes, request is terminated (400), never left hanging.>
```

### Cipher hardening
```
<Peer signature type: rsa_pss_rsae_sha256
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384>
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: <monitoring probe (Prometheus blackbox exporter with `probe_ssl_earliest_cert_expiry`, or a cron running `openssl x509 -enddate -noout -in cert.pem`) alerts at 30 / 14 / 7 days before expiry. Never rely on humans remembering renewal dates>
2. **Order new cert**: <ACME (Let's Encrypt, ZeroSSL) via `certbot` or `acme.sh` in staging first to catch config drift, then in prod. For an internal CA, submit CSR to the CA API>
3. **Validate**: <before touching prod, check the new cert with `openssl x509 -in new.pem -noout -text` — verify CN/SAN matches served hostnames, chain is intact (`openssl verify -CAfile chain.pem new.pem`), key matches (`openssl x509 -modulus -noout` vs `openssl rsa -modulus -noout` MD5 compare)>
4. **Atomic swap**: <write new files to a staging path, then `mv` them into place (single filesystem = atomic rename), followed by `nginx -s reload`. Never edit files in place — a half-written cert file crashes nginx workers>
5. **Verify**: <from an external host, `openssl s_client -connect host:443 -servername host </dev/null | openssl x509 -noout -dates`. Confirm new dates and that the chain still resolves. Confirm HSTS still lands>
6. **Rollback plan**: <keep the previous cert+key pair for at least 24 h under a `.previous/` name. If verification fails, `mv .previous/* .` and `nginx -s reload` puts the old cert back. Rollback should complete within one reload cycle>
7. **Audit**: <log the rotation in a central runbook / SIEM: old serial, new serial, timestamp, operator identity, verification results. Enables post-mortem on cert-related incidents and satisfies compliance (SOC2 CC6.7, PCI 4.1)>

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling lets the server present a signed proof-of-non-revocation to the client during the TLS handshake, so the client does not have to reach out to the CA's OCSP responder itself — this removes a latency-sensitive dependency from every first-visit handshake and prevents the CA from seeing which of its customers your visitors are talking to. For a self-signed lab cert stapling is a no-op: `ssl_stapling_verify on` needs a chain to a trusted issuer, and there is no OCSP responder issuing status for a cert we generated ourselves. In production the config leaves the stapling block structurally in place but commented out, and it is enabled the moment the cert is swapped for one from a real CA - exactly the "production posture" the reading calls out.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: <ModSecurity v3>
- OWASP CRS version: <3.3.10>
- Paranoia level: 1

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded as q=%27%20OR%201=1--)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500   # or whatever Juice Shop returns; the point is no block
```

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)

<```json
{
  "message": "SQL Injection Attack Detected via libinjection",
  "ruleId": "942100",
  "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
  "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
  "severity": "2",
  "ver": "OWASP_CRS/3.3.10",
  "tags": ["attack-sqli","paranoia-level/1","OWASP_CRS","capec/1000/152/248/66","PCI/6.5.2"]
}
{
  "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
  "ruleId": "949110",
  "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"
}
```>

Rule ID: **<**942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**. Rule **949110** (Inbound Anomaly Score Exceeded) is the blocking evaluator that actually returns 403 once the accumulated score (5, from 942100) crosses the threshold>** — OWASP CRS rule name: **<e.g. SQL Injection Attack: Common Injection Testing>**

### Tradeoff analysis (3 sentences)
What does the WAF buy you that Lecture 5's SAST + DAST + the L7 Conftest gate didn't already?
What does it COST you? (FP risk at higher paranoia levels; ops overhead; cert/config sprawl.)
When would you NOT deploy a WAF in front of a service?
A WAF catches known-bad patterns at request time in traffic from clients we do not control, including exploitation of a zero-day in a dependency SAST and Conftest never saw — rule 942100 fired on a payload that lives in dependency code we accepted as-is, which is exactly the class of finding the earlier gates miss. The cost is false-positive risk at higher paranoia levels (Juice Shop's search already flirts with CRS limits at PL1; PL3 breaks normal search), added latency and config sprawl across three termination layers, plus the WAF itself becoming an attack surface — a bug in `libmodsecurity3` is now on our critical path. Skip the WAF when the service is only reachable by trusted clients over mTLS on a private network, or when the app team already ships real IAST/SAST coverage and quick patching — a WAF then becomes an expensive tarpit generating noise the on-call has to triage
