# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name _;

  limit_conn conn 50;
  client_body_timeout 10s;
  client_header_timeout 10s;

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;
  ssl_session_timeout 1d;
  ssl_session_cache   shared:SSL:10m;
  ssl_session_tickets off;

  ssl_protocols TLSv1.3;
  ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
  ssl_ecdh_curve X25519:secp384r1;
  ssl_prefer_server_ciphers off;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

### B. TLS 1.3 proof
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof (all 6 present)
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against
- **HSTS**: forces the browser to always use HTTPS for this domain, even if the user types `http://` or clicks an old HTTP link, preventing SSL-stripping downgrade attacks.
- **X-Content-Type-Options: nosniff**: stops the browser from guessing ("sniffing") a file's MIME type, blocking attacks where a malicious file disguised as an image is executed as a script.
- **X-Frame-Options: DENY**: prevents the page from being embedded in an `<iframe>` on another site, defending against clickjacking.
- **Referrer-Policy**: limits how much of the current URL is leaked to external sites via the `Referer` header when a user clicks an outbound link, reducing information disclosure.
- **Permissions-Policy**: explicitly disables browser features (camera, microphone, geolocation) the site doesn't need, shrinking the attack surface if the page is ever compromised by XSS.
- **Content-Security-Policy**: restricts which sources scripts, styles, and images can load from, mitigating the impact of an XSS injection even if one slips through.

---

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 429 | 54 |
| 500 | 6 |

The 500s are expected — these are GET requests to a login endpoint that expects a POST body; the point of this test is that the rate limiter itself engaged (54/60 blocked with 429), not the semantic correctness of unrelated requests that got through.

### Timeout enforced
```
Connecting to ::1
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
A8330000:error:0A000126:SSL routines::unexpected eof while reading
```
An incomplete request (missing the terminating blank line HTTP requires) was sent, then the client waited 15s before doing anything else. Nginx's `client_header_timeout 10s` closed the connection before the 15s elapsed — the abrupt "unexpected eof" is the client observing the server-initiated close.

### Cipher hardening
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Cipher    : TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate `notAfter` dates via an automated check (e.g. `openssl x509 -enddate -noout` run daily by a cron job or a monitoring tool like Prometheus blackbox exporter) that alerts 30 days before expiry.
2. **Order new cert**: Request a new certificate from the CA (Let's Encrypt via certbot in production, or an internal CA) using the same CSR parameters (CN, SANs) as the current cert.
3. **Validate**: Verify the new cert's chain, expiry date, and that the private key matches the public cert (`openssl x509 -noout -modulus | md5sum` vs `openssl rsa -noout -modulus | md5sum`) before deploying.
4. **Atomic swap**: Write the new `.crt`/`.key` files to a staging path, then atomically rename/symlink them into the path Nginx reads from, so there's no window where a half-written file is served.
5. **Verify**: Reload Nginx (`nginx -s reload`, not a full restart, to avoid dropping connections), then re-run the TLS verification commands (`openssl s_client`) against the live endpoint to confirm the new cert is being served.
6. **Rollback plan**: Keep the previous cert/key pair backed up until the new one is confirmed working in production traffic for at least one full day; if anything breaks, atomically swap back the old files and reload.
7. **Audit**: Log the rotation event (old serial number, new serial number, timestamp, operator) to the change-management system for compliance traceability.

### What OCSP stapling buys you
OCSP stapling lets the server proactively attach a signed, time-stamped "this certificate is not revoked" response from the CA to the TLS handshake, so the client doesn't have to make its own separate call to the CA's OCSP responder — this is faster and doesn't leak the client's browsing activity to the CA. It's not meaningful for our self-signed lab cert because there is no CA issuing OCSP responses for it in the first place; stapling only has something to staple when a real, publicly-trusted CA is in the chain, which is why this directive is commented out and documentation-only here.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: **ModSecurity v3** (via the official `owasp/modsecurity-crs:nginx-alpine` image — Nginx + ModSecurity v3 connector + OWASP CRS bundled together, avoiding a manual module compile)
- OWASP CRS version: **3.3.10**
- Paranoia level: **1**

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone, Task 1/2 stack on :443)
```
no-waf: HTTP 500
```
The request reached Juice Shop unmodified; the app itself errored trying to process the malformed query, but nothing blocked it upstream.

### After WAF (ModSecurity sidecar on :8081)
```
with-waf: HTTP 403
```

### Audit log excerpt (the rules that fired)
```json
{"messages":[
  {
    "message":"SQL Injection Attack Detected via libinjection",
    "details":{
      "match":"detected SQLi using libinjection.",
      "ruleId":"942100",
      "file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
      "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
      "tags":["attack-sqli","paranoia-level/1","OWASP_CRS"]
    }
  },
  {
    "message":"Inbound Anomaly Score Exceeded (Total Score: 5)",
    "details":{
      "match":"Matched \"Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' )",
      "ruleId":"949110",
      "file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"
    }
  }
]}
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection** (the detection rule that flagged the payload); the actual 403 block is issued by the separate blocking-evaluation rule **949110** once the accumulated anomaly score crosses the paranoia-level-1 threshold — this two-stage detect-then-score-then-block design is CRS's core mechanism.

### Tradeoff analysis
A WAF catches attack **patterns** at the network edge, independent of the application's own code — Semgrep only sees what's in the source it scanned, ZAP only probes what its scan config covers, and the Lab 7 Conftest gate only checks Kubernetes manifest hardening, so none of them stop a malicious request from ever reaching a vulnerable endpoint at runtime the way the WAF just did. The cost is real: paranoia level 1 already needed a real payload to trigger, and pushing to paranoia 2-4 for stricter coverage sharply increases false positives on legitimate traffic (URLs with quotes, JSON bodies with SQL-like keywords, etc.), which means someone has to actively tune exceptions or the WAF becomes an availability risk of its own; it also adds an extra network hop, another TLS termination point, and another piece of config/certs to keep in sync. A WAF is a poor fit in front of an internal-only service with a small, trusted client set (the ops overhead outweighs the benefit), or as a substitute for fixing the underlying vulnerable code — it's a compensating control, not a replacement for SAST/dependency scanning that would actually eliminate the SQL injection at the source.
