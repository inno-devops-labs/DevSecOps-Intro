# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
  # HTTP server (redirect to HTTPS)
  server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Core headers (also on redirects)
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

    # TLS 1.3 only — no TLS 1.2 fallback (Reading 11 / Task 1)
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_ecdh_curve X25519:secp384r1;

    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    ssl_stapling off;   # see Task 2 for why this stays off in the lab

    client_max_body_size 2m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 10s;
    send_timeout 10s;

    limit_conn conn 50;

    # Security headers (include HSTS here only)
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

> **Debugging note — `ssl_ciphers` rejects TLS 1.3 suite names.** The lab asks for `ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;`. Nginx would not start with that line. Error: `SSL_CTX_set_cipher_list(...) failed (SSL: error:0A0000B9:SSL routines::no cipher match)`. Reason: `ssl_ciphers` uses OpenSSL's old cipher-list format (names like `ECDHE-RSA-...`), and it does not understand the new TLS 1.3 suite names. TLS 1.3 suites need a different directive: `ssl_conf_command Ciphersuites ...;`. I removed `ssl_ciphers` and used `ssl_conf_command Ciphersuites ...;` instead. It starts fine and picks the right suite (see proof below).

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof
```
Connecting to ::1
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof (all 6 present)
```
HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
(Two extra headers also show up: `cross-origin-opener-policy` and `cross-origin-resource-policy`. They were already in the starter config. Not required, but they don't hurt.)

### What each header defends against
- **HSTS**: Tells the browser to only use HTTPS for this site, for 2 years. Stops an attacker from downgrading the connection to plain HTTP.
- **X-Content-Type-Options: nosniff**: Stops the browser from guessing a file's type. Blocks tricks like uploading a `.txt` file that the browser runs as `.html` or `.js`.
- **X-Frame-Options: DENY**: Blocks the page from being put inside an `<iframe>` on another site. Stops clickjacking.
- **Referrer-Policy**: Limits how much of the page URL gets sent to other sites when a user clicks a link away from the site.
- **Permissions-Policy**: Turns off camera, microphone, and location access for the page and any embedded content. A hacked third-party script can't ask for device access.
- **Content-Security-Policy**: Limits which sites scripts, styles, and images can load from. Even if an attacker sneaks in a script (XSS), it can't call home to their server. Set to `Report-Only` here, not enforced, because Juice Shop's own frontend uses inline scripts and `eval`, and a strict CSP would break it.

---

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

54 of 60 requests to `/rest/user/login` got blocked with `429`. That's the rate limiter (`limit_req zone=login burst=5 nodelay;` + `limit_req_status 429;`) doing its job. The other 6 got a `500`, not `200` — that's fine, since the test sends plain `GET` requests to an endpoint that expects a `POST` with a JSON body. The point was just to check the limiter fires, and it did.

### Timeout enforced
The lab suggests this test: `echo "GET / HTTP/1.0" | nc localhost 443`. It doesn't actually test `client_header_timeout`. Port 443 only speaks TLS, and sending plain text at it breaks the TLS handshake right away (connection closed in 0.014s, no timeout involved, just an instant SSL error). That tests "what happens if you send garbage to a TLS port," not the timeout we want.

So instead I wrote a small Python script: it does a real TLS 1.3 handshake, sends half of an HTTP request (headers with no blank line at the end, like a Slowloris attack), then just waits:
```
TLS handshake complete at t=0.03s, protocol=TLSv1.3
Sent partial headers at t=0.03s, now waiting for server to act...
Server closed connection (EOF) at t=10.02s
```
The server kept the connection open for about 10 seconds, then closed it. That matches `client_header_timeout 10s;` exactly — the timeout works.

### Cipher hardening
```
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```
(Note: this OpenSSL version, 3.6.1, calls the line `Peer Temp Key` instead of `Server Temp Key` like the lab doc shows. Same thing, just a newer label. It confirms `TLS_AES_256_GCM_SHA384` and `X25519` are in use, which matches our `ssl_conf_command Ciphersuites` and `ssl_ecdh_curve` settings.)

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Run a daily check (`openssl x509 -enddate -noout -in localhost.crt`, or a tool like `cert-manager` or `testssl.sh`). Alert on-call when the cert has less than 30 days left. Don't wait for a browser warning to find out.
2. **Order new cert**: For this lab, just regenerate with the same `openssl req -x509 ...` command. In production, use an ACME client (certbot/Let's Encrypt) or the company's own CA to request a new cert for the same domain.
3. **Validate**: Before touching anything live, check the new cert and key actually match, check the certificate chain, and check it covers all the right domain names.
4. **Atomic swap**: Put the new cert and key in a new file (or a new Secret), then point nginx at the new files and reload with `nginx -s reload`. Never edit the live cert file directly — a client could read it half-written mid-handshake.
5. **Verify**: Right after the reload, run the same checks from Task 1 against the live site — confirm TLS 1.3 works, the new expiry date shows up, and the site still returns 200s.
6. **Rollback plan**: Keep the old cert and key around until step 5 passes. If something goes wrong, just point nginx back at the old files and reload. Don't delete the old cert too early.
7. **Audit**: Write down who rotated the cert, when, and the old/new expiry dates. In this course's setup, that log entry would live next to the DefectDojo engagement or in a CI log, so anyone can check when the cert was last rotated.

### What OCSP stapling buys you
OCSP stapling lets the server attach a signed "this cert is still valid" proof to the TLS handshake, so the browser doesn't need to ask the certificate authority separately. That's faster (one less network round trip) and more private (the CA never sees who's visiting the site). It does nothing here because our cert is self-signed — there's no CA to ask, so there's nothing to staple. That's why `ssl_stapling` stays `off` in this lab, with a comment explaining why, instead of turning it on for show. In real production, with a cert from a real CA, it's a genuine (if now smaller, thanks to short-lived certs) speed and privacy win.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: **ModSecurity v3**, via the official `owasp/modsecurity-crs:nginx-alpine` image (ModSecurity-nginx connector v1.0.4, libmodsecurity3 v3.0.16). The lab suggested ModSecurity over Coraza because the CRS docs have more ModSecurity examples.
- OWASP CRS version: **3.3.10** (what the image ships — one minor version behind the "4.x" the lab mentions, worth noting instead of pretending it's 4.x).
- Paranoia level: **1** (`BLOCKING_PARANOIA=1`, `ANOMALY_INBOUND=5` — the safe default for production, confirmed in the startup log: `Configuring 900000 for BLOCKING_PARANOIA with paranoia_level=1`).

Setup: `labs/lab11/waf/docker-compose.override.yml` adds a `waf` service that sits in front of the already-hardened nginx from Task 1/2 — it doesn't replace it. The WAF handles TLS on ports `8443`/`8080`, runs ModSecurity + CRS, and if a request passes, forwards it to `nginx:443` over its own TLS connection (`BACKEND: "https://nginx:443"`, `PROXY_SSL: "on"`). So anything that gets past the WAF still goes through all of Task 1/2's headers, rate limits, and TLS hardening. Nginx's own ports (80/443) stay open too, as the "no-WAF" baseline to compare against.

The official image had two real bugs I had to work around (both explained in `labs/lab11/waf/docker-compose.override.yml`):
1. **Relative paths in the override file are resolved from the folder you run `docker compose` in (`labs/lab11`), not from the override file's own folder.** I first wrote `../reverse-proxy/certs`, which would be correct relative to `labs/lab11/waf/`, but it actually pointed to a folder that doesn't exist, and nginx couldn't find the cert. Fixed by changing it to `./reverse-proxy/certs`.
2. **The image's env var names don't match its own config.** The image says to use `PROXY_SSL_CERT_FILE`/`PROXY_SSL_CERT_KEY_FILE`, but the actual nginx template looks for `PROXY_SSL_CERT`/`PROXY_SSL_CERT_KEY` (no `_FILE`). Left unset, nginx failed with `unknown "proxy_ssl_cert" variable`. Fixed by setting the correct names directly.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded as `q=%27%20OR%201%3D1--` / `q='%20OR%201=1--`)

### Before WAF (Nginx alone)
```
no-waf: HTTP 500
```
Not just "no block" — the payload actually reached Juice Shop's database and broke the query:
```
Error: SQLITE_ERROR: incomplete input
```
That's even better proof than a plain `200` would be: it shows the raw injection string made it all the way to the database, since none of the Task 1/2 hardening (TLS, headers, rate limits) looks at request content at all.

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```
waf-1 | 2026/07/13 10:15:35 [error] 528#528: *5 [client 192.168.65.1] ModSecurity: Access denied with code 403 (phase 2).
Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' )
[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"]
[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
request: "GET /rest/products/search?q='%20OR%201=1-- HTTP/2.0", host: "localhost:8443"

{"messages":[
  {"message":"SQL Injection Attack Detected via libinjection",
   "details":{"match":"detected SQLi using libinjection.","ruleId":"942100",
              "file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
              "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
              "tags":["attack-sqli","paranoia-level/1","OWASP_CRS","PCI/6.5.2"]}},
  {"message":"Inbound Anomaly Score Exceeded (Total Score: 5)",
   "details":{"ruleId":"949110","file":"REQUEST-949-BLOCKING-EVALUATION.conf"}}
]}
```
Rule ID: **942100** — "SQL Injection Attack Detected via libinjection" (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`). It pushed the anomaly score to 5, which hit the paranoia-level-1 block threshold (rule `949110`), and that's what caused the 403.

### Tradeoff analysis
The WAF gives you something SAST, DAST, and Conftest can't: it blocks bad requests live, in real time, no matter what the app code currently allows. Semgrep and Checkov only check code before deploy. Even ZAP's DAST scan is a one-time check. None of them stop a bad request hitting production right now — the WAF does. The cost: false positives go up fast above paranoia level 1 (normal text with quotes or SQL-like words can get blocked), it's one more thing to run and keep configured (as the two bugs above show), and it adds latency plus a new component that can itself break and take down traffic. You would skip a WAF in front of a purely internal service that only talks to other trusted internal services — there's no untrusted public input to filter, so the WAF's main job doesn't apply, and you're just adding risk and slowdown for nothing.
