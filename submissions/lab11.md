# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)
```nginx
# HTTP server — redirect everything to HTTPS with a 308, carrying the header set
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

# HTTPS server — TLS 1.3 only + full header set
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name _;

  ssl_certificate     /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;

  # TLS 1.3 only
  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;    # TLS 1.3 ignores this anyway; explicit for clarity

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
  add_header Cross-Origin-Opener-Policy "same-origin" always;
  add_header Cross-Origin-Resource-Policy "same-origin" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
  ...
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
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
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: RSA-PSS
```
(The `verify error:num=18:self-signed certificate` line is expected — the lab cert is self-signed, so `-k`/insecure is used for all client probes.)

### C. Security headers proof (all 6 present)
```
HTTP/1.1 200 OK
Server: nginx
...
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
All 6 required headers land on the real 200 response: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, and CSP (Report-Only). The upstream's own weaker headers (`Feature-Policy: payment 'self'`) are stripped/overridden at the proxy via the `proxy_hide_header` block.

### What each header defends against
- **HSTS** (`Strict-Transport-Security`): forces the browser to use HTTPS for every future request to this host for 2 years, so an attacker can't strip TLS with an SSL-downgrade/MITM on the first plaintext hop.
- **X-Content-Type-Options: nosniff**: stops the browser from MIME-sniffing a response into an executable type, so a user-uploaded "image" that's actually JavaScript won't be run as script.
- **X-Frame-Options: DENY**: forbids the page from being embedded in any `<iframe>`, killing clickjacking overlays that trick a user into clicking hidden controls.
- **Referrer-Policy: strict-origin-when-cross-origin**: sends only the origin (not the full path/query) on cross-site navigations, preventing leakage of sensitive URL parameters (tokens, IDs) to third-party sites.
- **Permissions-Policy**: explicitly denies the page access to camera, microphone, and geolocation, so a compromised/XSS'd script can't silently request those device APIs.
- **Content-Security-Policy (Report-Only)**: declares which sources scripts/styles/images may load from; in Report-Only mode it observes and reports violations without breaking Juice Shop's inline scripts, letting you tighten the policy iteratively before enforcing.

---

## Task 2: Production Posture

### nginx.conf (rate/conn/timeout/cipher sections)
```nginx
# http {} block
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=conn:10m;

# server {} (443)
# TLS 1.3 cipher suites — MUST use ssl_conf_command, NOT ssl_ciphers (see env notes)
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
ssl_ecdh_curve X25519:secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP stapling (inert on a self-signed cert — documentation-only)
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 1.1.1.1 valid=300s;
resolver_timeout 5s;

limit_conn conn 50;
client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_connect_timeout 5s;
send_timeout 10s;

# login endpoint
location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

### Rate limit proof
60 sequential POSTs to `/rest/user/login` (zone rate 10r/m, burst 5 nodelay):

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 (passed through burst → Juice Shop "unauthorized") | 6 |
| 429 (Too Many Requests — rate limited by nginx) | 54 |
| 5xx | 0 |

The 6 that got through equal burst(5) + 1 baseline token; the remaining 54 were rejected by nginx with `429` (the configured `limit_req_status`) before ever reaching the upstream.

### Timeout enforced
```
Connecting to ::1
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
depth=0 CN=juice.local
...unexpected eof while reading...
```
A partial request (`GET / HTTP/1.0` with no terminating blank line) held open for 15s was cut off by nginx after `client_header_timeout 10s` — the `unexpected eof while reading` is nginx closing the socket fail-closed, exactly the Slowloris defense intended.

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```
Negotiated cipher is `TLS_AES_256_GCM_SHA384` (top of the configured `ssl_conf_command Ciphersuites` list) over an `X25519` ephemeral key-exchange curve — matches the Mozilla Modern profile.

### Cert rotation runbook (7 steps)
1. **Detect expiry**: monitor `notAfter` on the live cert (`openssl x509 -enddate -noout -in localhost.crt`) via a scheduled check / Prometheus `ssl_exporter`; alert at 30/14/7 days remaining. In prod, certbot's renewal timer handles this automatically.
2. **Order new cert**: request the replacement from the CA (ACME `certbot renew`, or an internal PKI CSR) into a *staging* path (`certs/localhost.crt.new`), never overwriting the live file.
3. **Validate**: verify the new cert before it goes live — check the chain (`openssl verify -CAfile chain.pem localhost.crt.new`), confirm CN/SAN, key match (`openssl x509 -modulus` == `openssl rsa -modulus`), and that `notBefore`/`notAfter` are sane.
4. **Atomic swap**: move the validated files into place with an atomic `mv` (or symlink flip) so nginx never sees a half-written cert, then `nginx -t` to test config, then `nginx -s reload` for a zero-downtime graceful reload.
5. **Verify**: re-probe the live endpoint (`openssl s_client -connect host:443` / `curl -vI`) and confirm the new serial/fingerprint and `notAfter` are being served; run `testssl.sh host:443` for a full posture re-grade.
6. **Rollback plan**: keep the previous cert+key in a timestamped backup dir; if step 5 fails, `mv` the old pair back and `nginx -s reload` — recovery is one atomic swap + reload, seconds not minutes.
7. **Audit**: record who rotated, when, old→new serials/fingerprints, and expiry in a change log / ticket; update the monitoring baseline so the next expiry alert tracks the new `notAfter`.

### What OCSP stapling buys you
OCSP stapling has the server fetch a signed, time-stamped "this cert is not revoked" proof from the CA and attach ("staple") it to the TLS handshake, so the client doesn't have to make its own privacy-leaking round-trip to the CA's OCSP responder — it's faster and hides the client's browsing from the CA. It's useful in production because a publicly-trusted cert has a real issuing CA with an OCSP responder URL and a revocation status worth checking. It buys nothing for this lab's self-signed cert: there is no CA, no OCSP responder URL in the cert, and no chain to verify against, so nginx logs a stapling warning and simply serves no stapled response — the directives are present only to show the correct production config.

---

## Environment notes
- Host has no native `openssl`; used the one bundled with Git for Windows (`C:\Program Files\Git\usr\bin\openssl.exe`, OpenSSL 3.2.4) for cert generation and all `s_client` probes.
- **TLS 1.3 cipher config gotcha:** the lab's Task 2 template suggests putting the TLS1.3 suite names in `ssl_ciphers`. That crashes nginx on a TLS1.3-only server with `SSL_CTX_set_cipher_list(...) failed (no cipher match)` — in nginx `ssl_ciphers` only governs TLS ≤1.2 suites, and TLS 1.3 suites must be set via `ssl_conf_command Ciphersuites` (OpenSSL 1.1.1+). Switched to `ssl_conf_command`; nginx then started cleanly and negotiated `TLS_AES_256_GCM_SHA384` as intended.
- The shipped starter `nginx.conf` was already substantially hardened (redirect, headers, login rate-zone). Task work tightened it to the exact spec: TLS 1.3-only (dropped TLS 1.2), the three-suite TLS1.3 cipher list via `ssl_conf_command`, `ssl_ecdh_curve X25519:secp384r1`, `ssl_session_tickets off`, `limit_conn 50`, HSTS `max-age` raised to 63072000 (2y), and the OCSP-stapling documentation block.
- Rate-limit/timeout probes use PowerShell 5.1, which lacks `ForEach-Object -Parallel`; ran the loops through Git Bash instead (`ratelimit-test.sh`, `timeout-test.sh`).
- Ports 80/443 were free on the host, so no remap of the shipped `docker-compose.yml` was needed.
- Bonus (Coraza/ModSecurity WAF + OWASP CRS) not attempted — out of scope per this submission's chosen coverage (Task 1 + Task 2).
