# Lab 11 — Edge Hardening with a Reverse Proxy

Stack: Juice Shop **v20.0.0** (no published port, `expose: 3000` only) behind **nginx 1.30.6** (OpenSSL 3.5.9), self-signed cert for `CN=localhost`. Raw outputs of every command are in `labs/lab11/results/`.

Port note: host port 80 is already taken on this machine by another container, so the HTTP listener is published as **`8088:80`**. HTTPS stays on **443**, which means the redirect target `https://$host$request_uri` is correct without carrying a port. All HTTP URLs below use `:8088`.

Config: [`labs/lab11/reverse-proxy/nginx.conf`](../labs/lab11/reverse-proxy/nginx.conf).

## Task 1

### Redirect

```
$ curl -sI http://localhost:8088/some/path?x=1 | head -3
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/some/path?x=1

$ curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' -X POST http://localhost:8088/rest/user/login
308 -> https://localhost/rest/user/login
```

**308**, not 301. Both are permanent and cacheable, but 301 lets clients rewrite a POST into a GET when they follow it (and browsers do), so a form or API call that hits `http://` silently loses its body. 308 is defined to keep the method and body, so `POST /rest/user/login` stays a POST after the redirect. Every client that matters today understands 308, so there is no compatibility reason left to pick 301. Path and query string are preserved.

### TLS 1.3 negotiation

```
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

TLS 1.2 still works and lands on an ECDHE + AES-GCM suite (`ECDHE-RSA-AES256-GCM-SHA384`, `results/tls12.txt`).

### What the server offers (testssl.sh 3.2.4, its own TLS stack)

```
 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

TLS 1.0 and 1.1 are not offered by the server, proven by a scanner that can still speak them, not by local OpenSSL refusing to try.

### The six headers, as returned

```
$ curl -skI https://localhost | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

All six are added with `always`, and I checked that they survive error responses: the same grep returns 6 matches on a `500` from Juice Shop (`results/headers-error.txt`) and on the proxy's own `429` (`results/headers-429.txt`). Upstream copies of these headers are removed with `proxy_hide_header`, so the browser never sees two conflicting values. I dropped `preload` from the starter's HSTS: preload is a commitment to the browser preload list for a real registrable domain, and it means nothing for `localhost` with a self-signed cert. HSTS is sent only on the HTTPS server, since browsers ignore it over plain HTTP.

### Why Report-Only

Enforcing this policy today would break Juice Shop. Its `index.html` pulls Material fonts from `fonts.googleapis.com` / `fonts.gstatic.com`, which `style-src 'self'` and `default-src 'self'` (no `font-src`) both block, so every icon would turn into its ligature text; it has inline `<style>` blocks and Angular injects more at runtime; and it talks to its backend over socket.io, so `connect-src` has to allow the WebSocket explicitly to be safe across browsers. Anything not listed is blocked, so the visible result would be broken icons and layout and dead real-time notifications (challenge solved toasts). The policy as written is also weak (`'unsafe-inline'` and `'unsafe-eval'` in `script-src`), so enforcing it would add breakage without much protection against XSS. The way to enforcement: add a `report-to`/`report-uri` endpoint and collect violations from real traffic for a couple of weeks, fix or explicitly allow each legitimate source, replace `'unsafe-inline'` with nonces or hashes (Angular supports a CSP nonce) and remove `'unsafe-eval'`, then ship the tightened policy as Report-Only again until the reports are quiet, and only then switch to `Content-Security-Policy`, keeping the reporting endpoint so regressions show up.

## Task 2

### Rate limit on login

```nginx
# http {}
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
# server {} -> location = /rest/user/login {}
limit_req zone=login burst=5 nodelay;
```

**Rate 10 requests/minute per client address (one token every 6 s), burst 5, `nodelay`.** The limit is on the exact location `= /rest/user/login` only, not the whole site.

```
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login \
    -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'; done; echo
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

1 request + 5 burst reach Juice Shop and get `401` (wrong credentials); requests 7–14 are answered by nginx with `429`, not the default `503`. The error log records it:

```
[warn] limiting requests, excess: 5.839 by zone "login", client: 172.18.0.1, ... "POST /rest/user/login HTTP/1.1"
```

Fourteen requests to `/rest/products/search` in the same second all return `200` (`results/not-limited.txt`), so the rest of the site is not affected.

### Connection limit per client address

```nginx
limit_conn_zone $binary_remote_addr zone=perip:10m;   # http {}
limit_conn_status 429;
limit_conn perip 30;                                  # HTTPS server {}
```

Proof: I paused the Juice Shop container so every request hangs on the backend, then opened 35 concurrent HTTP/1.1 connections:

```
$ docker compose pause juice
$ seq 1 35 | xargs -P 35 -I{} curl -sk --http1.1 -o /dev/null -w '%{http_code}\n' "https://localhost/rest/products/search?q={}" | sort | uniq -c
      5 429
     30 504
[warn] limiting connections by zone "perip", client: 172.18.0.1, ...
```

Exactly 30 got through (and then timed out, see below), the 5 over the limit were refused at once with `429`. 30 is deliberately not tiny: with HTTP/2 each concurrent stream counts against `limit_conn`, and the SPA loads many assets in parallel on first visit.

### Ciphers

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
ssl_prefer_server_ciphers on;
```

`ssl_ciphers` only governs TLS 1.2 (ECDHE + AES-GCM, CHACHA20 removed from the starter list); the TLS 1.3 list is set with `ssl_conf_command Ciphersuites`. A TLS 1.3 suite outside the list is refused by the server:

```
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure'
1
... ssl/tls alert handshake failure ... SSL alert number 40

$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
```

Alert 40 (`handshake_failure`) comes from the server, because the client offered only CHACHA20 and the server has nothing in common with it; the same client with an allowed AES-GCM suite connects fine. The TLS 1.2 `ECDHE-RSA-CHACHA20-POLY1305` is refused the same way (`results/tls12-chacha.txt`).

### Timeouts

| Directive | Value | What it protects against |
|---|---|---|
| `proxy_connect_timeout` | 5s | A dead or unreachable backend: nginx gives up on the TCP handshake quickly instead of holding the client and a worker connection. |
| `proxy_send_timeout` | 10s | A backend that stops reading the request (full receive buffer, stuck event loop): nginx stops waiting between two writes. |
| `proxy_read_timeout` | 30s | A hung backend that accepted the request but never answers (slow query, deadlock): the client gets a `504` instead of waiting forever, and the connection slot is freed. |
| `client_header_timeout` / `client_body_timeout` | 10s | Slowloris / slow POST: a client that trickles headers or body to pin connections. |
| `send_timeout` / `keepalive_timeout` | 10s | Slow readers and idle keep-alive connections holding sockets. |

The read timeout actually firing (backend paused with `docker compose pause juice`):

```
$ curl -sk -o /dev/null -w 'status=%{http_code} time_total=%{time_total}s\n' https://localhost/rest/products/search?q=x
status=504 time_total=30.045311s

[error] upstream timed out (110: Operation timed out) while reading response header from upstream, client: 172.18.0.1, ... upstream: "http://172.18.0.2:3000/rest/products/search?q=x"
```

`504` after 30.0 s, which is exactly `proxy_read_timeout`. The client header timeout fires too: a TLS connection that sends `GET / HTTP/1.1`, `Host:` and then half a header line and stops is closed by nginx and logged as `408` with `rt=8.995` (`results/timeout-header.txt`).

### OCSP stapling

Stapling saves the client a separate round trip to the CA's OCSP responder during the handshake: the server fetches the signed revocation status itself, caches it, and hands it over inside the TLS handshake. That is faster, more reliable (no handshake stall if the responder is slow), and more private, because the CA no longer learns which sites each client visits. I left it **off** here: the certificate is self-signed, there is no issuer OCSP URL to query, so `ssl_stapling on` would only produce warnings. With a publicly trusted certificate I would enable it with `ssl_stapling_verify on`, a `resolver` and the issuer chain in `ssl_trusted_certificate` (left commented in the config). Note that Let's Encrypt has dropped OCSP URLs from its certificates, so for those stapling is moot and revocation relies on CRLs and short lifetimes.

### Certificate rotation runbook (zero failed requests)

1. **Get the new pair** into the cert directory under *new* names (`localhost.new.crt`, `localhost.new.key`), permissions readable by the nginx user (`644` on the bind mount here; `640` with group `nginx` in production).
2. **Check the pair before touching anything:** the cert and key moduli must hash the same (`openssl x509 -noout -modulus -in new.crt | openssl sha256` vs `openssl rsa -noout -modulus -in new.key | openssl sha256`), the chain must be complete, the SAN must cover the hostname, and `notAfter` must be in the future.
3. **Keep the old pair** (`localhost.old.*`) for rollback.
4. **Swap atomically** with `mv` (rename on the same filesystem, so nginx never reads half a file), cert and key together.
5. **`nginx -t && nginx -s reload`**: config test first, then a graceful reload. New workers load the new cert, old workers finish their in-flight connections and exit; no listening socket is closed, so no request fails.
6. **Verify the new cert is live** from outside, by serial/fingerprint: `echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -serial -enddate -fingerprint -sha256`, and compare with `openssl x509 -noout -serial -in localhost.crt` on disk. In production, check every node behind the load balancer, not just one.
7. **Rollback** if anything is wrong: move `localhost.old.*` back and reload again. Delete the old key only after the new cert has been serving cleanly for a while.

I ran this against the live proxy with 300 requests in flight during the swap (`results/cert-rotation.txt`):

```
## before   serial=64FCFEA06F4D202145C5972D276F6365B9EB6DD5
## 2. new pair matches (modulus hashes equal): e941bd8f...470d / e941bd8f...470d
## 4. nginx: configuration file /etc/nginx/nginx.conf test is successful
## 5. requests during rotation:   300 200
## after    serial=33429675BBFE458F0AFB9884A91FA99CE95D9107
## file on disk serial=33429675BBFE458F0AFB9884A91FA99CE95D9107
```

300 out of 300 returned `200`, and the server now presents the new serial, which matches the file on disk.

### Getting around a per-address rate limit

The first bypass is simply having many addresses: a botnet, residential proxy networks or cloud IPv6 ranges (a single `/64` holds 2^64 addresses, and `$binary_remote_addr` keys on the full address) let an attacker spread credential stuffing so thin that each address stays under 10 requests/minute. The second is the opposite problem, that the "address" is wrong: if the proxy ever trusts a client-supplied `X-Forwarded-For` (for example `real_ip_header X-Forwarded-For` with a too-broad `set_real_ip_from`), the attacker rotates a fake header and gets a fresh bucket per request; and behind NAT or a CDN many real users share one address and get throttled together. You can see this in my own logs: every request arrives as `172.18.0.1`, the Docker gateway. At this layer I would add a second limit keyed on the target account (the `email` from the body, via njs or the app) so one account can't be hammered from many IPs, aggregate IPv6 to `/64`, only trust forwarded headers from known proxy ranges, and above it put bot detection / CAPTCHA after N failures, per-account lockout with backoff, breached-password checks and MFA in the application.

## Bonus

WAF: `owasp/modsecurity-crs:nginx` (ModSecurity v3 + **OWASP CRS 4.30.0**, image pinned by digest), defined in [`labs/lab11/waf/docker-compose.override.yml`](../labs/lab11/waf/docker-compose.override.yml). It joins the same compose project, proxies to `http://juice:3000`, is published on **9443** next to the plain proxy on 443, and runs with `MODSEC_RULE_ENGINE=On` (blocking), paranoia level 1, inbound anomaly threshold 5. Juice Shop itself still has no published port, so it is reachable only through one of the two proxies.

```bash
cd labs/lab11
docker compose -f docker-compose.yml -f waf/docker-compose.override.yml up -d
```

### Same request, both paths

```
# GET /rest/products/search?q=%27%20OR%201%3D1--   (q=' OR 1=1--)
plain proxy https://localhost      -> 500
WAF         https://localhost:9443 -> 403
# same request without payload
plain proxy -> 200
WAF         -> 200
```

The plain proxy forwards the payload and Juice Shop's vulnerable search query breaks with a database error (`500`), so the injection reached the database. The WAF answers `403` and the request never gets to the app. Normal search works through both.

### Rule that fired

From the WAF's JSON audit log (`docker compose logs waf`, `results/waf-rules.txt`):

```
GET /rest/products/search?q=%27%20OR%201%3D1-- 403
    942100 | SQL Injection Attack Detected via libinjection | Matched Data: s&1c found within ARGS:q: ' OR 1=1--
    949110 | Inbound Anomaly Score Exceeded (Total Score: 5) |
```

**942100** runs libinjection's SQL tokenizer over every request argument, cookie and header and matches when the token sequence ("fingerprint") looks like SQL; here `s&1c` = string, logical operator, number, comment, i.e. a quote breaking out of a string followed by `OR 1=1--`. It is a critical rule worth 5 anomaly points. CRS does not block on the match itself: **949110** is the blocking evaluation rule that compares the total inbound anomaly score (5) with the threshold (5) and denies the request.

### False-positive hunt

I sent ordinary traffic through the WAF: the SPA shell, `main.js`, `/api/Products`, searches for `O'Reilly`, `apple juice (1000ml)`, `select`, `drop table lamp`, a login with `o'brien@example.com`, a login with password `P@ss'w0rd<>&;--`, feedback text containing `Select ... ; or drop me a line --` and `<b>html</b>` (`results/waf-false-positives.txt`). All of them passed the WAF; the `500`s in that file come from Juice Shop itself (the same `O'Reilly` search returns `500` through the plain proxy too, and feedback without a captcha id is rejected by the app).

One legitimate request **was blocked**: registering a user whose password is `'Or'1=1Strong!`:

```
POST /api/Users 403
    942100 | SQL Injection Attack Detected via libinjection | Matched Data: s&s found within ARGS:json.password: 'Or'1=1Strong!
    942100 | SQL Injection Attack Detected via libinjection | Matched Data: s&s found within ARGS:json.passwordRepeat: 'Or'1=1Strong!
    949110 | Inbound Anomaly Score Exceeded (Total Score: 10) |
```

That is a valid, strong password, and the user can't sign up with it. Password fields are free-form by design, so they should not be inspected for SQL syntax: the fix is a narrow exclusion such as `SecRuleUpdateTargetById 942100 "!ARGS:json.password" "!ARGS:json.passwordRepeat"` (scoped to `/api/Users` and `/rest/user/login`), not disabling 942100.

### Rolling CRS out in front of a real application

I would start in **DetectionOnly** (`MODSEC_RULE_ENGINE=DetectionOnly`) at paranoia level 1, in front of production traffic, and ship the audit log to the SIEM. For two to four weeks I would review every rule hit, separate attacks from false positives, and write narrow exclusions per rule, per parameter and per path (or use the CRS application exclusion plugins) instead of switching rules off. Then I would switch to blocking with a deliberately high inbound anomaly threshold (for example 50 or 100), so only clear attacks are blocked, and lower it step by step towards 5 while watching 403 rates and support tickets, with a feature flag to fall back to detection-only. Every exclusion goes through code review like any other config, and raising the paranoia level later starts the same cycle again in detection mode.

## Cleanup

```bash
cd labs/lab11
docker compose -f docker-compose.yml -f waf/docker-compose.override.yml down -v
```

`labs/lab11/reverse-proxy/certs/` and `labs/lab11/logs/` are not committed.
