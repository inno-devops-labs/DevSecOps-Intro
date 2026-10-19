# Lab 11 — Edge Hardening with a Reverse Proxy

**Setup:** Windows 11 + Docker Desktop (Docker 29.8.2, Compose v5.5.1). `bkimminich/juice-shop:v20.0.0` behind `nginx:stable-alpine` (nginx/1.30.6, OpenSSL 3). Juice Shop has no published port (`expose: 3000` only). Proxy on 80/443. Self-signed cert `CN=localhost` (with SAN `DNS:localhost, IP:127.0.0.1`), generated with `alpine/openssl`.
Everything was run by `labs/lab11/lab11-run.ps1`; raw output is in `labs/lab11/results/`. Host-side requests go to `127.0.0.1` (on this PC `localhost` resolves to `::1`, which is held by `wslrelay`). `openssl s_client` and `testssl.sh` run in containers on the compose network and target `nginx:443` directly, because `--network host` is not available on Docker Desktop for Windows.

Config: [`labs/lab11/reverse-proxy/nginx.conf`](../labs/lab11/reverse-proxy/nginx.conf). `nginx -t` result: `syntax is ok … test is successful`.

## Task 1 — TLS and headers

### Redirect: 308

```
$ curl -sI http://127.0.0.1/
HTTP/1.1 308 Permanent Redirect
Location: https://127.0.0.1/

$ curl -sk -L -X POST http://127.0.0.1/rest/user/login -d '{}'
final=https://127.0.0.1/rest/user/login code=401 redirects=1
```

I chose **308** over 301. Both are permanent and cacheable, but with 301 a client may change POST to GET when it follows the redirect, and browsers do. With 308 it must repeat the same method and body. The second command proves it: a POST to `http://…/rest/user/login` arrives at the HTTPS login endpoint as a POST (Juice Shop answers 401 for the empty credentials, not 404/405 as it would for a GET). Every client that reaches HTTPS goes there anyway, so we lose nothing. HSTS removes the plain-HTTP hop after the first visit.

### TLS 1.3 handshake

```
$ echo | openssl s_client -connect nginx:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

(TLS 1.2 with the default client offer negotiates `ECDHE-RSA-AES256-GCM-SHA384`.)

### Protocols offered by the server (testssl.sh 3.2.4, which uses its own TLS stack)

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

Ciphers per protocol (`testssl.sh -E`):

```
TLSv1.2
 xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 256   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 256   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLSv1.3
 x1302   TLS_AES_256_GCM_SHA384            ECDH/MLKEM AESGCM      256      TLS_AES_256_GCM_SHA384
 x1301   TLS_AES_128_GCM_SHA256            ECDH/MLKEM AESGCM      128      TLS_AES_128_GCM_SHA256
```

(The ECDSA suites in `ssl_ciphers` do not appear because the certificate is RSA.)

### Security headers as returned by the server

```
$ curl -skI https://127.0.0.1/
HTTP/1.1 200 OK
Server: nginx
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

All six headers are set with `always`, and they really are present on error responses. The 429 from Task 2 carries the same set, as do the 308 redirect and the 404 path (`results/headers-404.txt`, `results/ratelimit-429-headers.txt`). `Server: nginx` carries no version (`server_tokens off`), and Juice Shop's `X-Powered-By` is stripped. HSTS is sent only on 443, because browsers ignore it over plain HTTP. Note on `preload`: it is a statement that we want the domain in browser preload lists. On a real domain, add it only once every subdomain serves HTTPS, because removing a domain from the lists takes months.

### Why CSP is Report-Only, and the path to enforcement

If we enforced this policy today:
- `default-src 'self'` covers scripts, styles and fonts loaded from other hosts. Juice Shop's `index.html` pulls the cookie-consent banner's CSS and JS from `cdnjs.cloudflare.com`, so the banner would disappear, and any embedded third-party content (frames, media) is blocked too, because there is no `frame-src`/`media-src`.
- Removing `'unsafe-inline'`/`'unsafe-eval'` to make the policy meaningful would break the Angular app and the inline handlers several challenges rely on. Kept as is, the enforced policy stops almost no XSS, so enforcing it today would cost features without buying security.
- We do not have a list of what actually breaks: the browser console shows Report-Only violations, but nothing collects them yet.

The process for getting to enforcement:
1. Ship Report-Only with a `report-to`/`report-uri` endpoint, and collect violations from real traffic for a few release cycles.
2. Turn each legitimate violation into an explicit source, and remove the inline scripts and `eval`: move them into files, or use nonces or hashes plus `'strict-dynamic'`.
3. Tighten the Report-Only policy until a full regression/E2E run and a week of production traffic produce no reports.
4. Then switch to `Content-Security-Policy` enforcing, and keep Report-Only running next to it with the next, stricter version of the policy.

## Task 2 — Availability controls

### Login rate limit: status-code sequence

Configuration: `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;` + `limit_req_status 429;` in `http`. The `limit_req zone=login burst=5 nodelay;` line sits **only** in `location = /rest/user/login`.
So the limit is **10 requests/minute per client address (one every 6 s), burst 5, nodelay**.

```
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://127.0.0.1/rest/user/login -d @login-bad.json; done
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

Six requests reach Juice Shop and get 401 (1 at the base rate + 5 burst). From the 7th on, nginx answers **429 Too Many Requests** itself, not 503. nginx `error.log` records it:

```
[warn] limiting requests, excess: 5.929 by zone "login", client: 172.20.0.1, request: "POST /rest/user/login HTTP/1.1"
```

The rest of the site is not limited: 20 back-to-back `GET /rest/admin/application-version` → `200 ×20`.

Connection limit per address: `limit_conn_zone $binary_remote_addr zone=perip:10m;`, `limit_conn perip 20;` in both servers, and `limit_conn_status 429`. It allows at most 20 concurrent connections, or HTTP/2 streams, per client address.

### TLS 1.3 cipher restriction

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";  # TLS 1.2 only
ssl_prefer_server_ciphers on;
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;                                            # TLS 1.3
```

I also removed the CHACHA20 suites from the starter's TLS 1.2 list, so both protocol versions are AES-GCM only.

Proof:

```
$ echo | openssl s_client -connect nginx:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -iE 'alert|failure'
...:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:...:SSL alert number 40
$ ... | grep -icE 'alert|failure'
1

$ echo | openssl s_client -connect nginx:443 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -brief   # control: in the list
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
```

The server answers a ChaCha20-only TLS 1.3 offer with alert 40 (handshake_failure). That means the client really sent the suite and the server refused it. It is not the local `no cipher match` error. On TLS 1.2, `ECDHE-RSA-CHACHA20-POLY1305` and the CBC suite `ECDHE-RSA-AES256-SHA384` are refused the same way. The testssl table above confirms it: only the two AES-GCM suites are offered on each protocol.

### Timeouts

| Directive | Value | What it protects against |
|---|---|---|
| `client_header_timeout` | 10s | Slowloris: a client that opens a connection and sends headers slowly, or never finishes them, to hold a worker connection. |
| `client_body_timeout` | 10s | Slow-POST / R.U.D.Y.: a request body dripped one byte at a time. This is the maximum gap between two reads. |
| `send_timeout` | 10s | Slow-read: a client that stops reading the response, so the proxy has to keep the buffers and connection. |
| `keepalive_timeout` | 10s | Idle keep-alive connections piling up and using up `worker_connections`. |
| `proxy_connect_timeout` | 5s | An upstream that is down or blackholed. Requests fail fast with 502/504 instead of queueing. |
| `proxy_send_timeout` | 30s | An upstream that stops accepting the request body. |
| `proxy_read_timeout` | 30s | An upstream that hangs, for example a slow SQL query or event-loop starvation. Without the timeout, every waiting client keeps a connection open, and the outage spreads to the proxy. |

**The timeout firing**, not just configured (`results/timeout.txt`): open TLS, send the request line and one header, then go silent:

```
$ ( printf 'GET / HTTP/1.1\r\nHost: localhost\r\n'; sleep 40 ) | openssl s_client -connect nginx:443 -quiet
05:49:49 sent 'GET / HTTP/1.1' + 'Host:' and then nothing (no blank line)
...:error:0A000126:SSL routines::unexpected eof while reading
05:49:59 connection closed by nginx after 10s
```

nginx access log for that connection: `"GET / HTTP/1.1" 408 0 … rt=9.999`. The server drops the half-sent request after exactly `client_header_timeout`, with status 408.

### OCSP stapling

With stapling, the server fetches the CA's signed OCSP response itself, caches it, and sends it inside the TLS handshake. The client does not have to make its own round trip to the CA's OCSP responder: that saves latency, avoids a hard dependency on the CA being reachable, and the CA no longer learns which sites the user visits. I left it **off** here (`ssl_stapling off`). The certificate is self-signed, has no Authority Information Access/OCSP URL, and has no issuer chain, so there is nothing to staple, and nginx would only log warnings. With a publicly-trusted certificate, I would enable `ssl_stapling on; ssl_stapling_verify on;` with a `resolver` and `ssl_trusted_certificate` (already in the config, commented out). A caveat: Let's Encrypt ended OCSP in 2025 in favour of CRLs and short-lived certificates, so for LE certificates stapling is moot.

### Certificate rotation runbook (zero failed requests)

The key point: `nginx -s reload` is graceful. The master process loads the new config and certificate and starts new workers. Old workers finish their in-flight requests and exit. Nothing is ever not listening. Steps:

1. **Generate the new key and certificate** (CSR → CA, or here self-signed) in a staging directory, not over the live files: `certs/new/localhost.{key,crt}`.
2. **Check the pair before touching anything:** the public key hash of the certificate and of the key must match (`openssl x509 -noout -pubkey | sha256sum` vs `openssl pkey -pubout | sha256sum`). Also check the subject/SAN, `notAfter`, and that the chain is complete.
3. **Back up the current pair:** `certs/old/`.
4. **Install:** copy the new files over `certs/localhost.{crt,key}`, readable by the nginx user (`644`; the key is `640` with group nginx in production).
5. **Validate the config:** `docker compose exec nginx nginx -t`. If it fails, restore from `certs/old/` and stop.
6. **Graceful reload:** `docker compose exec nginx nginx -s reload`. **Not** `docker compose restart`, which drops connections.
7. **Verify the new certificate is live** from a client: `openssl s_client -connect host:443 </dev/null | openssl x509 -noout -serial -enddate -fingerprint -sha256`. Compare with step 2, then check the error log and the 5xx/handshake-error rate.
8. Keep `certs/old/` until the next rotation for rollback (steps 4–6 in reverse), then delete it.

I ran this runbook under load: a container sending back-to-back HTTPS requests to `https://nginx/rest/admin/application-version` for 25 s, with steps 1–7 done in the middle of it:

```
before: serial=5C9309A2F6C7F167EFF7E685478545E9B87E9195  notAfter=Nov 18 05:49:28 2026 GMT  SHA256=A3:C0:8F:…:4D:29
step 2: pubkey sha256 (cert) = ed012b65…61a1ce = pubkey sha256 (key)
step 5: nginx -t → syntax is ok, test is successful
step 6: reloaded 08:50:39
after:  serial=712A1588FCD8D95AF1496B179A7C2C2E234FF3CC  notAfter=Jan 17 05:50:38 2027 GMT  SHA256=3B:99:75:…:CA:7C
load during rotation: 1849 x 200   (0 failures)
```

### Getting around a per-address rate limit

1. **Spread the attack over many addresses:** residential proxy networks, botnets, Tor exit nodes, or IPv6. One /64 gives an attacker 2^64 source addresses, and `$binary_remote_addr` keys each one separately. This is how credential stuffing works in practice: thousands of IPs, a handful of attempts each.
2. **Sit behind addresses we cannot afford to limit:** a corporate NAT, a carrier-grade NAT, or a CDN. Then either we throttle many legitimate users together, or we raise the limit until it no longer bites. Closely related: if the key were taken from a client-controlled header (`X-Forwarded-For` without `set_real_ip_from` restricted to trusted proxies), an attacker would just rotate a fake header value. That is why this config keys on `$binary_remote_addr`, and only trusts XFF behind a known edge.

What I would add:
- At this layer: a second `limit_req` zone keyed on the **target account**, for example the login email extracted with `njs`/Lua, or by the app, so that 1000 IPs against one account still trip the limit. Also aggregate IPv6 to the /64 prefix for the key.
- Above it: an edge/CDN bot-management or WAF (CRS, IP reputation, ASN/Tor lists), and in the app, progressive delays or lockout per account, CAPTCHA after N failures, MFA, and breached-password checks.

## Bonus — A WAF that catches what the proxy forwards

[`labs/lab11/waf/docker-compose.override.yml`](../labs/lab11/waf/docker-compose.override.yml) adds `owasp/modsecurity-crs:nginx` (ModSecurity v3 + **OWASP CRS 4.30.0**) to the same compose project. It runs with `BACKEND=http://juice:3000`, `MODSEC_RULE_ENGINE=On` (blocking; `DetectionOnly` is the log-only mode), paranoia level 1 and inbound anomaly threshold 5, published on **8880**, next to the plain proxy on 443:

```
$ docker compose -p lab11 -f docker-compose.yml -f waf/docker-compose.override.yml ps
lab11-juice-1   bkimminich/juice-shop:v20.0.0   juice   3000/tcp
lab11-nginx-1   nginx:stable-alpine             nginx   0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
lab11-waf-1     owasp/modsecurity-crs:nginx     waf     0.0.0.0:8880->8080/tcp

$ docker compose port juice 3000      -> no published port ("invalid IP:0")
$ curl http://127.0.0.1:3000/          -> 000 (connection refused)
```

The app is reachable only through nginx (443) or the WAF (8880).

### Same payload, both paths

```
$ curl -sk "https://127.0.0.1/rest/products/search?q=%27%20OR%201%3D1--"     # plain proxy
500   <title>Error: SQLITE_ERROR: incomplete input</title>

$ curl -s  "http://127.0.0.1:8880/rest/products/search?q=%27%20OR%201%3D1--" # WAF
403   <h1>403 Forbidden</h1>
```

The hardened proxy forwards the injection, and Juice Shop leaks a raw SQLite error (500). That is the error-based SQLi the app is built to have. The WAF stops the request before it reaches the app.

### The rule that fired (WAF log)

```
"message":"SQL Injection Attack Detected via libinjection","ruleId":"942100",
"file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
"data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--","severity":"2","ver":"OWASP_CRS/4.30.0"

ModSecurity: Access denied with code 403 (phase 2). ... [id "949110"]
[msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [uri "/rest/products/search"]
```

**942100** runs every request argument through **libinjection**, a tokenizer that parses the value as SQL and compares the token sequence against fingerprints of known injections. Here the fingerprint is `s&1c`: string, operator, number, comment. That is exactly `' OR 1=1--`, a quote that closes the string, a tautology, and a comment that cuts off the rest of the query. Rules in CRS 4 do not block by themselves. 942100 is CRITICAL and adds 5 to the anomaly score. **920350** ("Host header is a numeric IP address", +3, because we call `127.0.0.1`) adds 3 more. **949110** then compares the total against the threshold, 8 ≥ 5, and returns the 403.

### False-positive hunt

The same legitimate requests went through both paths (`results/fp-hunt.txt`), logged in as `jim@juice-sh.op`:

| Request | Proxy | WAF |
|---|---|---|
| `GET /` | 200 | 200 |
| `GET /main.js` | 200 | 200 |
| `GET /rest/products/search?q=apple` | 200 | 200 |
| `GET /rest/products/search?q=select juice` | 200 | 200 |
| `GET /rest/products/search?q=O'Reilly` | 500 | 500 |
| `GET /api/Products/1` | 200 | 200 |
| `POST /rest/user/login` (real credentials) | 200 | 200 |
| `POST /rest/user/login`, password `Xk9'#;--Pa$$w0rd!` | 401 | 401 |
| `GET /rest/basket/2` (own basket) | 200 | 200 |
| **`PUT /api/BasketItems/4 {"quantity":2}`** | **200** | **403** |
| `POST /api/Feedbacks` with `-- ; ' &` in the text | 500 | 500 |

**False positive found:** changing the quantity of an item in your own basket works through the proxy (200) but is blocked by the WAF:

```
"message":"Method is not allowed by policy","ruleId":"911100",
"match":"Matched \"Operator `Within' with parameter `GET HEAD POST OPTIONS' against variable `REQUEST_METHOD' (Value: `PUT')"
... [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [uri "/api/BasketItems/4"]
```

CRS's default `tx.allowed_methods` is `GET HEAD POST OPTIONS`. Juice Shop's REST API uses `PUT` and `DELETE` (basket quantity, addresses, cards). So the basket breaks for every user in blocking mode. The fix is to tune the setting, not to disable the rule: `ALLOWED_METHODS="GET HEAD POST OPTIONS PUT PATCH DELETE"`, or a scoped exclusion for `/api/*`.

Other observations:
- **920350 fires on every request** (14×), because clients use an IP as Host. It is noise, worth 3 points, and it lowers the margin for everything else. With a real hostname it disappears. Otherwise exclude it for that vhost.
- The password with `'`, `#`, `;`, `--` was **not** blocked. libinjection did not flag it, which matters, because blocking strong passwords is a classic CRS false positive at PL2+. The `-- ; ' &` feedback text also passed. Its 500 is Juice Shop rejecting a feedback without a CAPTCHA, the same through both paths.
- **False negative:** `q=O'Reilly` produces the same SQLite 500 through both paths. A single apostrophe is legitimate input, so CRS rightly lets it pass, but it shows the app is injectable with input the WAF will never block. The WAF reduces exploitability; it does not fix the parameterised-query bug.

### Rolling CRS out in front of a real application

Turning on blocking mode on day one is how this PUT false positive becomes an outage and the WAF gets switched off. I would roll it out in four phases:
1. **Detection only first.** Deploy with `MODSEC_RULE_ENGINE=DetectionOnly`, paranoia level 1, and the full audit log shipped to the SIEM. Run it for 2–4 weeks of real traffic, including a full E2E/regression run, so every hit is logged and none is blocked.
2. **Tune on the evidence.** Triage hits per rule and per endpoint. Fix genuine issues in the app. Write narrow exclusions in `REQUEST-900`/`RESPONSE-999` files, scoped per rule, URI and parameter (e.g. allow PUT/DELETE, exclude a rich-text field from 941xxx), never global `SecRuleRemoveById`. Keep the exclusions in git with a reason for each.
3. **Block with a high threshold.** Switch to blocking with a high inbound anomaly threshold, for example 50 or 25, so only blatant attacks with many matched rules are blocked. Lower it step by step (25 → 10 → 5) while watching the 403 rate and support tickets, with a feature flag/env var to fall back to DetectionOnly quickly. Optionally canary per vhost or per percentage of traffic.
4. **Then raise coverage.** Once PL1 at threshold 5 is quiet, consider PL2 for sensitive endpoints such as login and payment. Re-run the false-positive suite in CI on every app release and every CRS update, so new API routes do not regress into blocked requests.
