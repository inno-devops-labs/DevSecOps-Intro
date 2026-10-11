# Lab 11 — Edge Hardening with a Reverse Proxy

## Setup

The stack is `labs/lab11/docker-compose.yml` with nginx `1.30.5` (`nginx:stable-alpine`) in front of `bkimminich/juice-shop:v20.0.0`. Ports 80 and 443 were free, so no remap was needed. The certificate is a self-signed RSA-2048 for `CN=localhost`, valid 30 days, files `644` so the `nginx` user inside the container can read them. Juice Shop only `expose`s 3000, so `curl http://127.0.0.1:3000/` from the host gets `connection refused` and the app is reachable only through the proxy.

The starter `nginx.conf` already had the redirect, TLS 1.2/1.3, the six headers with `always`, the login `limit_req` zone and the proxy timeouts. I checked each of them against the requirements rather than rewriting them, and changed four things (diff against the starter):

```diff
-  map $http_upgrade $connection_upgrade { default upgrade; '' close; }
+  limit_conn_zone $binary_remote_addr zone=perip:10m;
+  limit_conn_status 429;
+
+  map $http_upgrade $connection_upgrade { default upgrade; '' ''; }
...
     ssl_prefer_server_ciphers on;
+    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
+    ssl_session_tickets off;
...
     send_timeout 10s;
+
+    limit_conn perip 20;
```

- **`limit_conn_zone` / `limit_conn perip 20`:** the per-client-address connection limit the lab asks for, answering 429 instead of 503.
- **`ssl_conf_command Ciphersuites`:** TLS 1.3 restricted to the two AES-GCM suites. `ssl_ciphers` doesn't apply to 1.3.
- **`ssl_session_tickets off`:** without ticket-key rotation, session tickets weaken forward secrecy. The shared session cache already gives resumption.
- **The `map` fix:** the starter sent `Connection: close` to Juice Shop on every normal request. That silently defeated the `keepalive 32` upstream pool, so every proxied request opened a new TCP connection to the app.

## Task 1

### 1. Redirect

```
$ curl -sI http://localhost | head -2
HTTP/1.1 308 Permanent Redirect
Server: nginx

$ curl -sI 'http://localhost/some/path?x=1' | grep -i location
Location: https://localhost/some/path?x=1
```

**308**, not 301. Both are permanent and cacheable, but 301 lets clients turn a `POST` into a `GET` on the redirected request (browsers do), which drops the body. 308 requires the client to repeat the same method and body against the HTTPS URL. A `POST /rest/user/login` sent to port 80 by an old link or a misconfigured client therefore isn't silently turned into a `GET` that fails in a confusing way. The path and query string are kept (`$request_uri`).

### 2. TLS

A TLS 1.3 connection:

```
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

What the server offers, from testssl.sh, which uses its own TLS stack and so actually tries 1.0 and 1.1 against the server:

```
$ docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 https://localhost
 Testing protocols via sockets except NPN+ALPN

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

### 3. The six headers

```
$ curl -skI https://localhost | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

They also survive error responses. The rate-limited `429` from Task 2 still carries `strict-transport-security`, `x-frame-options`, `referrer-policy` and `content-security-policy-report-only`, because every `add_header` has `always`. The `proxy_hide_header` lines strip Juice Shop's own copies, so each header appears once with the proxy's value.

### 4. Why Report-Only, and the path to enforcement

Enforcing this policy today would break Juice Shop's own `index.html`, which I fetched through the proxy:

- the cookie banner is started by an **inline `<script>`** (`window.cookieconsent.initialise(…)`);
- the stylesheet uses an **inline event handler**, `<link … media="print" onload="this.media='all'">`;
- the page loads the VT323 font from **`https://fonts.gstatic.com`** inside an inline `<style>` block, and with no `font-src` the policy falls back to `default-src 'self'`, which blocks it.

The policy only "works" because it allows `'unsafe-inline'` and `'unsafe-eval'` for scripts, which removes most of CSP's protection against XSS, the class of bug Juice Shop is full of. I checked `main.js`, `polyfills.js` and `scripts.js`, and none of them contains `eval(` or `new Function(`, so `'unsafe-eval'` can simply be dropped. The policy also has no `report-uri`/`report-to`, so in Report-Only mode the violations go nowhere, and today the header produces no data.

The path to enforcement:
1. Add a reporting endpoint and collect reports for a release cycle.
2. Move the inline script into a file or give it a hash or nonce, replace `onload=` with a small script, and self-host the font or add `font-src https://fonts.gstatic.com`.
3. Remove `'unsafe-eval'` and then `'unsafe-inline'` from `script-src`, watching the reports go to zero after each step.
4. Only then copy the same policy into an enforcing `Content-Security-Policy` header, keep Report-Only running in parallel with the next, stricter draft, and repeat.

## Task 2

### 1. Rate limit on the login endpoint

```
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

The rate is **10 requests per minute per client address** (one token every 6 s), with **`burst=5` and `nodelay`**. It applies only to the exact location `= /rest/user/login`.

```
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login \
    -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'; done; echo
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

The first request uses the regular token and the next 5 use the burst (`nodelay`, so they are forwarded at once). Juice Shop answers those 6 with 401. From the 7th on, nginx answers **429** itself and the app never sees the request. The error log records each rejection: `limiting requests, excess: 5.966 by zone "login", client: 172.25.0.1`. The same loop against `/rest/admin/application-version` gives 14 × `200`, so the limit doesn't touch the rest of the site.

**Connection limit:** `limit_conn_zone $binary_remote_addr zone=perip:10m;` plus `limit_conn perip 20;` in the HTTPS server, with `limit_conn_status 429`. I tested it with a Python script that opens 25 parallel TLS connections from one address. Each one sends a `POST /api/Feedbacks` with `Content-Length: 100` and then never sends the body, so each request stays open:

```
Counter({'': 20, 'HTTP/1.1 429 Too Many Requests': 5})
timings by status: {'': [10.0], 'HTTP/1.1 429 Too Many Requests': [0.0]}
```

The access log shows `20 × 408` and `5 × 429`, and the error log shows `limiting connections by zone "perip", client: 172.25.0.1`. Connections 21–25 were refused immediately.

### 2. Ciphers

```
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
ssl_prefer_server_ciphers on;
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

A suite outside the TLS 1.3 list is refused by the server:

```
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -iE 'alert|failure'
40978A271B740000:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1599:SSL alert number 40
$ … | grep -icE 'alert|failure'
1
```

Alert 40 (`handshake_failure`) comes from the server, so the ClientHello did go out, unlike the `-cipher TLS_AES_*` test bug. Both listed suites negotiate (`-ciphersuites TLS_AES_128_GCM_SHA256` → `Ciphersuite: TLS_AES_128_GCM_SHA256`, and the same for `_256_GCM_SHA384`). testssl.sh `--cipher-per-proto` confirms it from the server side:

```
TLSv1.3
 x1302   TLS_AES_256_GCM_SHA384            ECDH/MLKEM AESGCM      256      TLS_AES_256_GCM_SHA384
 x1301   TLS_AES_128_GCM_SHA256            ECDH/MLKEM AESGCM      128      TLS_AES_128_GCM_SHA256
```

On TLS 1.2 I left the ECDHE-CHACHA20 suites from the Mozilla "intermediate" list in place for clients without AES hardware. The requirement was about 1.3, and every remaining 1.2 suite is AEAD with forward secrecy.

### 3. Timeouts

| Directive | Value | What it protects against |
| --------- | ----: | ------------------------ |
| `proxy_connect_timeout` | 5s | An app container that's down or not accepting connections. The proxy fails fast with 502/504 instead of holding a worker and the client's connection while it waits for a TCP handshake that won't complete. |
| `proxy_send_timeout` | 30s | An upstream that stops reading the request body (stuck or overloaded), so the proxy doesn't block forever writing a large upload into it. |
| `proxy_read_timeout` | 30s | An upstream that accepted the request but never answers, such as a hung query or event loop. It caps how long each such request holds a connection. |
| `client_header_timeout` | 10s | Slowloris: clients that open a connection and trickle request headers to tie up worker connections. |
| `client_body_timeout` | 10s | Slow-POST (R.U.D.Y.): clients that send headers with a `Content-Length` and then dribble the body, or never send it. |
| `send_timeout` | 10s | Slow readers that never read the response, so the proxy's buffers and connections stay tied up. |
| `keepalive_timeout` | 10s | Idle keep-alive connections that use up connection slots, which together with `limit_conn` keeps a single client's share small. |

Two of them fired:

- **`client_body_timeout`.** In the connection-limit test above, each of the 20 admitted connections was closed **after exactly 10.0 s**, and every one was logged with status **408**.
- **`proxy_read_timeout`.** I froze the app with `docker compose pause juice`. Its TCP stack still accepts connections, but it never answers:
  ```
  $ curl -sk -o /dev/null -w 'paused upstream: HTTP %{http_code} after %{time_total}s\n' https://localhost/rest/admin/application-version
  paused upstream: HTTP 504 after 30.030880s
  ```
  The error log shows `upstream timed out (110: Operation timed out) while reading response header from upstream`. After `docker compose unpause juice` the same request returns 200 again.

### 4. OCSP stapling

Stapling saves the client a separate, often plaintext, request to the CA's OCSP responder during the handshake. That request costs one round trip, fails open in most browsers, and tells the CA which site the user is visiting. Instead the server attaches a recent CA-signed status to the handshake. I left `ssl_stapling off` here, because a self-signed certificate has no issuer, no OCSP responder URL and no chain to verify a response against, so there is nothing to staple. With a publicly trusted certificate I would enable it with `ssl_stapling_verify on` and a `resolver`. One caveat: Let's Encrypt has dropped OCSP in favour of CRLs, so first check whether the CA still runs an OCSP responder at all.

### 5. Certificate rotation runbook

I ran these steps against the live proxy while a loop of requests ran the whole time.

1. **Issue the new certificate** next to the old files, never over them: `localhost.crt.new` / `localhost.key.new`, mode `644` (readable by the nginx user).
2. **Check it before it goes anywhere.** It must not be expired yet and must have the right SAN/CN, and the key must match the certificate: `openssl x509 -noout -pubkey -in crt.new | sha256sum` must equal `openssl pkey -pubout -in key.new | sha256sum`.
3. **Back up the current pair** (`*.old`), so rolling back is a rename.
4. **Swap atomically**: `mv -f localhost.key.new localhost.key`, then `mv -f localhost.crt.new localhost.crt`. `mv` within one directory is a rename, so nginx never reads a half-written file. The bind-mounted directory makes the new files visible in the container immediately.
5. **Test the config**: `docker compose exec nginx nginx -t`. If it fails, rename the `.old` files back and stop. Don't reload.
6. **Graceful reload**: `docker compose exec nginx nginx -s reload`. The master process starts new workers with the new certificate, and old workers finish their in-flight requests before exiting. No connection is dropped, unlike `restart`.
7. **Verify the new certificate is live** from outside, by fingerprint rather than by "it still works":
   ```
   echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -fingerprint -sha256 -enddate
   ```
   The fingerprint must equal the new file's. Then check the error log for SSL errors and delete the `.old` pair after the old certificate's clients have gone.

Result of the run:

```
live before: D1:CF:02:1D:7B:3C:83:07:21:D3:02:97:9E:29:97:3F:28:A6:A2:5E:01:B1:E9:E7:60:3F:DC:38:67:A2:8F:CE
new cert:    B7:D7:1B:56:BA:30:2C:C5:FB:2A:CD:23:CE:33:07:1F:89:5E:C0:BA:07:AA:9E:E6:7E:29:EC:7C:D0:67:E9:10
key matches cert
nginx: configuration file /etc/nginx/nginx.conf test is successful
live after:  B7:D7:1B:56:BA:30:2C:C5:FB:2A:CD:23:CE:33:07:1F:89:5E:C0:BA:07:AA:9E:E6:7E:29:EC:7C:D0:67:E9:10
   1736 200
```

All 1,736 requests during the 20-second window, reload included, returned 200. None failed.

### 6. Getting around a per-address limit

1. **Spread the attack over many source addresses.** Residential proxy networks, botnets, cloud functions, or a whole IPv6 /64 rotated per request. With `$binary_remote_addr` each address gets its own 10 requests/min, so 1,000 addresses means 10,000 password guesses a minute.
2. **Make many users look like one address, or one address look like many.** Behind a CDN or load balancer every client shares the proxy's address, so legitimate users get 429 together. If someone then "fixes" that by keying on `X-Forwarded-For` without `set_real_ip_from` restricted to the trusted hops, an attacker sets the header themselves and gets a fresh bucket per request.

At this layer I would:
- set `real_ip_header` and trust it only from the known upstream hop;
- key IPv6 clients on their /64;
- add a second login zone keyed on the **target account**: the `email` in the request body, which needs njs or the app, so that one account gets limited no matter how many IPs try it.

Above this layer: per-account lockout or exponential back-off in the app, a CAPTCHA or proof-of-work after N failures, MFA, and credential-stuffing detection in the WAF/CDN that uses reputation and fingerprinting. A per-IP counter can't see a distributed attack on its own.

## Bonus

### 1. Setup

`labs/lab11/waf/docker-compose.override.yml` adds a `waf` service to the same compose project:

- **Image:** `owasp/modsecurity-crs:nginx`, pinned by digest `sha256:133267aa811e…`. It ships nginx 1.30.5 + ModSecurity v3 + **CRS 4.30.0** (`ver:'OWASP_CRS/4.30.0'` in `crs-setup.conf`).
- **Backend:** `BACKEND=http://juice:3000`.
- **Mode:** blocking, with `MODSEC_RULE_ENGINE=On`, `BLOCKING_PARANOIA=1` and inbound anomaly threshold 5.
- **Audit log:** JSON to stdout.
- **Port:** published on `127.0.0.1:8090`. 8080 was already taken on this host by DefectDojo from Lab 10.

Started with `docker compose -f docker-compose.yml -f waf/docker-compose.override.yml up -d`. Juice Shop still publishes nothing, so the app can only be reached through `nginx` on 443 or `waf` on 8090.

### 2. The same request through both paths

```
plain proxy (https://localhost/rest/products/search?q=%27%20OR%201%3D1--): 500
WAF        (http://127.0.0.1:8090/rest/products/search?q=%27%20OR%201%3D1--): 403
```

Through the plain proxy the payload reaches the database. Juice Shop answers 500 with `<title>Error: SQLITE_ERROR: incomplete input</title>`, which is the Lab 5 injection. Through the WAF it never reaches the app.

### 3. The CRS rule that fired

From the WAF's JSON audit log for that request:

```
/rest/products/search?q=%27%20OR%201%3D1--
403
920350  Host header is a numeric IP address                Host: 127.0.0.1:8090
942100  SQL Injection Attack Detected via libinjection    Matched Data: s&1c found within ARGS:q: ' OR 1=1--
949110  Inbound Anomaly Score Exceeded (Total Score: 8)
```

**942100** is the detection. CRS passes every argument through **libinjection**, which tokenizes the value the way a SQL parser would and compares the token fingerprint against known injection shapes. Here `s&1c` means string, logical operator, number, comment, i.e. `' OR 1=1--`. It is a CRITICAL rule worth 5 anomaly points, which on its own meets the threshold of 5. **949110** is the blocking rule that compares the total with the threshold and returns 403. 920350 (3 points, numeric `Host`) only fired because I tested against `127.0.0.1`. Repeated with `Host: localhost`, the request is still blocked with `942100` alone, `Total Score: 5`.

### 4. Looking for false positives

I sent ordinary application traffic through the WAF (`Host: localhost`):

| Request | Through WAF |
| ------- | ----------: |
| `GET /`, `GET /main.js`, `search?q=apple`, `search?q=apple juice (1000ml)` | 200 |
| login with valid credentials (`jim@juice-sh.op`) | 200 |
| register with password `P@ss'w0rd--;` and answer `my mom's name` | 201 |
| `search?q=O'Reilly` | 500 *(passed the WAF; the app itself breaks on the quote)* |
| **`PUT /rest/products/1/reviews`** (write a product review) | **403** |
| **`PUT /api/BasketItems/1 {"quantity":2}`** (change basket quantity) | **403** |
| feedback comment *"The union select of juices is great, drop table service too"* | **403** |

Two of these are real false positives that would break the app:

- **`911100 Method is not allowed by policy: PUT`.** CRS's default `allowed_methods` is `GET HEAD POST OPTIONS`. Juice Shop uses `PUT` to post reviews and change basket quantities, and `DELETE` to remove basket items. The same basket `PUT` through the plain proxy reaches the app (401, because it needs a login). Through the WAF it's refused before authentication is even checked. Writing a review or changing a quantity would simply stop working for every user. The fix is a one-line exclusion: set `tx.allowed_methods` to include `PUT PATCH DELETE`, scoped to `/rest/` and `/api/`.
- **`942190 Detects SQL code execution and information gathering attempts`** on harmless prose that contains the words "union select". Any free-text field (reviews, feedback, a support form) will eventually trigger it. The fix is a targeted rule exclusion for `ARGS:json.comment` and `ARGS:json.message` on those endpoints, not disabling 942190 globally.

It also missed one: a bare `'` (`O'Reilly`) passes the WAF but still breaks the app's query (500). A WAF lowers the cost of exploitation; it doesn't remove the bug from `routes/search.ts`.

### 5. How I would roll this out on a real application

1. **Detection only.** Start with `MODSEC_RULE_ENGINE=DetectionOnly` at paranoia level 1, in front of real traffic, for at least one full business cycle. Ship the audit log to the SIEM and group hits by rule id and endpoint.
2. **Tune.** Every hit on known-good traffic, like the `PUT` and free-text cases above, becomes a narrow exclusion, scoped by rule id and argument or path. Exclusions live in version control and are reviewed like code, with an owner and a reason.
3. **Block with a high threshold.** Once hits on legitimate traffic are near zero, switch to blocking with a high inbound anomaly threshold (e.g. 20), so only requests that trip several critical rules are blocked. Lower it gradually towards 5 while watching 403 rates and support tickets.
4. **Raise paranoia per path, not globally.** For example PL2 on `/rest/user/login` and admin routes.

Every step has a one-variable rollback (`DetectionOnly`). The WAF stays a compensating control with an expiry date, while the actual fix, parameterized queries, goes into the app.
