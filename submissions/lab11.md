# Lab 11 — Edge Hardening with a Reverse Proxy

**Environment**
- Host: Windows 11, Docker Desktop 29.7.2, Git Bash with `OpenSSL 3.5.5` and `curl 8.18.0`.
- Proxy: `nginx:stable-alpine` = **nginx 1.30.6**. Backend: `bkimminich/juice-shop:v20.0.0`, reachable only through the proxy (no published port; `curl http://localhost:3000` gets no answer).
- Certificate: self-signed, `CN=localhost`, 30 days, `chmod 644`; `nginx -t` reports the configuration as successful.

The config is [`labs/lab11/reverse-proxy/nginx.conf`](../labs/lab11/reverse-proxy/nginx.conf). The starter already had the redirect, the protocol list, the headers and the login rate limit. I added or changed:
- a per-address connection limit;
- TLS 1.3 restricted to AES-GCM with `ssl_conf_command Ciphersuites`, and ChaCha20 dropped from the TLS 1.2 list to match;
- timeouts documented and tightened (`proxy_send_timeout` from 30 s to 10 s);
- `preload` removed from HSTS.

**One deviation.** The lab runs testssl.sh with `--network host`. On Docker Desktop that is the VM's network, not this machine's `localhost`, so I ran it on the compose network against `https://nginx:443`. It is the same server and the same listener, without the host port mapping in between.

## Task 1

### Redirect

```text
$ curl -sI http://localhost | head -2
HTTP/1.1 308 Permanent Redirect
Server: nginx
$ curl -sI -X POST http://localhost/rest/user/login
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/rest/user/login
```

**308, not 301.** Both are permanent, but 308 *preserves the method and body*. A `POST` to `http://…/rest/user/login` is re-sent as a `POST` to HTTPS. With 301, clients are allowed to, and commonly do, turn it into a `GET`, which silently drops the request body. The site's only state-changing traffic is API calls, so a method-preserving redirect is the safe default.

### TLS

```text
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

What the server **offers**, from testssl.sh 3.2:

```text
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

testssl's per-protocol cipher enumeration (`-E`) also shows the suite restriction from Task 2, seen from outside:

```text
TLSv1.2  xc030 ECDHE-RSA-AES256-GCM-SHA384   ECDH 256        AESGCM 256
         xc02f ECDHE-RSA-AES128-GCM-SHA256   ECDH 256        AESGCM 128
TLSv1.3  x1302 TLS_AES_256_GCM_SHA384        ECDH/MLKEM      AESGCM 256
         x1301 TLS_AES_128_GCM_SHA256        ECDH/MLKEM      AESGCM 128
```

TLS 1.0 and 1.1 have no ciphers at all. The `ECDH/MLKEM` key exchange is the hybrid post-quantum X25519MLKEM768 that this nginx/OpenSSL build negotiates by default.

### Headers

```text
$ curl -skI https://localhost
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

The same six headers also come back on an **error**: the 429 from the rate limit in Task 2 carries all of them, because every `add_header` has `always`. I removed `preload` from HSTS. It is a request to be hard-coded into browsers for a registrable domain with a publicly trusted certificate, which a self-signed `localhost` is not, and getting off the preload list takes months.

### CSP: why Report-Only, and the path to enforcing

If I enforced this policy today, Juice Shop's **fonts would break**. `index.html` loads a stylesheet from `https://fonts.googleapis.com` and font files from `https://fonts.gstatic.com`. The policy allows neither: `style-src` has no Google origin, and with no `font-src`, fonts fall back to `default-src 'self'`. The Material icon font would degrade into its ligature text.

At the same time, the policy as written protects little. `'unsafe-inline'` lets any injected inline script run, which is exactly the XSS Juice Shop is built around. `'unsafe-eval'` is not even needed: the main bundle contains no `eval` or `new Function`. Report-Only has a second gap: without `report-uri` or `report-to`, the violations land only in each visitor's browser console, where nobody reads them.

The path to enforcement:
1. Add a reporting endpoint and collect violations from real traffic for a couple of weeks.
2. Add the origins that are genuinely needed, here `fonts.googleapis.com` for `style-src` and `fonts.gstatic.com` for `font-src`. Better still, self-host the fonts.
3. Replace `'unsafe-inline'` for scripts with a nonce or hash for the single inline `<script>`, and drop `'unsafe-eval'`.
4. Ship that as `Content-Security-Policy`, keeping a stricter next version running in parallel as `…-Report-Only`.

## Task 2

### Rate limit

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;   # http block
limit_req_status 429;
location = /rest/user/login { limit_req zone=login burst=5 nodelay; … }
```

The rate is **10 requests per minute** (one token every 6 s) with a **burst of 5**, and `nodelay`. It applies to `/rest/user/login` only.

```text
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login …; done
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

Six requests reach Juice Shop: the regular one plus the burst of 5, all served at once because of `nodelay`, and each gets `401` for the bad password. The next eight get **429**, not nginx's default 503. While the login is throttled, `GET /rest/admin/application-version` still returns 200, so the limit is scoped to login and not to the site. The error log shows each rejection:

```text
[warn] limiting requests, excess: 5.906 by zone "login", client: 192.168.65.1, server: _, request: "POST /rest/user/login HTTP/1.1"
```

**Connection limit per client address**, configured as:

```nginx
limit_conn_zone $binary_remote_addr zone=perip:10m;   # http block
limit_conn_status 429;
limit_conn perip 20;                                   # HTTPS server
```

I proved it as well. With the app paused so that requests hang, 25 parallel requests from one address gave:

```text
     20 504(30.0s)    <- admitted, then hit proxy_read_timeout
      5 429(0.0s)     <- refused at once
[warn] limiting connections by zone "perip", client: 192.168.65.1
```

### Ciphers

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";  # TLS 1.2
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;                                                       # TLS 1.3
```

A TLS 1.3 suite outside the list is refused at the handshake:

```text
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
…:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:…:SSL alert number 40
New, (NONE), Cipher is (NONE)
$ … | grep -icE 'alert|failure'
1
```

A suite inside the list still works (`-ciphersuites TLS_AES_128_GCM_SHA256` gives `TLSv1.3`, `TLS_AES_128_GCM_SHA256`). The testssl table in Task 1 confirms from the server side that only the two AES-GCM suites are offered.

### Timeouts

| Directive | Value | What it protects against |
|---|---|---|
| `proxy_connect_timeout` | 5 s | An app that is down or unreachable. The proxy fails fast instead of piling up waiting connections. On the same Docker network a healthy connect takes milliseconds. |
| `proxy_send_timeout` | 10 s | An upstream that stops reading the request body. It caps how long a worker sits blocked pushing data to it. |
| `proxy_read_timeout` | 30 s | A hung or overloaded app. Without it, every stuck request holds a proxy connection for nginx's default 60 s, and a slow endpoint becomes a self-inflicted DoS. |
| `client_header_timeout` / `client_body_timeout` | 10 s | Slowloris-style clients that dribble headers or a body to hold connections open. |
| `send_timeout` / `keepalive_timeout` | 10 s | Clients that read the response very slowly, and idle keep-alive connections that tie up slots. |

**A timeout actually firing.** I froze the app with `docker pause`, so its kernel still accepts TCP connections but the process never answers:

```text
$ docker pause lab11-juice-1
$ curl -sk -o /dev/null -w 'HTTP %{http_code} after %{time_total}s\n' https://localhost/rest/admin/application-version
HTTP 504 after 30.040869s
# access.log
"GET /rest/admin/application-version HTTP/1.1" 504 160 "-" "curl/8.18.0" rt=30.030 uct=0.000 urt=30.030
# error.log
upstream timed out (110: Operation timed out) while reading response header from upstream, … upstream: "http://172.20.0.2:3000/…"
$ docker unpause lab11-juice-1      # next request: 200
```

`uct=0.000` shows that the connect succeeded; `urt=30.030` shows it was `proxy_read_timeout` that fired.

### OCSP stapling

Stapling saves the client a separate round trip to the CA's OCSP responder during the handshake. The server fetches a signed "not revoked" response itself, caches it and sends it along. That removes latency, removes a failure point (the responder being down), and stops the CA learning which sites each user visits. I would **not** enable it here, for three reasons:
- The certificate is self-signed, has no Authority Information Access URL, and no responder exists.
- Turning it on would mean a resolver and outbound requests from the proxy for nothing.
- With a public certificate it is less useful than it used to be: Let's Encrypt has retired OCSP in favour of CRLs, and Chrome does not do online OCSP checks anyway.

### Certificate rotation runbook: zero failed requests

1. **Prepare.** Obtain the new key and certificate, then check them before they go anywhere near nginx:
   - the key matches the certificate: `openssl x509 -noout -pubkey -in new.crt` equals `openssl pkey -pubout -in new.key`;
   - the expiry and SANs are right: `openssl x509 -noout -enddate -ext subjectAltName -in new.crt`;
   - the full chain is included.
2. **Record the current fingerprint** for later comparison: `echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256`.
3. **Stage the files atomically.** Copy them next to the live ones as `localhost.crt.new` and `localhost.key.new` with mode `644`, then `mv` them over `localhost.crt` and `localhost.key`. A rename is atomic, so nginx never reads a half-written file.
4. **Validate before reloading:** `docker compose exec nginx nginx -t`. If it fails, restore the old files. Nothing has changed for clients yet.
5. **Reload gracefully:** `docker compose exec nginx nginx -s reload`. Never restart the container. On a reload the master starts new workers with the new certificate while the old workers finish their in-flight requests and close, so no connection is dropped.
6. **Verify the new certificate is live.** Rerun the fingerprint command from step 2: it must show the new fingerprint and the new `notAfter`. Then:
   - `curl -skI https://localhost` returns 200, with no new `[emerg]` or `[crit]` lines in `logs/error.log`;
   - if the certificate is publicly trusted, run the same check from outside the host.
7. **Afterwards.** Keep the old pair for a rollback window, then delete the old key. Put the next expiry into monitoring, and alert at 21 days.

### Getting around a per-address limit

1. **Many addresses.** A botnet, residential-proxy pool or cloud IPs spread the credential-stuffing load so that each address stays under 10 requests a minute. Over IPv6 a single host can rotate through its whole /64, so keying on the full address gives an attacker 2⁶⁴ buckets.
2. **Low and slow across accounts.** One password tried against thousands of usernames at 9 requests a minute per address never trips a limit that counts requests per address, not attempts per account.

The opposite failure showed up in this lab. Every request arrived from `192.168.65.1`, Docker Desktop's NAT gateway. Behind a corporate NAT or a load balancer without `real_ip` configured, everyone shares one bucket, and one user's typos lock out the office.

What I would add:
- **At this layer:** key IPv6 on the /64 prefix; take the client address from `X-Forwarded-For` only via `set_real_ip_from` the trusted load balancer, never from the raw header, which anyone can forge.
- **Above it:** a per-account limit with exponential backoff in the application; a CAPTCHA or proof-of-work after a few failures; MFA, so that a guessed password is not enough; and bot-reputation filtering at a CDN or WAF.

## Bonus

Not submitted. I wrote a WAF override (`labs/lab11/waf/docker-compose.override.yml`, `owasp/modsecurity-crs:4.30.0-nginx-…`, blocking mode, ports 8081/8444) but did not run it. With no request compared through both paths and no CRS rule id from a real log, there is nothing to claim, so the file is not part of this PR.

## Clean-up

`docker compose -f labs/lab11/docker-compose.yml down -v`. `certs/`, `logs/` and `results/` are not committed.
