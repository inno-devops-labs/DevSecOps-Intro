# Lab 11 — Edge Hardening with a Reverse Proxy

nginx `stable-alpine` in front of `bkimminich/juice-shop:v20.0.0`, ports 80 and 443 (both free on this host, so no remapping). Self-signed certificate for `CN=localhost`, 2048-bit RSA, 30 days — so every `curl` below carries `-k` and `openssl s_client` always prints a verify error.

The app publishes no port of its own (`expose: "3000"` only), so the only way in is through a proxy.

## Task 1

### The redirect

```bash
$ curl -sI http://localhost | head -2
HTTP/1.1 308 Permanent Redirect
Server: nginx
```

**308, not 301.** Both are permanent, and the difference is what happens to the method and body. A 301 historically allows — and in practice causes — clients to rewrite a `POST` into a `GET` and drop the body; 308 forbids that, so a form submission or an API call that arrives on port 80 is replayed to HTTPS intact. Here that is not academic: `POST /rest/user/login` arriving over plain HTTP should finish as a `POST` over TLS, not silently become a `GET` that returns a page and loses the credentials. The one thing 308 does not fix is that those credentials already crossed the network in clear text — the redirect protects the *next* request, which is why HSTS below matters more than the redirect does.

### TLS

```bash
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

What the **server offers**, enumerated by a scanner that carries its own TLS stack rather than by a client that refuses to speak old protocols:

```
$ docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 https://localhost

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

This is the distinction the lab makes: `openssl s_client -tls1_1` fails with `no protocols available` on OpenSSL 3 before a packet leaves the machine, which says something about my client and nothing about my server. The table above is the actual answer.

### All six headers

```bash
$ curl -skI https://localhost
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Every one carries `always`, so they survive 4xx and 5xx — which is exactly when a browser is most exposed, because an error page is still a page that can be framed or sniffed. The Lab 1 triage of this same app found `X-Content-Type-Options` and `X-Frame-Options` present and CSP and HSTS missing; all four now come from the proxy, and the application's own copies are stripped with `proxy_hide_header` so policy is set in one place rather than negotiated between two.

### Why Report-Only, and the path to enforcement

The CSP above would break Juice Shop immediately if enforced, and the policy text says why in its own terms: it already contains `'unsafe-inline'` and `'unsafe-eval'` for scripts, which is most of what a CSP is supposed to prevent. An Angular application of this vintage inlines bootstrap script, the theme injects inline styles, and `img-src 'self' data:` is there because product images are served as data URIs. Enforce it today and the result is a blank page, not a secure one — and the specific failure would be invisible to anyone not watching the browser console.

The process to get to enforcement has four steps and none of them is "flip the switch". First, deploy Report-Only with a `report-uri`/`report-to` endpoint and collect violations from real traffic for long enough to cover the slow paths — admin screens, error pages, the payment flow — which is typically two to four weeks, not two days. Second, read the report stream and sort violations into *the policy is wrong* (a legitimate CDN nobody listed) versus *the application is wrong* (inline handlers that should be external files). Third, fix the application side, which is the expensive part and the reason most teams stop here: removing `'unsafe-inline'` means refactoring templates and adopting nonces or hashes. Only then does the same policy move from `Content-Security-Policy-Report-Only` to `Content-Security-Policy`, ideally on a fraction of traffic first. The honest summary for this application is that enforcement is blocked on application work, and shipping Report-Only now is what makes that work measurable instead of theoretical.

## Task 2

### The rate limit bites

```bash
$ for i in $(seq 1 14); do
    curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login \
      -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'
  done; echo
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

Configuration:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
...
location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

**Rate 10r/m, burst 5, `nodelay`.** Six requests get through — one at the steady rate plus the burst of five — and the remaining eight are refused. The limit is scoped with `location =` to the login endpoint only: rate-limiting the whole site at 10 requests a minute would make the application unusable, since one page load pulls dozens of assets.

`limit_req_status 429` matters more than it looks. The nginx default is **503**, which tells a client "the server is temporarily broken, retry" — exactly the wrong instruction, and one that well-behaved clients obey by retrying immediately. 429 means "you are going too fast", which is what actually happened, and is the status a sane client backs off on.

nginx's own view of the same event:

```
[warn] 34#34: *55 limiting requests, excess: 5.934 by zone "login", client: 192.168.65.1
```

### Connection limit per address

```nginx
limit_conn_zone $binary_remote_addr zone=perip:10m;
limit_conn_status 429;
...
limit_conn perip 10;    # in the HTTPS server block
```

`limit_req` bounds the *rate* of requests; this bounds how many sockets one address may hold open at once. They defend against different attacks — a slowloris client makes almost no requests and simply refuses to finish the ones it has, which a request-rate limit never notices.

### Cipher configuration, and proof a suite outside it is refused

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:...";   # TLS 1.2 only
ssl_prefer_server_ciphers on;
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;   # TLS 1.3
```

AES-GCM only; ChaCha20-Poly1305 is deliberately excluded so the restriction is observable.

```bash
$ echo | openssl s_client -connect localhost:443 -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure'
1

# what it actually says
error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure: SSL alert number 40

# and a suite that IS on the list
$ echo | openssl s_client -connect localhost:443 -tls1_3 \
    -ciphersuites TLS_AES_128_GCM_SHA256 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
```

Alert 40 is `handshake_failure` from the **server** — the negotiation reached nginx and nginx refused, which is the proof that matters. The pitfall the lab warns about is the opposite case: `-cipher TLS_AES_256_GCM_SHA384` fails with `no cipher match` inside OpenSSL before any packet is sent, because `-cipher` only names TLS 1.2 suites. That failure is a test bug and proves nothing about the server. Equally, putting `TLS_AES_*` names in `ssl_ciphers` would have been silently ignored by nginx — the config would look restrictive and restrict nothing.

### Timeouts, and one firing

| Directive | Value | What it protects against |
|---|---|---|
| `client_header_timeout` | 10s | Slowloris: a client that opens a connection and dribbles headers forever, holding a worker slot without ever completing a request. |
| `client_body_timeout` | 10s | The same attack moved to the body — headers complete, then the POST body arrives one byte at a time. |
| `send_timeout` | 10s | A slow-read client that requests a large response and then stops reading it, pinning a worker and the memory behind it. |
| `proxy_connect_timeout` | 5s | A dead or saturated upstream: fail fast rather than queueing clients behind a backend that is not accepting connections. |
| `proxy_read_timeout` | 30s | An upstream that accepted the request and then hangs; without it, one wedged backend request occupies a proxy worker indefinitely. |
| `proxy_send_timeout` | 30s | An upstream that stops reading the request body mid-transfer. |
| `keepalive_timeout` | 10s | Idle connections accumulating and exhausting the connection table. |

**Proof that one actually fires** — open a TLS connection, send the request line and then no headers at all:

```python
s.sendall(b"GET / HTTP/1.1\r\n")   # and nothing more
```

```
ждали 10.0s
(соединение закрыто без ответа)
```

and in nginx's access log:

```
192.168.65.1 - - [14/Oct/2026:16:19:22 +0000] "GET / HTTP/1.1" 408 0 "-" "-" rt=10.009 uct=- urt=-
```

`408` after `rt=10.009` — the request time matches `client_header_timeout 10s` to within nine milliseconds. A configured timeout and a firing timeout are different claims, and this is the second one.

### OCSP stapling

Stapling saves the client a **separate network round trip to the CA** on every new connection, and with it a privacy leak: without stapling the browser tells the CA which site you are visiting and when. The server fetches the revocation response itself, caches it, and hands it over inside the handshake already signed by the CA, so the client gets the same assurance with none of the latency or the disclosure.

**I would not enable it here**, and the config says so with `ssl_stapling off` plus a commented block showing what to turn on later. The certificate is self-signed: there is no issuer to query, no OCSP responder URL in the certificate, and nginx would log `ssl_stapling ignored, issuer certificate not found` on every reload while changing nothing. On a publicly-trusted certificate the answer flips — stapling goes on, together with `ssl_stapling_verify on`, a `resolver`, and `ssl_trusted_certificate` pointing at the issuer chain, because without those nginx cannot validate the response it is about to staple.

### Certificate rotation runbook

Zero failed requests, in order:

1. **Before anything touches the server:** obtain the new certificate and key and verify them off-line. `openssl x509 -noout -dates -subject -in new.crt` for validity and name; `openssl x509 -noout -modulus -in new.crt | openssl md5` against `openssl rsa -noout -modulus -in new.key | openssl md5` to prove the pair matches. A mismatched pair discovered after a reload is an outage.
2. **Stage the files under new names** next to the live ones, with ownership and mode that the nginx worker user can read — `644` on the certificate, `640` or `644` on the key depending on how the container runs it. The lab's own pitfall applies here: a key written `600` by root on the host is unreadable through a bind mount by the unprivileged user inside the container.
3. **Point the config at the new paths** (or swap the symlink the config already points at — the symlink approach is better, because it makes the change and the rollback a single atomic operation).
4. **Validate before applying:** `nginx -t`. This parses the whole configuration and opens the certificate files. Nothing is live yet, and a failure here costs nothing.
5. **Reload, do not restart:** `nginx -s reload`. New worker processes start with the new certificate, existing workers finish the requests they are already serving and then exit. No connection is dropped and no listening socket is closed, which is the entire difference between a reload and a restart.
6. **Verify the new certificate is actually live**, from outside the box, not from the config file:
   ```bash
   echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
     | openssl x509 -noout -dates -serial -fingerprint -sha256
   ```
   The serial and SHA-256 fingerprint must equal the new certificate's, and `notAfter` must be the new expiry. Checking only `notAfter` is how people convince themselves a rotation worked when the old certificate is still being served from a worker that never got recycled.
7. **Confirm traffic is healthy** — a smoke request through the proxy and a look at the error log for `SSL_CTX_use_PrivateKey` complaints — then and only then remove the old files, keeping them for one rotation cycle so step 3 can be reversed.

### Two ways around a per-address rate limit

The limit keys on `$binary_remote_addr`, so it assumes one attacker equals one address. Two ways that fails:

- **Distribute the source.** A botnet, a residential-proxy service or a few hundred cloud instances give an attacker thousands of addresses, each staying comfortably under 10r/m while the aggregate is thousands of login attempts a minute. Password spraying is designed around exactly this: a few attempts per account from many addresses.
- **Appear as a different address, or as the wrong one.** If the proxy ever sits behind a CDN or load balancer without `real_ip_header`/`set_real_ip_from` configured, every request arrives with the balancer's address and the entire internet shares one bucket — one attacker then rate-limits every legitimate user. Worse, a misconfigured `X-Forwarded-For` trust lets the attacker *choose* their key by sending a new value per request, which removes the limit entirely. IPv6 is a quieter version of the same problem: a single client is routinely handed a /64, which is 18 quintillion distinct `$binary_remote_addr` values.

What I would add, at this layer and above it. At the proxy: key the limit on something more expensive to rotate than an address — the submitted username for login attempts, so spraying one account is bounded no matter where it comes from — and for IPv6 key on the /64 rather than the full address. Above it: per-account lockout with exponential backoff in the application, which no network-layer control can substitute for, and a CDN or scrubbing service in front for volumetric distribution, since by the time thousands of addresses reach nginx the capacity has already been spent. The honest framing is that a per-address limit stops the lazy attacker and buys time against the serious one; it is a speed bump, not a control, and treating it as a control is how teams end up surprised.

## Bonus

### The same request through both paths

Payload: `' OR 1=1--` as the `q` parameter of the product search — the Lab 5 injection, URL-encoded.

```bash
$ curl -sk -o /dev/null -w "%{http_code}\n" "https://localhost/rest/products/search?q=%27%20OR%201%3D1--"
500        # plain proxy: forwarded, and the application's SQL parser choked on it

$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/rest/products/search?q=%27%20OR%201%3D1--"
403        # WAF: refused before it reached the application

$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/rest/products/search?q=apple"
200        # the same endpoint, benign input, through the same WAF
```

The 500 from the plain proxy is worth a sentence: the hardened nginx did everything it was configured to do — TLS, headers, rate limits — and forwarded a SQL injection without comment, because nothing in Task 1 or Task 2 inspects a request body or query string. That is the gap a WAF fills.

### The CRS rule that fired

From the ModSecurity JSON audit log:

```json
{"ruleId": 942100, "severity": 2,
 "message": "SQL Injection Attack Detected via libinjection",
 "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"}
{"ruleId": 949110, "severity": 0,
 "message": "Inbound Anomaly Score Exceeded (Total Score: 5)"}
```

**942100** is the detection. It does not pattern-match SQL keywords; it hands the parameter to **libinjection**, a tokenising library that decides whether a string parses as SQL syntax rather than as data. `s&1c` is libinjection's fingerprint for what it saw — string, operator, number, comment — which is why it catches `' OR 1=1--` and not a product called "Union Smoothie".

**949110** is the rule that actually returns 403. CRS in anomaly-scoring mode adds each match to a score and blocks when the inbound total crosses the threshold (5, configured here). This two-stage design is the thing to understand before tuning: a single rule firing does not block, and turning off 949110 to "reduce false positives" disables blocking globally rather than for the rule you meant.

### A legitimate request the WAF blocks

**Yes, and it is a serious one: `PUT /rest/products/1/reviews` — posting a product review — is blocked by CRS and works fine through the plain proxy.**

```bash
$ curl -s -o /dev/null -w "%{http_code}\n" -X PUT "http://localhost:8080/rest/products/1/reviews" \
    -H 'Content-Type: application/json' -d '{"message":"Lovely juice","author":"a@b.c"}'
403

$ curl -sk -o /dev/null -w "%{http_code}\n" -X PUT "https://localhost/rest/products/1/reviews" \
    -H 'Content-Type: application/json' -d '{"message":"Lovely juice","author":"a@b.c"}'
201
```

The rule is **911100, "Method is not allowed by policy"** — CRS's default `tx.allowed_methods` is `GET HEAD POST OPTIONS`, and any REST API that uses PUT, PATCH or DELETE breaks on day one. `DELETE /api/Products/1` is refused the same way.

I went looking for the more obvious false positive first and did not find it: a review containing the word "union" passes (`GET /rest/products/search?q=union%20of%20flavors` → 200), as do `O'Brien`, `100% juice`, `a<b`, and logins whose password contains an apostrophe or the literal string `select*from2024`. libinjection is parsing, not keyword-matching, and it is good at it. The false positive that bit was not about payloads at all — it was a policy default about HTTP verbs, which is the kind of thing nobody tests for because it looks like infrastructure rather than security.

### Rolling this out in front of a real application

Blocking mode on day one is how teams end up turning the WAF off, and the PUT result above is exactly the mechanism: within an hour of go-live, reviews stop working, nobody connects it to the WAF, and the fastest fix anyone can think of is `MODSEC_RULE_ENGINE=Off`. After that it never goes back on, because now nobody trusts it.

So: start in **DetectionOnly** (`MODSEC_RULE_ENGINE=DetectionOnly`) with the full rule set and full audit logging, in production, against real traffic — staging traffic does not contain the weird-but-legitimate requests that cause false positives. Run it for at least a full business cycle, two to four weeks, long enough to see month-end jobs and the admin paths that are used once a quarter. Then work the log the way you would a scanner backlog: group by rule id, and for each one decide whether it is a true positive (leave it), a policy mismatch (fix the policy — adding PUT and DELETE to `allowed_methods` is a configuration change, not an exception), or a genuine false positive (a targeted `SecRuleRemoveById` scoped to one path, never globally).

Only then enable blocking, and not everywhere at once: start with the paranoia level you tuned at (1, not 4), block on one low-risk route or a percentage of traffic, and keep a documented, one-variable rollback that an on-call engineer can execute at 3 a.m. without asking permission. Two things make the difference between a WAF that survives and one that gets disabled: every blocked request must be attributable to a rule id in a log someone actually reads, and the team must be able to turn it off faster than they can be pressured into deleting it.
