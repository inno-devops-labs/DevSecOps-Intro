# Lab 11 — Edge Hardening with a Reverse Proxy

> **Environment note:** macOS ships LibreSSL 3.3.6 as `openssl`, which lacks `-brief` and `-ciphersuites`. Where the lab's exact `openssl s_client` invocation wasn't available locally, I used `docker run --rm --network host alpine/openssl ...` (a real OpenSSL 3.x build) to get an equivalent, correctly-flagged result, and note which is which below.

## Task 1

**Redirect status code:** `308 Permanent Redirect`. I chose 308 over 301 because 308 is defined to preserve the request method and body on redirect (301 technically allows — and in practice some older clients did — a POST becoming a GET on the redirected request). Since this proxy redirects *every* request including POSTs (e.g. `POST /rest/user/login` over plain HTTP), 308 is the version of "permanent redirect" that doesn't risk silently turning a login POST into a GET.

**TLS 1.3 protocol and cipher suite negotiated** (`echo | openssl s_client -connect localhost:443 -tls1_3`, LibreSSL output — no `-brief` support, so read from the full handshake dump):

```
Protocol  : TLSv1.3
Cipher    : AEAD-AES256-GCM-SHA384
```

**Protocol table from a real scanner** (`docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 https://localhost`):

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

Only TLS 1.2 and 1.3 are offered — TLS 1.0/1.1/SSLv2/SSLv3 are all absent, confirmed by a client that carries its own TLS stack rather than depending on what my local OpenSSL is still willing to attempt.

**All six headers, as returned by the server** (`curl -skI https://localhost`):

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

**What would break if `Content-Security-Policy-Report-Only` were enforced today.** I checked this concretely rather than guessing: I temporarily swapped the header name to `Content-Security-Policy` (enforcing), reloaded nginx, and inspected Juice Shop's own HTML source with `curl`. The index page inlines an `@font-face` block that loads its retro display font (`VT323`, used for the page's main headings) directly from `https://fonts.gstatic.com/...woff2`, and preconnects to `https://fonts.googleapis.com`. Neither host is in the policy's `style-src`/`font-src` allowlist (there is no `font-src` directive at all, so it falls back to `default-src 'self'`), so enforcing this policy as written today would silently block that font — the retro headings would fall back to a generic system font, a visible but non-breaking regression. I reverted the header back to report-only immediately after confirming this. The path to enforcement: run in report-only for a real traffic window and collect violation reports (a `report-uri`/`report-to` endpoint would need to be added — currently absent), fix each legitimate violation by either self-hosting the font or adding `fonts.googleapis.com`/`fonts.gstatic.com` to an explicit `style-src`/`font-src`, then flip the header once a full pass through the app's UI produces zero new violations in the reports.

## Task 2

**Status code sequence** (`for i in $(seq 1 14); do curl ... POST /rest/user/login; done`):

```
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

**Configured rate:** `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;` with `limit_req zone=login burst=5 nodelay;` on `location = /rest/user/login`, and `limit_req_status 429;` globally. With `nodelay`, the burst bucket (5) plus the one token the bucket starts with lets 6 requests through immediately; the next 8 in my rapid-fire loop all landed inside the same second and got 429 — matching what the sequence shows.

**Cipher configuration:**

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

`ssl_ciphers` covers TLS 1.2 (unchanged from the starter); `ssl_conf_command Ciphersuites` is the directive that actually configures TLS 1.3 — I added it, restricted to the two AES-GCM suites, deliberately excluding `TLS_CHACHA20_POLY1305_SHA256`.

**Proof a suite outside the list is refused.** LibreSSL's `s_client` doesn't support `-ciphersuites` at all, so I used a real OpenSSL 3.x build via Docker:

```
$ docker run --rm --network host alpine/openssl s_client -connect localhost:443 -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256
...
New, (NONE), Cipher is (NONE)
Protocol: TLSv1.3
```

`Cipher is (NONE)` — no suite was agreed because the client only offered ChaCha20-Poly1305 and the server only accepts AES-GCM. As a control, the same command with an allowed suite succeeds:

```
$ docker run --rm --network host alpine/openssl s_client -connect localhost:443 -tls1_3 \
    -ciphersuites TLS_AES_256_GCM_SHA384
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

**Timeout values, and what each protects against:**

| Directive | Value | Protects against |
|---|---|---|
| `client_body_timeout` | 10s | A client that opens a request and trickles the body in byte by byte (Slowloris-style), tying up a worker connection indefinitely. |
| `client_header_timeout` | 10s | Same attack shape against the request headers instead of the body. |
| `proxy_connect_timeout` | 5s | The upstream (Juice Shop) being unreachable or the TCP handshake to it hanging — bounds how long nginx waits before failing over/erroring instead of queuing requests behind a dead backend. |
| `proxy_read_timeout` / `proxy_send_timeout` | 30s each | A backend that accepted the connection but then stalls mid-response (or a slow client on the send side) — bounds worker occupancy per request. |
| `keepalive_timeout` | 10s | Idle keep-alive connections held open by a client that never sends a second request, consuming a worker slot for nothing. |

**Command proving a timeout actually fires** (not just configured): I opened a raw TLS socket in Python, sent full headers declaring `Content-Length: 100` but only sent 8 bytes of body, then waited:

```
Sent headers + partial body only (client_body_timeout=10s configured)
Connection closed/response received after 10.0s
Bytes received: (connection closed with no response body)
```

The connection was held open for exactly 10.0 seconds — matching `client_body_timeout 10s` to the decisecond — then nginx closed it. This is a live timer firing, not a configuration value being echoed back.

**OCSP stapling.** OCSP stapling lets the server fetch the certificate's revocation status from the CA once, cache it, and hand it to the client alongside the TLS handshake — saving the client a separate round trip to the CA's OCSP responder before it can trust the cert, which both speeds up the handshake and avoids leaking "I am visiting this site" to the CA on every connection. I left it **disabled** here (`ssl_stapling off;`) because it only makes sense for a certificate a real CA issued and actually publishes revocation status for; this lab's cert is self-signed with no CA behind it to staple a response from, so turning it on would do nothing but add a resolver dependency and startup delay for a feature with no real backing data. It's the correct thing to enable the moment this cert is replaced with a CA-issued one (Task 2's rotation runbook below is exactly that moment).

**Cert rotation runbook, proven with zero failed requests:**

1. Generate/obtain the new cert+key pair (`openssl req -x509 -newkey rsa:2048 ... -out localhost-new.crt -keyout localhost-new.key`).
2. Overwrite the host paths nginx has bind-mounted (`labs/lab11/reverse-proxy/certs/localhost.crt` and `.key`) with the new files — the container never needs to be touched.
3. `docker exec lab11-nginx-1 nginx -s reload` — this sends `SIGHUP`, which makes nginx re-read the config *and* re-open the cert/key files in new worker processes, while existing workers finish serving in-flight connections on the old cert before exiting. No connection is dropped.
4. Verify: `echo | openssl s_client -connect localhost:443 -tls1_3 | openssl x509 -noout -serial` and confirm the serial matches the new cert, not the old one.

I proved this live: I ran a continuous loop of 60 requests (one every 0.1s) against `https://localhost/`, and 1.5 seconds in — mid-loop — replaced the cert files on disk and issued `nginx -s reload`. Result:

```
=== results ===
  60 200
```

All 60 requests returned 200; zero failures across the rotation. I then confirmed the new cert was actually the one being served:

```
$ echo | openssl s_client -connect localhost:443 -tls1_3 | openssl x509 -noout -serial
serial=B330D8A7A2DEC152        # matches the newly generated cert, not the original
```

**Rate limit bypass — per client address.** My `limit_req_zone $binary_remote_addr ...` keys purely on source IP, which an attacker gets around in at least two ways: (1) **a botnet or a rotating proxy pool** — each request arrives from a different source IP, so no single IP ever accumulates enough requests to trip the bucket, even though the aggregate request rate against `/rest/user/login` is identical to a single-IP flood; (2) **IPv6 address rotation on a single host** — an attacker with an IPv6 /64 or larger allocation can trivially source each request from a fresh address in the block (`$binary_remote_addr` treats each distinct address as a separate bucket), defeating the per-address limit without needing any botnet at all. What I'd add at this layer or above it: a second `limit_req_zone` keyed on something the attacker can't rotate as cheaply — e.g. a normalized `/64` for IPv6 (`map` the client address down to its network prefix before using it as the zone key) — and, above this layer, an account-level lockout/backoff on the login endpoint itself (keyed on the `email` field in the request body, which Nginx alone can't see without app-layer help) so that credential stuffing against one username is capped regardless of how many source addresses it's spread across.

## Bonus

**The same request through both paths:**

```
$ curl -sk -o /dev/null -w "%{http_code}\n" "https://localhost/rest/products/search?q=%27%20OR%201%3D1--"
500    # plain nginx proxy (443) — forwarded straight to Juice Shop, which crashed on it

$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8443/rest/products/search?q=%27%20OR%201%3D1--"
403    # WAF path (8443) — blocked before it ever reached the app
```

**CRS rule that fired, from the WAF's JSON log:**

```json
{"message":"SQL Injection Attack Detected via libinjection","details":{
  "match":"detected SQLi using libinjection.","reference":"v28,10",
  "ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
  "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
  "tags":["attack-sqli","paranoia-level/1","OWASP_CRS"]}}
{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110",
  "file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"}}
```

**Rule 942100**, from `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`: it runs the request's `ARGS` (here, `q=' OR 1=1--`) through the `libinjection` SQL-injection detection library, which parses the string as a candidate SQL fragment rather than pattern-matching on keywords — it correctly identified the classic `' OR 1=1--` tautology. Rule 949110 is the CRS anomaly-scoring rule that actually blocks: 942100 contributed 5 points to the transaction's anomaly score, which met the default blocking threshold, and 949110 is what turns that score into the 403.

**False-positive hunt.** I tried a legitimate-looking search containing an apostrophe — the kind of input a real user named "O'Brien" would type:

```
$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8443/rest/products/search?q=O%27Brien"
500
```

This looked like a possible false positive at first glance (non-200), but checking the WAF's own log shows it was **not** blocked — `"is_interrupted":false` and `"messages":[]` — the request passed straight through with no CRS rule firing at all. The 500 is Juice Shop's *own* SQL injection bug: the search endpoint concatenates the query string into a raw SQL statement, and the apostrophe in "O'Brien" breaks that query server-side (`SQLITE_ERROR: near "Brien": syntax error`, visible in the app's own error page). So this is evidence in the other direction: I looked for a false positive on a legitimate apostrophe-containing search and found none — the WAF correctly let it through, and the failure that did occur is a real, independent vulnerability in the app itself (the same class of bug CRS is there to catch on other inputs).

**Rollout plan.** CRS in blocking mode on day one, in front of an application nobody has tuned it against, is exactly how a WAF earns a reputation for "breaking things" and gets disabled at 2am during an incident — the false positives that do exist (unlike the one I went looking for here and didn't find) get discovered by angry users instead of by testing. I'd roll this out in three phases: (1) **detection-only** (`MODSEC_RULE_ENGINE: DetectionOnly`) in front of real production traffic for at least one full business cycle (a week, minimum, to catch batch jobs and less common user flows), collecting every rule that fires without blocking; (2) **triage the detection-only log** — for each rule that fired on legitimate traffic, either add a narrowly-scoped exclusion (tied to the specific endpoint/parameter, not a blanket rule disable) or fix the app if the "false positive" is actually revealing bad input handling; (3) **flip to blocking mode**, starting at a high paranoia level threshold (this config uses `PARANOIA=1`, the least aggressive) and only raising it once each level has been through the same detect-then-triage cycle, rather than jumping straight to the strictest setting CRS offers.
