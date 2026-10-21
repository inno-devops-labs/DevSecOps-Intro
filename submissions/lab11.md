# Lab 11 — Edge Hardening with a Reverse Proxy

Stack: `bkimminich/juice-shop:v20.0.0` with no published port, behind `nginx:stable-alpine` on 80/443,
plus an `owasp/modsecurity-crs:nginx` WAF on 8080 for the bonus. Self-signed cert, so every `curl` uses
`-k`. OpenSSL 3.6.4, curl 8.7.1, on Docker (Colima).

## Task 1

### The redirect

```console
$ curl -sI http://localhost | head -1
HTTP/1.1 308 Permanent Redirect
```

I chose **308**, not 301. Both are permanent, but 301 historically let clients rewrite a POST to the
redirected URL as a GET, which silently drops the body. 308 requires the client to repeat the original
method and body, so a `POST /rest/user/login` over HTTP is redirected to the same POST over HTTPS rather
than turning into a GET. For an API behind the proxy that correctness matters, and there is no downside
for the plain `GET /` case.

### TLS: what was negotiated, and what the server offers

```console
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

That the negotiated 1.3 suite is `TLS_AES_256_GCM_SHA384` (AES-GCM) rather than ChaCha20 is the
`ssl_conf_command Ciphersuites` restriction working, proven further in Task 2.

The scanner shows what the server actually *offers*, independent of what my client will speak:

```console
$ docker run --rm --network host drwetter/testssl.sh:3.2 --protocols https://localhost
 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
```

TLS 1.0 and 1.1 are not offered by the server, which is the point: `openssl s_client -tls1_1` locally only
proves my OpenSSL refuses 1.1, not that the far end does. testssl carries its own TLS stack and asks.

### The six headers, as returned

```console
$ curl -skI https://localhost | grep -iE 'strict-transport|x-frame|x-content-type|referrer|permissions|content-security'
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

All six carry `always`, so they survive 4xx/5xx responses, which is exactly when a browser is most exposed.

### Why Report-Only, and the path to enforcement

I set `Content-Security-Policy-Report-Only` rather than an enforcing `Content-Security-Policy` because
enforcing this policy against Juice Shop today would break the app. Juice Shop is an Angular single-page
app that relies on inline scripts and styles and runtime-evaluated code; even the permissive policy here
(`script-src 'self' 'unsafe-inline' 'unsafe-eval'`) is looser than I would want, and a stricter one would
block the bundle from running and leave a blank page. Report-Only lets the browser evaluate the policy and
send violation reports without blocking anything, so I can see what a given policy *would* break before it
breaks it. The path to enforcement is: ship Report-Only, collect violation reports for a representative
period of real usage, tighten the directives (replace `unsafe-inline` with nonces or hashes, drop
`unsafe-eval` once the code no longer needs it) until the report stream goes quiet, and only then rename the
header to the enforcing `Content-Security-Policy`. Enforcement is the last step, not the first.

## Task 2

### The rate limit biting

```console
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST \
    https://localhost/rest/user/login -H 'Content-Type: application/json' \
    -d '{"email":"a@b.c","password":"x"}'; done; echo
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

Configured `limit_req_zone ... rate=10r/m` with `limit_req zone=login burst=5 nodelay` on the
`= /rest/user/login` location only, and `limit_req_status 429`. The first six requests pass (one at the
base rate plus the burst of five, released immediately by `nodelay`) and reach Juice Shop, which returns
401 for the bad credentials; the seventh onward exceed the burst and get **429**, not nginx's default 503.
429 is correct here: it tells the client it is being throttled and to slow down, where 503 would invite a
retry. The limit is scoped to the login endpoint, so browsing the catalogue is unaffected.

### The cipher restriction

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

`ssl_ciphers` controls TLS 1.2 only; the TLS 1.3 suites are AES-GCM-only via `ssl_conf_command
Ciphersuites`. A client offering only ChaCha20 is refused, while an AES-GCM suite connects:

```console
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure'
1
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 2>&1 | grep 'Cipher is'
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

`-ciphersuites` is the TLS 1.3 selector; `-cipher TLS_AES_...` would fail inside OpenSSL before connecting
and prove nothing about the server.

### Timeouts, and one firing

```nginx
proxy_connect_timeout 5s;   # cap time to establish the upstream TCP connection; a dead/slow backend fails fast instead of tying up a worker
proxy_send_timeout 30s;     # cap time between successive writes to the upstream; a stalled upstream read does not hang the proxy forever
proxy_read_timeout 30s;     # cap time waiting for the upstream's response; protects against a backend that accepts but never answers
client_header_timeout 10s;  # cap time to send the request headers; defeats a slowloris that dribbles headers
client_body_timeout 10s;    # cap time to send the request body; defeats a slow-body (R-U-Dead-Yet) attack
send_timeout 10s;           # cap time between successive writes to the client; reclaims a worker stuck on a client that stops reading
```

`client_body_timeout` firing, shown by holding a POST open with a declared `Content-Length` but no body:

```console
$ ( printf 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50\r\n\r\n'; sleep 30 ) \
    | openssl s_client -connect localhost:443 -quiet
# ...nginx closes the connection with "unexpected eof" at ~11s, matching the 10s client_body_timeout
```

The connection is held, not answered, and nginx tears it down at the 10-second body timeout (measured ~11s
with 1-second polling granularity) rather than waiting forever.

### OCSP stapling

OCSP stapling has the server fetch the CA's signed revocation status and attach ("staple") it to the TLS
handshake, so the **client** does not make its own OCSP call to the CA. That saves the client a round trip
on connect and, more importantly, stops it leaking to the CA which sites it visits. I left it **off** here
(`ssl_stapling off`) because the certificate is self-signed: there is no CA OCSP responder to fetch from, so
stapling has nothing to staple. With a publicly-trusted certificate I would enable it (`ssl_stapling on;
ssl_stapling_verify on;` plus a `resolver`), because the privacy and latency win is real and the cost is a
periodic fetch the server already caches.

### Certificate rotation runbook (zero failed requests)

1. **Stage** the new `localhost.crt` and `localhost.key` next to the live ones, without overwriting yet.
2. **Validate the new pair before it goes live**: confirm the key matches the cert
   (`openssl x509 -noout -modulus -in new.crt | openssl md5` equals
   `openssl rsa -noout -modulus -in new.key | openssl md5`) and the dates are right
   (`openssl x509 -noout -dates -in new.crt`).
3. **Swap the files** into the mounted path, then **reload, do not restart**: `nginx -s reload` (SIGHUP).
   Reload starts new workers with the new certificate and lets the old workers finish their in-flight
   requests, so no connection is dropped. A `restart` would drop every live connection; that is the step
   people get wrong.
4. **Verify the new cert is live** from outside:
   `echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -fingerprint -dates`
   and confirm the fingerprint and `notAfter` are the new ones.
5. **Remove** the old key material once the new cert is confirmed serving.

### The per-address rate limit is bypassable

My `limit_req` keys on `$binary_remote_addr`, the real TCP source address, so two concrete bypasses are:
(1) **distribute the source** — a botnet or a pool of cloud IPs spreads the login attempts so no single
address crosses 10/min, and the per-IP limit never triggers; (2) **rotate addresses** — an attacker cycles
through proxies, a residential-proxy network, or a fresh IPv6 address per attempt (a /64 gives effectively
unlimited addresses), each looking like a new client. What I would add: move the primary throttle to the
**credential/account** dimension at the app or an auth gateway (lock or step-up after N failures *for an
account*, regardless of source IP), add a global anomaly detector on the login endpoint, and put a
reputation-aware control (the WAF below, or a fail2ban-style blocklist fed from the 429 logs) in front so
distributed low-and-slow attempts are correlated rather than counted one IP at a time.

## Bonus — a WAF that catches what the proxy forwards

### Same payload, both paths

```console
$ curl -sk -o /dev/null -w '%{http_code}\n' "https://localhost/rest/products/search?q=' OR 1=1--"   # plain proxy
500
$ curl -s  -o /dev/null -w '%{http_code}\n' "http://localhost:8080/rest/products/search?q=' OR 1=1--" # WAF
403
```

The plain proxy forwards the injection and Juice Shop's unparameterised query errors into a **500**; the
WAF refuses it with **403** before it ever reaches the app.

### The CRS rule that fired

From the WAF's JSON audit log:

```
id "942100"  "SQL Injection Attack Detected via libinjection"
  file REQUEST-942-APPLICATION-ATTACK-SQLI.conf, severity 2 (CRITICAL), CRS 4.30.0
  "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"
id "949110"  "Inbound Anomaly Score Exceeded (Total Score: 5)"  -> the 403
```

**942100** is the detection: it runs the request arguments through *libinjection*, a SQL-injection
tokenizer, and flags `' OR 1=1--` as an injection. CRS is anomaly-scoring, so 942100 adds to the inbound
score and **949110** is the blocking-evaluation rule that turns a score of 5 (at or above the threshold)
into the 403. The detection names the attack; the evaluation rule pulls the trigger.

### False-positive hunt — looked, found none at PL1

I ran legitimate inputs that look injection-ish through the WAF:

```
q=union jack flag  -> 200    q=select the best -> 200    q=C++ tutorial -> 200
q=a < b comparison -> 200    q=1+1=2 math      -> 200    q=100% cotton  -> 200
q=ping -c 4        -> 200    login passwords with & | && ; -> 401 (reached the app)
```

None were blocked. The one interesting case is an apostrophe name: `q=O'Reilly books` returns **500**, not
403 — the WAF's libinjection correctly does *not* treat a lone apostrophe in a name as SQLi and lets it
through, after which Juice Shop's own injectable query errors on it. So that 500 is evidence the WAF is
*not* over-blocking a legitimate apostrophe, and a reminder the WAF is not a substitute for the
parameterised-query fix the app still needs. At paranoia level 1, I found no legitimate request the WAF
wrongly blocks.

### Rolling CRS out in front of a real app

Turning CRS to blocking on day one is how teams end up disabling the WAF: the first legitimate request it
wrongly blocks becomes an incident, and the fastest fix under pressure is to switch it off. I would roll it
out in **DetectionOnly** first (`MODSEC_RULE_ENGINE=DetectionOnly`), pointed at real production traffic,
and watch the audit log for which rules fire on legitimate requests. Then I would tune: write targeted
exclusions for the genuine false positives (per-rule, per-endpoint, not blanket disables), start at
paranoia level 1 and raise it only once the lower level is clean, and lower the anomaly threshold
gradually. Only after the detection-mode log is quiet against real traffic would I flip a single service to
blocking, ideally behind a canary so a mistake affects a slice of traffic rather than everyone. Blocking is
the destination; detection-and-tune is the road to it.
