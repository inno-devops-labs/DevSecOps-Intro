# Lab 11 — Submission

A hardened Nginx reverse proxy in front of Juice Shop: TLS, security headers, rate/connection
limits, and a WAF — each control proven with a command.

## Setup

Self-signed cert (`/CN=localhost`, 2048-bit, 30 days) in `reverse-proxy/certs/`, so every `curl`
uses `-k` and `openssl s_client` always prints a verify error (expected).

**Port note:** host port 80 was already taken, so I remapped HTTP to **9080** and kept HTTPS on the
standard **443** (which was free, so redirect targets like `https://localhost/` resolve normally).
The HTTP-redirect test therefore uses `http://localhost:9080`; every HTTPS URL is unchanged.

## Task 1 — TLS and headers

### Redirect

```
$ curl -sI -H 'Host: localhost' http://localhost:9080
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

**308, not 301.** A 308 is a *permanent* redirect that **preserves the method and body** — a
POST stays a POST. 301 historically let clients rewrite POST→GET, which silently breaks API calls;
since Juice Shop is API-backed, 308 is the safe permanent choice (307 would be the non-cacheable
equivalent).

### TLS

```
$ openssl s_client -connect localhost:443 -tls1_3 -brief
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

Server-side protocol enumeration (testssl, which carries its own TLS stack):

```
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
```

Only 1.2 and 1.3 are offered — 1.0/1.1 and the SSLv2/3 are off at the server, not just refused by
my client.

### The six headers (as returned by the server)

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:;
  script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

All set with `always`, so they survive 4xx/5xx responses — which is exactly when a browser is most
exposed.

### Why CSP is Report-Only, and the path to enforcement

If I enforced this CSP against Juice Shop today it would break the app. Juice Shop is an Angular
SPA: even with `'unsafe-inline' 'unsafe-eval'` permitting its inline scripts, the policy sets no
`connect-src`, so it falls back to `default-src 'self'` and would block the app's `socket.io`
WebSocket and any XHR to other origins, and `img-src 'self' data:` would block product images
served from elsewhere. The path to enforcement is: keep **Report-Only** and wire up a
`report-uri`/`report-to` endpoint, collect real violation reports from actual usage, then
iteratively widen the policy to the legitimate sources those reports reveal while tightening away
from `'unsafe-inline'` (moving to nonces or hashes). Only once the report stream is clean for a
representative period do you rename the header to `Content-Security-Policy` and enforce. You get to
enforcement by measuring first, never by guessing the allowlist.

## Task 2 — Availability controls

### Rate limit

```
$ for i in $(seq 1 14); do curl ... -X POST https://localhost/rest/user/login ...; done
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

Config: `limit_req_zone … rate=10r/m` with `limit_req zone=login burst=5 nodelay` on
`location = /rest/user/login`, and `limit_req_status 429`. At 10r/min one request is admitted at
the steady rate plus a burst of 5 = **6 reach the app (401 from Juice Shop)**, and the remaining
**8 are rejected with 429** (not the nginx-default 503, which would tell a client to retry instead
of back off). A per-address connection cap is also set: `limit_conn perip 20`.

### Cipher restriction and proof

TLS 1.3 suites are pinned to AES-GCM with the correct directive (`ssl_ciphers` does **not** affect
1.3):

```nginx
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

```
$ openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
  | grep -icE 'alert|failure'
1                                 # a suite outside the list is refused
$ openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256   # an allowed suite still works
```

### Timeouts

| Directive | Value | Protects against |
|---|---|---|
| `proxy_connect_timeout` | 5s | upstream that won't accept the connection (dead/overloaded Juice Shop) |
| `proxy_send_timeout` | 30s | upstream stalling while nginx sends it the request |
| `proxy_read_timeout` | 30s | upstream that accepts but never responds (hung backend) |
| `client_header_timeout` | 10s | Slowloris — a client dribbling request headers to hold a worker |
| `client_body_timeout` | 10s | slow-body variant — announcing a body and sending it a byte at a time |
| `send_timeout` | 10s | a client that stops reading the response to pin a connection open |

**Proof a timeout actually fires** — I announced a 50-byte body, sent 4 bytes, and stalled; nginx
closed it after exactly the 10s `client_body_timeout`:

```
"POST /rest/user/login HTTP/1.1" 408 0 "-" "-" rt=10.010 uct=- urt=-
```

### OCSP stapling

OCSP stapling saves the client a round-trip and a privacy leak: instead of the browser contacting
the CA's OCSP responder to check whether the cert is revoked (which is slow and tells the CA which
sites the user visits), the server fetches that signed OCSP response itself and *staples* it to the
handshake. **I did not enable it here** because the certificate is self-signed — there is no CA
OCSP responder to staple a response from, so the directive would do nothing. On a publicly-trusted
cert I would enable it (`ssl_stapling on; ssl_stapling_verify on;` with a `resolver` and
`ssl_trusted_certificate`).

### Cert rotation runbook (zero failed requests)

1. Stage the new cert + key next to the old ones (new filenames), don't overwrite yet.
2. Validate the new pair: `openssl x509 -noout -subject -dates -fingerprint -in new.crt` and
   confirm the key matches (`openssl x509 -modulus` == `openssl rsa -modulus`).
3. Point the config at the new files (or atomically swap the paths).
4. `nginx -t` — never reload an invalid config.
5. `nginx -s reload` — a **graceful** reload: existing connections drain on the old workers while
   new connections pick up the new cert. No connection is dropped.
6. Verify live:
   `echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -dates -fingerprint`
   and confirm the fingerprint/expiry match the new cert.
7. Only after verification, remove the old key.

### Per-address rate limit — two bypasses, and what to add

The limit keys on `$binary_remote_addr`, so an attacker evades it by **spreading the attack across
many source IPs** — a botnet, a pool of cloud/proxy egress IPs — where each address stays under
10r/min while the aggregate is huge. Second, **shared-IP collateral works in reverse**: many real
users behind one NAT/corporate egress hit the limit together, so an attacker on that same IP hides
in legitimate traffic (and can grief those users). (Spoofing `X-Forwarded-For` does *not* work here,
because we key on the real connection address, not the header.) What I'd add: rate-limit per
**account/credential**, not just per IP (cap login attempts per email), add exponential backoff or
a CAPTCHA on repeated failures, and push a reputation-aware rate limit / bot management to the
**edge (CDN/WAF)** above this proxy, where distributed sources can be correlated.

## Bonus — A WAF that catches what the proxy forwards

A CRS-enabled ModSecurity WAF (`owasp/modsecurity-crs:nginx`, CRS 4.30.0) in the same compose
project on port **9081**, blocking mode (`MODSEC_RULE_ENGINE=On`), with Juice Shop still
unpublished so it's reachable only through a proxy.

### Same request, both paths

`GET /rest/products/search?q=' OR 1=1--`:

| Path | Status |
|---|---|
| Plain proxy (443) | **500** — forwarded the injection to Juice Shop, which errored on it |
| Through the WAF (9081) | **403** — blocked before it reached the app |

The plain proxy forwards the SQLi without comment (the 500 is Juice Shop's own vulnerable query
choking on it, exactly as in Lab 5); the WAF refuses it.

### The CRS rule that fired

From the WAF's audit log, two rules:

- **`942100` — "SQL Injection Attack Detected via libinjection"**
  (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`). This is the detector: it runs the argument through
  **libinjection**, a tokenizing library that recognizes the *structure* of SQL injection rather
  than matching keywords — here `Matched Data: s&1c found within ARGS:q: ' OR 1=1--`. It scored the
  request severity CRITICAL.
- **`949110` — "Inbound Anomaly Score Exceeded (Total Score: 5)"**
  (`REQUEST-949-BLOCKING-EVALUATION.conf`). CRS is anomaly-scoring: 942100 added to the score, it
  crossed the inbound threshold of 5, and 949110 is the rule that actually returns the 403.

### False-positive hunt — found none

I ran a range of legitimate requests through the WAF: the homepage, `q=apple`,
`q=select a juice`, `/api/Products`, `/rest/admin/application-version`, a valid login, a password
with `<`, `&` and quotes, and — the classic SQLi-lookalike — a search for **`O'Brien`**. The WAF
blocked **none** of them (total 403s in the log stayed at 1, the actual attack). The `O'Brien`
search is the telling one: it returned 500, not 403 — the WAF *forwarded* it (libinjection is
structural, so a bare apostrophe in a name doesn't look like injection) and Juice Shop's own
vulnerable query is what broke. So at paranoia level 1 I found no false positive, and I have a
useful reminder that the WAF is a shield, not a fix: the SQL injection bug is still there behind it.

### How I'd roll this out in front of a real app

Turning CRS on in blocking mode on day one is how teams end up disabling the WAF: it blocks real
users on day one and the business demands it be switched off. Instead I'd deploy it first in
**DetectionOnly** (`MODSEC_RULE_ENGINE=DetectionOnly`) against real production traffic, so it logs
what it *would* block without blocking anything. I'd watch those logs for a representative period,
tune out the false positives with targeted rule exclusions and the right paranoia level, and only
then flip to blocking — ideally per-route or to a small traffic percentage first, with the anomaly
threshold and alerting in place. Blocking is the last step, not the first.

## Artifacts

- `labs/lab11/reverse-proxy/nginx.conf` — the hardened proxy config (committed deliverable).
- `labs/lab11/waf/docker-compose.override.yml` — the CRS WAF (committed, bonus).
- `labs/lab11/results/*.txt` — the command outputs above (uncommitted).
