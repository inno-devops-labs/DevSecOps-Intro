# Lab 11 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (TLS + headers) · Task 2 (rate limits / timeouts / ciphers) · **Bonus Task** (OWASP CRS WAF, +2 pts)

## Environment

| Item | Value |
|------|-------|
| Stack | `labs/lab11/docker-compose.yml` + `labs/lab11/waf/docker-compose.override.yml` |
| Proxy | `https://localhost` (80→443) |
| WAF | `http://127.0.0.1:8081` → Juice Shop (juice not published) |
| Cert | self-signed `localhost.crt` / `localhost.key` (curl `-k`) |

## Task 1

### Redirect

```bash
curl -sI http://localhost | head -2
```

```text
HTTP/1.1 308 Permanent Redirect
```

**308** (not 301): permanent, and it preserves method/body on the follow-up. A POST login must not become a GET after the upgrade to HTTPS.

### TLS 1.3 negotiation + protocol table

```bash
echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
```

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

Scanner (`testssl.sh --protocols`):

```text
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
```

### Six headers (`curl -skI https://localhost`)

```text
strict-transport-security: max-age=31536000; includeSubDomains
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

### CSP Report-Only → enforce

Juice Shop’s Angular UI loads inline scripts, eval-ish patterns, and CDN fonts. Enforcing today’s Report-Only policy **without** `'unsafe-inline'` / `'unsafe-eval'` (or nonces/hashes) would blank the SPA. Process: ship Report-Only, collect violations for a week, add hashes/nonces or tighten third parties, flip to enforce behind a feature flag, watch error budgets, then remove Report-Only.

## Task 2

### Rate limit

Configured: `limit_req_zone … rate=10r/m`, `burst=5 nodelay`, `limit_req_status 429` on `location = /rest/user/login`.

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

First six reach Juice Shop (401 for bad creds); then **429** from nginx. Also `limit_conn per_client 20` with `limit_conn_status 429`.

### TLS 1.3 AES-GCM only

```nginx
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

```bash
echo | openssl s_client -connect localhost:443 -tls1_3 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure'
# → 1 ; Cipher is (NONE)
```

### Timeouts

| Directive | Value | Protects against |
|-----------|-------|------------------|
| `proxy_connect_timeout` | 5s | hung upstream TCP accept |
| `proxy_send_timeout` | 30s | stalled request body to upstream |
| `proxy_read_timeout` | 30s (global) | stalled upstream response |

Proof it fires (temporary `/timeout-demo` → blackhole upstream with `proxy_read_timeout 3s`):

```text
HTTP 504 time=3.051137
```

### OCSP stapling

Stapling saves the client an extra round trip to the CA’s OCSP responder and hides that check from the network. **Off here**: the cert is self-signed with no OCSP responder; enabling stapling would add complexity and no client benefit.

### Cert rotation runbook (zero failed requests)

1. Issue/place new `localhost.crt` + `localhost.key` beside the live files (or write to `localhost.crt.new`).
2. `mv` atomically into the bind-mounted paths (same inodes nginx already has open until reload).
3. `docker compose exec nginx nginx -t && docker compose exec nginx nginx -s reload` (graceful; workers finish in-flight).
4. Verify: `echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -fingerprint -sha256` matches the new cert; `curl -skI https://localhost` → 200.

### Rate-limit bypasses

Per-IP limits lose to **distributed bots** (many source IPs) and to **clients behind a shared NAT** (one IP hammers everyone, or an attacker spoofs/`X-Forwarded-For` if you trusted it — we set `X-Forwarded-For` from `$remote_addr` only). Add credential stuffing detections, CAPTCHA/step-up after N failures, edge CDN/WAF IP reputation, and auth-layer lockouts keyed on account id, not only address.

## Bonus

### Same payload, two paths

| Path | Request | Status |
|------|---------|-------:|
| Plain nginx | `https://localhost/?q=' OR 1=1--` | **200** |
| CRS WAF `:8081` | `http://127.0.0.1:8081/?q=' OR 1=1--` | **403** |

### CRS rule that fired

From WAF audit log: **`942100`** — “SQL Injection Attack Detected via libinjection” (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`), matched `ARGS:q: ' OR 1=1--`. Blocking evaluation **`949110`** raised the anomaly score over the threshold.

### False-positive hunt

At paranoia level 1 I tried legitimate-looking traffic: `/?q=O'Brien` → **200** (CRS did not interrupt; only advisory `920350` when Host was a numeric IP); `/rest/products/search?q=O'Brien` → **500** with `is_interrupted: false` — that is Juice Shop choking on the apostrophe, not CRS. Product names like `union` / `drop` also passed. A `User-Agent: sqlmap/1.0` **was** blocked by **`913100`** (scanner fingerprint) — intentional, not a customer FP. **Result: no clear false positive on normal Juice Shop browse/search at PL1**; the day-one risk would show up under higher paranoia or messier traffic (JSON bodies, CMS paths, marketing UTM strings).

### Rollout

Do **not** start in blocking mode on day one. Deploy detection-only, tune false positives on real traffic, raise paranoia slowly, then enable blocking behind a canary / path allow-list, with an owner and a kill switch. Teams that flip CRS to block on day one usually disable the WAF after the first marketing campaign with apostrophes in names.

## Cleanup

`docker compose -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml down -v`
