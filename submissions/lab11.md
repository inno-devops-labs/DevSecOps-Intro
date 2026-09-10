# Lab 11 — Edge Hardening

## Task 1

### Redirect
`HTTP/1.1 308 Permanent Redirect` — method-preserving permanent redirect to HTTPS (308 over 301 so POST login is not downgraded to GET).

### TLS 1.3
```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```
Server offers TLS 1.2/1.3 only (`ssl_protocols TLSv1.2 TLSv1.3`).

`testssl.sh --protocols` excerpt:
```
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
```

### Headers (always)
- Strict-Transport-Security: `max-age=31536000; includeSubDomains; preload`
- X-Frame-Options: `DENY`
- X-Content-Type-Options: `nosniff`
- Referrer-Policy: `strict-origin-when-cross-origin`
- Permissions-Policy: `camera=(), geolocation=(), microphone=()`
- Content-Security-Policy-Report-Only: `default-src 'self'; ... script-src 'self' 'unsafe-inline' 'unsafe-eval' ...`

Report-Only first: Juice Shop needs `unsafe-inline`/`unsafe-eval`; enforcing CSP today would break Angular scripts. Collect violation reports, tighten, then flip to enforce.

## Task 2

### Rate limit
`limit_req_zone ... rate=10r/m` + `burst=5 nodelay` on `/rest/user/login`; `limit_req_status 429`.  
Observed: `401 401 401 401 401 401 429 429 429 429 429 429 429 429`.

Also `limit_conn perip 20` and explicit `proxy_*_timeout` values in `nginx.conf`.

### TLS 1.3 suites
`ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256` — CHACHA refused (`openssl s_client ... TLS_CHACHA20_POLY1305_SHA256` → alert/failure count ≥1).

### Timeouts
`proxy_connect_timeout 5s`, `proxy_send_timeout 30s`, `proxy_read_timeout 30s` — protect against slow upstream / stalled clients. Client body/header timeouts also set.

### OCSP stapling
Off here (self-signed lab cert). In production stapling saves clients a round-trip to the CA; enable with a publicly trusted chain + resolver.

### Cert rotation runbook
1. Issue new cert/key beside the old files.  
2. `docker compose exec nginx nginx -t`.  
3. Atomic swap of cert files (or update compose mounts).  
4. `nginx -s reload` (no drop of existing connections).  
5. Verify: `openssl s_client -connect localhost:443` shows new notAfter; `curl -skI https://localhost` still 200.

### Rate-limit bypass
Distributed bots / many IPs; spoofed/X-Forwarded-For if you key on a spoofable header. Mitigate with authenticated edge, CDN/WAF bot scores, and shared rate store keyed on credential+IP.

## Bonus
Same payload `GET /rest/products/search?q=' OR 1=1--`:

| Path | Status | Notes |
|------|-------:|-------|
| Plain nginx `https://localhost/...` | **500** | Juice Shop SQLite error — proxy forwarded the SQLi |
| WAF `http://localhost:8080/...` | **403** | CRS blocked before backend |

CRS rule that fired: **942100** (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`) — "SQL Injection Attack Detected via libinjection" on `ARGS:q`. Anomaly gate **949110** then denied (score ≥ 5).

False-positive check: `q=apple` → **200** on both plain and WAF (no block on a normal search).

Rollout: start CRS in `DetectionOnly`, tune false positives / exception rules against real traffic for 1–2 weeks, raise paranoia only after baseline is quiet, then flip `MODSEC_RULE_ENGINE=On`. Day-one blocking without a tuning window is how teams disable the WAF after the first broken checkout.
