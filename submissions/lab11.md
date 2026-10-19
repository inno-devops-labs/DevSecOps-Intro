# Lab 11 — Edge Hardening with a Reverse Proxy

## Task 1

### Redirect
```
HTTP/1.1 308 Permanent Redirect
```
Chose **308** over 301 so a `POST /rest/user/login` is not silently converted to GET by intermediates that still treat 301 as method-rewriting. Permanent, method-preserving.

### TLS 1.3 (OpenSSL 3 via `alpine/openssl` on host network)
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
```

### Protocol table (`testssl.sh:3.2 --protocols`)
```
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
```
(`ssl_protocols TLSv1.2 TLSv1.3` — LibreSSL on macOS cannot speak TLS 1.1 to probe the server; the scanner’s own stack is the real enumeration.)

### Six headers (`curl -skI https://localhost`, all with `always`)
```
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Report-Only first: Juice Shop’s Angular UI needs `'unsafe-inline'` / `'unsafe-eval'`. Enforcing a strict CSP today breaks scripts, styles, and inline bootstrapping. Path to enforce: ship Report-Only → collect `report-uri`/`report-to` violations for a week of real traffic → allow-list the few hashes/nonces that remain → flip the header name to `Content-Security-Policy` behind a feature flag.

Config: `labs/lab11/reverse-proxy/nginx.conf`.

## Task 2

### Rate limit
Zone: `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;`  
On `location = /rest/user/login`: `limit_req zone=login burst=5 nodelay;` + `limit_req_status 429`.  
Also `limit_conn_zone` / `limit_conn perip 20` with `limit_conn_status 429`.

Observed 14 POSTs:
```
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```
First six within burst+rate reach Juice Shop (401); then nginx answers 429.

### TLS 1.3 cipher restriction
```
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```
Proof CHACHA is refused (`-ciphersuites TLS_CHACHA20_POLY1305_SHA256`):
```
SSL alert number 40
ssl/tls alert handshake failure
grep -icE 'alert|failure' → 1
```

### Timeouts
In `nginx.conf`: `proxy_connect_timeout 5s`, `proxy_send_timeout 30s`, `proxy_read_timeout 30s` (plus client body/header/send 10s).

| Directive | Protects against |
|-----------|------------------|
| `proxy_connect_timeout` | hung TCP handshake to a dead upstream |
| `proxy_send_timeout` | stalled request body upload to upstream |
| `proxy_read_timeout` | upstream that accepts then never responds |

Firing proof (same knobs, 3s read timeout → blackhole upstream `hang-backend:9999`):
```
http=504 time=3.015337
```
(`labs/lab11/results/timeout-fire.txt` — 504 Gateway Timeout after ~3s, not a hung client.)

### OCSP stapling
Stapling saves the client a round-trip to the CA’s OCSP responder and keeps soft-fail browsers from “failing open.” **Off here**: the lab cert is self-signed, so there is no CA responder to staple. Enable only with a publicly trusted chain + `resolver` + `ssl_trusted_certificate`.

### Cert rotation runbook (zero failed requests)
1. Issue new `localhost.crt` / `localhost.key` next to the live files (new names).
2. `docker compose exec nginx nginx -t` against a config pointing at the new paths (or stage files beside the mount).
3. Atomically replace the mounted files (write to `*.new`, then `mv`).
4. `docker compose exec nginx nginx -s reload` (workers finish in-flight requests on the old cert).
5. Verify live: `openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -dates` shows the new `notAfter`; `curl -skI https://localhost` still 200.

### Rate-limit bypass
Per-IP limits lose to (1) **distributed bots** (many source IPs) and (2) **clients behind CGNAT / shared egress** (many users, one IP — or the attacker rotating cloud egress). At this layer add credential+IP keys and CAPTCHA after N failures; above it, CDN/WAF bot scores and auth-aware quotas.

## Bonus

Same payload `GET /rest/products/search?q=' OR 1=1--`:

| Path | Status |
|------|-------:|
| Plain nginx `https://localhost/...` | **500** (Juice Shop SQLite error — proxy forwarded SQLi) |
| WAF `http://localhost:8080/...` | **403** (blocked before backend) |

CRS rule from WAF log: **942100** — “SQL Injection Attack Detected via libinjection” on `ARGS:q` (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`). Anomaly gate **949110** then denied (inbound score ≥ 5). CRS **4.30.0**, ModSecurity 3.0.17.

False-positive check: `q=apple` → **200** on both plain and WAF.

Rollout: start with `MODSEC_RULE_ENGINE=DetectionOnly`, tune exceptions against real traffic for 1–2 weeks, raise paranoia only after the noise floor is known, then flip to blocking. Day-one blocking without that window is how teams disable the WAF after the first broken checkout.

Override: `labs/lab11/waf/docker-compose.override.yml` (`owasp/modsecurity-crs:nginx`, port **8080**, `BACKEND=http://juice:3000`).
