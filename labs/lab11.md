# Lab 11 — BONUS — Reverse Proxy Hardening: Nginx + WAF

![difficulty](https://img.shields.io/badge/difficulty-advanced-red)
![topic](https://img.shields.io/badge/topic-Reverse%20Proxy-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Nginx%20%2B%20Coraza-informational)

> **Goal:** Put a hardened Nginx reverse proxy in front of Juice Shop (TLS 1.3, full security-header set, rate limiting), document the production posture, and (bonus) drop a Coraza WAF + OWASP CRS sidecar in front of Nginx that catches a real attack pattern.
> **Deliverable:** A PR from `feature/lab11` with `submissions/lab11.md` + your hardened `nginx.conf` (+ Coraza config for the bonus). Submit PR link via Moodle.

> 🌟 **This is a BONUS lab** — 10 pts total (Task 1: 4 + Task 2: 4 + Bonus: 2).
> Bonus labs count toward a separate **20% weight** in your final grade (see README).
> Difficulty is **advanced** — you're expected to operate more independently than in main labs.

---

## Overview

In this lab you will practice:
- **Production-grade Nginx config** — listen, upstream, ssl_protocols, http/2 (Reading 11)
- **TLS 1.3 + HSTS + security headers** — modern crypto + browser-side defenses
- **Rate limiting + connection limits + timeouts** — fail-closed defenses
- **Cipher hardening + session resumption + cert rotation** — production operational posture
- (Bonus) **WAF layer** — Coraza + OWASP Core Rule Set catching attacks Nginx alone lets pass

> **Read Reading 11 first.** It covers everything in this lab + the surrounding tradeoffs.

---

## Project State

**You should have from Labs 1, 8:**
- Juice Shop v20.0.0 deployable locally (Lab 1)
- Familiarity with signed-artifact patterns from Lab 8

**This lab adds:**
- A working `docker-compose` stack: nginx (in front) + juice-shop (behind)
- A hardened `nginx.conf` with all production-grade controls
- (Bonus) A Coraza WAF in front of Nginx, catching attacks Nginx alone misses

---

## Setup

You need:
- **Docker + docker-compose**
- **`openssl`** — for self-signed cert generation
- **`curl`** + **`jq`**

```bash
git switch main && git pull
git switch -c feature/lab11

docker compose version && openssl version
```

> **Plumbing provided** (in `labs/lab11/`):
> - [`labs/lab11/docker-compose.yml`](lab11/docker-compose.yml) — stack with nginx + juice-shop containers wired together
> - [`labs/lab11/reverse-proxy/`](lab11/reverse-proxy/) — bare-bones starter Nginx config

```bash
# Generate self-signed cert. File names MUST be localhost.crt/.key —
# the shipped nginx.conf expects those exact paths under /etc/nginx/certs/.
mkdir -p labs/lab11/reverse-proxy/certs
openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout labs/lab11/reverse-proxy/certs/localhost.key \
  -out labs/lab11/reverse-proxy/certs/localhost.crt \
  -subj "/CN=juice.local" \
  -days 3650
```

---

## Task 1 — TLS + Security Headers (4 pts)

**Objective:** Configure Nginx with TLS 1.3 only, the full security-header set, and verify every header lands on real responses.

### 11.1: Harden the SSL + headers section of `labs/lab11/reverse-proxy/nginx.conf`

```nginx
# YOUR TASK (Task 1 portion): TLS + security headers
# Requirements (Reading 11 covers each in detail):
#
# 1. HTTP server on 80 redirects to HTTPS 443 (301 or 308)
# 2. HTTPS server on 443: ssl_protocols TLSv1.3 only
#    `ssl_prefer_server_ciphers off;` (TLS 1.3 ignores this anyway)
# 3. Six required headers, all with the `always` keyword:
#    - Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
#    - X-Content-Type-Options "nosniff"
#    - X-Frame-Options "DENY"
#    - Referrer-Policy "strict-origin-when-cross-origin"
#    - Permissions-Policy "camera=(), microphone=(), geolocation=()"
#    - Content-Security-Policy-Report-Only (start strict; refine iteratively)
# 4. Upstream proxy to Juice Shop running as the `juice` service on port 3000
```

### 11.2: Bring up the stack

```bash
cd labs/lab11
docker compose up -d
docker compose ps
until curl -sk https://localhost/rest/admin/application-version > /dev/null; do sleep 2; done
echo "✅ Juice Shop reachable via Nginx"
cd -
```

### 11.3: Verify each control

```bash
mkdir -p labs/lab11/results

# A. HTTPS redirect
curl -sI http://localhost | tee labs/lab11/results/http-redirect.txt

# B. TLS 1.3 negotiation
echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | head -8 \
  | tee labs/lab11/results/tls13.txt

# C. Security headers
curl -skI https://localhost | tee labs/lab11/results/headers.txt
```

### 11.4: Document in `submissions/lab11.md`

````markdown
# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
<paste>
```

### A. HTTPS redirect proof
```
<paste http-redirect.txt — must show 301 or 308 to https://>
```

### B. TLS 1.3 proof
```
<paste tls13.txt — must show "Protocol version: TLSv1.3" line>
```

### C. Security headers proof (all 6 present)
```
<paste headers.txt — verify HSTS, X-CTO, X-FO, Referrer-Policy, Permissions-Policy, CSP>
```

### What each header defends against (1 sentence each)
- HSTS: ...
- X-Content-Type-Options: nosniff: ...
- X-Frame-Options: DENY: ...
- Referrer-Policy: ...
- Permissions-Policy: ...
- Content-Security-Policy: ...
````

---

## Task 2 — Rate Limiting, Timeouts, Cipher Hardening, Cert Rotation (4 pts)

> ⏭️ Optional. Skipping won't break Task 1 or the bonus.

**Objective:** Operationalize the production posture — rate limiting on auth endpoints, fail-closed timeouts, modern cipher list, cert-rotation runbook.

### 11.5: Add rate + connection limits + timeouts to `nginx.conf`

```nginx
# YOUR TASK (Task 2 portion):
#
# 1. Rate limit on /rest/user/login (or /api/* if you prefer):
#    `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;`
#    `limit_req zone=login burst=5 nodelay;` in the location block
#    `limit_req_status 429;` in the http block
# 2. Connection limit:
#    `limit_conn_zone $binary_remote_addr zone=conn:10m;`
#    `limit_conn conn 50;` per server
# 3. Timeouts (all fail-closed):
#    `client_body_timeout 10s; client_header_timeout 10s;`
#    `proxy_read_timeout 30s; proxy_connect_timeout 5s;`
# 4. Cipher hardening (Mozilla Modern):
#    `ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;`
#    `ssl_ecdh_curve X25519:secp384r1;`
#    `ssl_session_cache shared:SSL:10m; ssl_session_timeout 1d; ssl_session_tickets off;`
# 5. (Optional in lab; mandatory in prod) OCSP stapling:
#    `ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8 1.1.1.1 valid=300s;`
#    (No effect on a self-signed cert — documentation-only here.)
```

### 11.6: Test the rate limit + timeout

```bash
# Rate limit: 60 concurrent POSTs to login should produce many 429s
seq 1 60 | xargs -n1 -P 30 -I{} curl -sk -o /dev/null -w "%{http_code}\n" \
  https://localhost/rest/user/login 2>/dev/null | sort | uniq -c \
  | tee labs/lab11/results/ratelimit.txt

# Timeout: send a partial HTTP request slowly; nginx should close after client_header_timeout
echo "GET / HTTP/1.0" | timeout 15 nc localhost 443 2>&1 | head -5 \
  | tee labs/lab11/results/timeout.txt

# Cipher: verify TLS 1.3 cipher in use
echo | openssl s_client -connect localhost:443 -tls1_3 2>&1 \
  | grep -E "Cipher|Server Temp Key" | tee labs/lab11/results/cipher.txt
```

### 11.7: Cert rotation runbook

Write the 7-step runbook described in Reading 11 (Detect expiry → Order → Validate → Atomic swap → Verify → Rollback → Audit). Paste into your submission.

### 11.8: Document in `submissions/lab11.md`

````markdown
## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | <n> |
| 429 | <n> |
| 5xx | <n> |

### Timeout enforced
```
<paste timeout.txt>
```

### Cipher hardening
```
<paste cipher.txt — must show "Cipher: TLS_AES_256_GCM_SHA384" and "Server Temp Key: X25519">
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: <how>
2. **Order new cert**: <how>
3. **Validate**: <how>
4. **Atomic swap**: <how>
5. **Verify**: <how>
6. **Rollback plan**: <how>
7. **Audit**: <how>

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
Why is OCSP stapling useful for production but not for a self-signed lab cert?
````

---

## Bonus Task — Coraza WAF + OWASP CRS (2 pts)

> 🌟 **Genuinely valuable.** Reading 11 covered "WAF: The Next Layer". This bonus deploys it. A WAF sidecar catches **categories of attacks Nginx alone passes** — SQL injection probes, XSS payloads, path-traversal attempts. You'll demonstrate the difference.

**Objective:** Drop **Coraza** (Apache 2.0 OSS, Caddy/Envoy/standalone) with **OWASP Core Rule Set** in front of Nginx. Send a payload that Nginx alone proxies happily but Coraza blocks. Read the WAF audit log to confirm which rule fired.

### B.1: Add a Coraza sidecar

Create `labs/lab11/waf/docker-compose.override.yml`:

```yaml
# YOUR TASK: Coraza WAF + OWASP CRS in front of Nginx
#
# Two valid approaches — pick one:
#   (a) Standalone Coraza Server (coraza-spoa or coraza-server) as an SPOA filter
#       in front of Nginx — moderate ops complexity
#   (b) Caddy with the coraza module + OWASP CRS rules — easier, swap Nginx out
#       (but loses your Task 1+2 nginx.conf work)
#   (c) ModSecurity v3 + connector-nginx (the legacy alternative) — most documentation;
#       slightly heavier than Coraza
#
# For this bonus, pick (c) ModSecurity v3 because the OWASP CRS docs are richer:
# https://owasp.org/www-project-modsecurity-core-rule-set/
#
# Requirements:
#   - Service called `waf` (or extend nginx with the ModSec dynamic module)
#   - OWASP CRS v4.x installed
#   - paranoia_level = 1 (production-safe starting point)
#   - SecRuleEngine On (not DetectionOnly — we want it to block)
#   - Audit log to /var/log/modsec/audit.log
```

> **Why ModSecurity v3 over Coraza?** Coraza is the modern Go-based reimplementation, ~70% feature-parity with ModSec v3 as of 2026 and growing. For this lab either works; the OWASP CRS documentation has more ModSec examples, so ModSec is the gentler entry point. Note this in your submission either way.

### B.2: Bring up the WAF + Nginx + Juice Shop stack

```bash
cd labs/lab11
docker compose -f docker-compose.yml -f waf/docker-compose.override.yml up -d
docker compose ps    # WAF + nginx + juice all Up
```

### B.3: Probe with a malicious payload

```bash
# Baseline: through Nginx-only (Task 1 stack) — should reach Juice Shop and return 200/4xx
# but no blocking
curl -sk -o /dev/null -w "no-waf: HTTP %{http_code}\n" \
  "https://localhost/rest/products/search?q='%20OR%201=1--"

# Through WAF: should return 403 (Forbidden) per OWASP CRS Inbound Anomaly Score
curl -sk -o /dev/null -w "with-waf: HTTP %{http_code}\n" \
  "https://localhost-waf/rest/products/search?q='%20OR%201=1--"
# (or whatever endpoint your WAF stack exposes)
```

### B.4: Inspect the audit log

```bash
docker compose exec waf cat /var/log/modsec/audit.log | tail -50 \
  > labs/lab11/results/waf-audit.txt
# Look for the rule ID that fired — typically 942100 (SQL Injection Attack: Common Injection Testing) or 942130-942260
```

### B.5: Document in `submissions/lab11.md`

````markdown
## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: <Coraza / ModSecurity v3 / Caddy+Coraza>
- OWASP CRS version: <4.x>
- Paranoia level: 1

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)
```
no-waf: HTTP 200    # or whatever Juice Shop returns; the point is no block
```

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```
<paste 10-20 lines from waf-audit.txt showing the rule ID + matched value>
```
Rule ID: **<e.g. 942100>** — OWASP CRS rule name: **<e.g. SQL Injection Attack: Common Injection Testing>**

### Tradeoff analysis (3 sentences)
What does the WAF buy you that Lecture 5's SAST + DAST + the L7 Conftest gate didn't already?
What does it COST you? (FP risk at higher paranoia levels; ops overhead; cert/config sprawl.)
When would you NOT deploy a WAF in front of a service?
````

---

## How to Submit

```bash
git add labs/lab11/reverse-proxy/nginx.conf
git add labs/lab11/waf/                    # Bonus only
git add submissions/lab11.md
git commit -m "feat(lab11): hardened nginx + WAF sidecar"
git push -u origin feature/lab11

# Cleanup
cd labs/lab11
docker compose -f docker-compose.yml -f waf/docker-compose.override.yml down
cd -
```

PR checklist body:

```text
- [x] Task 1 — TLS 1.3 + 6 security headers (with proof)
- [ ] Task 2 — Rate limit + timeouts + cipher hardening + cert-rotation runbook
- [ ] Bonus — Coraza/ModSec WAF + OWASP CRS catching a payload Nginx-alone passes
```

---

## Acceptance Criteria

### Task 1 (4 pts)
- ✅ HTTPS serves; HTTP → HTTPS 301 or 308 redirect works
- ✅ TLS 1.3 negotiated (`openssl s_client -tls1_3` succeeds)
- ✅ All 6 security headers present (HSTS, X-CTO, X-FO, Referrer-Policy, Permissions-Policy, CSP)
- ✅ Each header's purpose explained in 1 sentence (no copy-paste from Mozilla docs)

### Task 2 (4 pts)
- ✅ Rate limit demonstrably returns 429 on >10 req/min sustained load
- ✅ Slowloris-style request triggers timeout (408 or connection close)
- ✅ TLS 1.3 cipher suite + X25519 curve in use (verified with `openssl s_client`)
- ✅ Cert-rotation runbook has all 7 steps (detect → order → validate → deploy → verify → rollback → audit)
- ✅ OCSP-stapling explanation references the production-vs-lab gap honestly

### Bonus Task (2 pts)
- ✅ WAF stack runs (Coraza, ModSec, or Caddy+Coraza); choice documented
- ✅ OWASP CRS v4.x installed; paranoia level documented
- ✅ Same payload that Nginx-alone passes returns 403 through WAF
- ✅ Audit log excerpt shows the OWASP CRS rule ID that fired
- ✅ Tradeoff analysis covers what-WAF-buys, FP risk, when-not-to-deploy

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — TLS + headers | **4** | HTTPS redirect + TLS 1.3 + 6 headers with proof + per-header explanation |
| **Task 2** — Production posture | **4** | Rate limit + timeout + cipher hardening + 7-step rotation runbook + OCSP explanation |
| **Bonus Task** — WAF + OWASP CRS | **2** | Stack runs + payload blocked + audit log shows specific rule + tradeoff analysis |
| **Total** | **10** | Task 1 + Task 2 + Bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Reading 11](../lectures/reading11.md) — the deep-dive companion to this lab
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — Pick "Modern"
- [Nginx official `ssl_*` directives](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/) — the WAF rules
- [Coraza documentation](https://coraza.io/docs/) — modern Go-based ModSec alternative
- [ModSecurity v3 + nginx-connector](https://github.com/owasp-modsecurity/ModSecurity-nginx)
- [Caddy + Coraza module](https://github.com/corazawaf/coraza-caddy) — the easiest WAF-with-batteries-included path

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`curl: (60) SSL certificate problem`** — your cert is self-signed. Use `-k` (insecure) flag for testing.
- 🚨 **`add_header` directives disappear on 5xx responses** — always use the `always` keyword.
- 🚨 **TLS 1.3 negotiation falls back to TLS 1.2** — verify with explicit `openssl s_client -tls1_3`.
- 🚨 **Rate limit returns 503 instead of 429** — set `limit_req_status 429;` in the `http {}` block.
- 🚨 **`docker compose up` fails with port-already-in-use on 80/443** — kill local nginx/Apache first, OR remap ports in `docker-compose.yml`.
- 🚨 **Cert file names** — the nginx.conf expects `/etc/nginx/certs/localhost.crt` and `localhost.key`. Use those exact names.
- 🚨 **CSP `default-src 'self'` breaks Juice Shop frontend** — Juice Shop loads inline scripts + remote fonts. Use `Content-Security-Policy-Report-Only` for the lab; tighten iteratively in real deployments.
- 🚨 **WAF paranoia 4 blocks everything** — start at paranoia 1, watch the audit log for legitimate traffic flagged, then escalate.
- 🚨 **WAF audit log empty** — `SecAuditLogParts ABIJDEFHZ` (or similar) must be in the modsecurity.conf; default config sometimes omits the request body parts.
- 💡 **`testssl.sh localhost:443`** is the industry-standard TLS posture tool — run it for a free A-F grade against your config.

</details>

<details>
<summary>🪜 Looking outside this course</summary>

The hardened proxy + WAF stack you built here is **production-grade**:
- Add Let's Encrypt + certbot for real cert automation
- Add `fail2ban` + Nginx access log scraping for IP-based abuse blocking (lighter than WAF, complementary)
- For multi-domain / cluster: Envoy or Traefik often replace Nginx; both support OWASP CRS via plugins
- For cloud: AWS WAF + Cloudflare WAF give you a managed CRS without the ops overhead

"I deployed a WAF with OWASP CRS in front of Juice Shop and watched it stop SQL injection attempts" is a strong interview line.

</details>
