# Lab 11 — Nginx reverse proxy (Juice Shop)

## Task 1 — Compose + why a proxy

Reverse proxy in front of the app is useful because: TLS and certs live on one box, you can bolt on headers and rate limits without touching Node, filter weird requests before they hit the app, and expose a single port pair to the internet instead of every microservice port.

Juice Shop only has `expose: 3000` — no `ports:` on the host. Only Nginx publishes **8080** (HTTP) and **8443** (HTTPS). That way scanners and bots hit the proxy first; the app isn’t directly reachable on the LAN.

`docker compose ps` (saved as `labs/lab11/analysis/compose-ps.txt`):

```
NAME            IMAGE                           ...   PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   ...   3000/tcp
lab11-nginx-1   nginx:stable-alpine             ...   0.0.0.0:8080->8080/tcp, 0.0.0.0:8443->8443/tcp
```

HTTP → HTTPS redirect:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
# HTTP 308
```

**Certs:** `localhost.crt` / `localhost.key` are **not** in git (`.gitignore` + pre-commit hates private keys). Generate once before `docker compose up` — see `labs/lab11/reverse-proxy/certs/README.txt` or:

```bash
docker run --rm -v "$(pwd)/reverse-proxy/certs:/certs" alpine:latest sh -c \
  "apk add --no-cache openssl && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
   -keyout /certs/localhost.key -out /certs/localhost.crt -subj '/CN=localhost' \
   -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'"
```

(Run from `labs/lab11` so `$(pwd)/reverse-proxy/certs` is correct.)

---

## Task 2 — Headers

Raw dumps: `labs/lab11/analysis/headers-http.txt`, `headers-https.txt`.

**HTTPS** (main app response) includes:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; ...
```

**HTTP** (port 8080) has the same security headers on the **308** redirect, but **no** `Strict-Transport-Security` — HSTS only on the TLS server block, as it should be.

What they’re for:

| Header | What it helps with |
| ------ | ------------------- |
| **X-Frame-Options** | Clickjacking — page can’t be framed by another origin. |
| **X-Content-Type-Options** | MIME sniffing — browser shouldn’t “guess” types and execute stuff wrong. |
| **HSTS** | Tells browsers to use HTTPS only for this host for a long time. |
| **Referrer-Policy** | Limits what URL leaks in the `Referer` header on cross-origin navigation. |
| **Permissions-Policy** | Disables powerful APIs (camera, mic, geo) by default. |
| **COOP / CORP** | Isolates your browsing context and resources from cross-origin pages (helps with Spectre-style issues and embedding). |
| **CSP-Report-Only** | Logs policy violations without blocking — sane for Juice Shop until you tune a real CSP. |

---

## Task 3 — TLS, testssl, rate limits, timeouts

### testssl.sh (Windows / Docker Desktop)

```bash
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 | tee analysis/testssl.txt
```

Full log: `labs/lab11/analysis/testssl.txt` (ANSI colors from the tool).

**Protocols:** SSLv2/3, TLS 1.0/1.1 not offered. **TLS 1.2** and **TLS 1.3** offered (1.3 is negotiated as final where supported).

**Cipher order (from scan):**  
TLS 1.2: `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-GCM-SHA256`.  
TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`.

**Why TLS 1.2+:** older protocols have known attacks (POODLE, BEAST-era design issues). TLS 1.3 trims handshake cruft and prefers modern AEAD ciphers; you still keep 1.2 for older clients.

**Expected ugly bits with a dev cert:** self-signed chain, no OCSP/CRL, no CT, hostname mismatch when hitting `host.docker.internal` from inside the container, grade capped in testssl — all normal until you use a real CA (Let’s Encrypt) and optional stapling.

**Vuln section:** Heartbleed, ROBOT, SWEET32, etc. reported **not vulnerable** for this listener.

### Rate limiting

`nginx.conf`: `limit_req_zone ... rate=10r/m`, on `/rest/user/login` → `limit_req zone=login burst=5 nodelay`.

12 quick POSTs with fake JSON credentials (`analysis/rate-limit-test.txt`):

```
401
401
401
401
401
401
429
429
429
429
429
429
```

So **6×401** (Juice Shop rejects bad login) then **6×429** (Nginx rate limit). The **401**s still count toward the limit — that’s what you want for brute-force: failed logins burn the budget.

**10r/m + burst 5:** ~10 requests per minute sustained, with a short bucket of 5 extra for bursty UI; stricter would annoy real users, looser would help password guessing.

**Timeouts** (from `nginx.conf`): `client_body_timeout` / `client_header_timeout` / `send_timeout` **10s** on the HTTPS server; `proxy_read_timeout` / `proxy_send_timeout` **30s**, `proxy_connect_timeout` **5s** to upstream. Shorter client timeouts hurt slowloris-style dribbles but can cut off very slow uploads; proxy timeouts need to be above worst-case app latency or you’ll see 502s on heavy pages.

**429 in access log:** see `labs/lab11/analysis/access-log-rate-limit.txt` (copy of the relevant `access.log` lines). Live `logs/*.log` is gitignored so the repo doesn’t fill with noise.

---

## Files

| Path | What |
| ---- | ---- |
| `labs/lab11/docker-compose.yml` | stack |
| `labs/lab11/reverse-proxy/nginx.conf` | headers, TLS, limits |
| `labs/lab11/reverse-proxy/certs/README.txt` | how to create cert + key locally |
| `labs/lab11/analysis/*` | curl headers, testssl, rate test, compose ps, log snippet |

## Cleanup

```bash
cd labs/lab11
docker compose down
```
