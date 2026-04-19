# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1

**Why reverse proxies are valuable:**

A reverse proxy sits in front of the application and provides multiple security benefits: it terminates TLS so the backend never needs to handle certificates; it injects security headers centrally without modifying application code; it can filter, rate-limit, and log requests before they reach the app; and it provides a single, well-hardened access point to enforce policy uniformly across all traffic.

**Why hiding direct app ports reduces attack surface:**

Hiding direct application ports means attackers cannot reach the app container even if they discover the internal port. Without the proxy layer, an attacker who knows port 3000 is open could bypass all header injection, rate limiting, and TLS entirely. Exposing only the proxy's ports (8080/8443) restricts the attack surface to a hardened choke point.

**Docker-compose output:**

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     8 minutes ago   Up 8 minutes   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     8 minutes ago   Up 8 minutes   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Juice Shop exposes only the internal `3000/tcp` with no host binding; only Nginx publishes ports to the host (8080 and 8443).

## Task 2

Security headers from `analysis/headers-https.txt`:

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

- **X-Frame-Options**: Prevents the page from being embedded in an `<iframe>` on another origin, blocking clickjacking attacks where a malicious site overlays a transparent frame to steal clicks.
- **X-Content-Type-Options**: Instructs browsers not to MIME-sniff the response content type, preventing attacks where a browser interprets a non-script file as executable JavaScript.
- **Strict-Transport-Security (HSTS)**: Forces the browser to use HTTPS for all future requests to this origin for `max-age` seconds (1 year here), including subdomains. Prevents SSL-stripping downgrade attacks. Present only on the HTTPS server block — absent on HTTP responses.
- **Referrer-Policy**: Controls how much of the current URL is sent in the `Referer` header on navigation. `strict-origin-when-cross-origin` sends only the origin (not path/query) when crossing origins, reducing leakage of sensitive URL parameters to third parties.
- **Permissions-Policy**: Restricts which browser features (camera, microphone, geolocation) the page and embedded frames can access, reducing the damage surface if the app is compromised or serves malicious content.
- **COOP/CORP**: `Cross-Origin-Opener-Policy: same-origin` isolates the browsing context group so cross-origin pages cannot access the window object, mitigating Spectre-style side-channel attacks. `Cross-Origin-Resource-Policy: same-origin` blocks other origins from loading this site's resources (e.g. images, scripts) via `<img>` or `fetch`, preventing cross-site information leakage.
- **CSP-Report-Only**: Defines a Content Security Policy in report-only mode so violations are logged without blocking content. Set in report-only rather than enforcing mode because Juice Shop uses `unsafe-inline` and `unsafe-eval` extensively; enforcing would break the app. It still allows operators to observe policy violations and tighten the policy iteratively.

## Task 3

**TLS protocol support** (from `analysis/testssl.txt`):
- SSLv2: not offered (OK)
- SSLv3: not offered (OK)
- TLS 1.0: not offered
- TLS 1.1: not offered
- TLS 1.2: offered (OK)
- TLS 1.3: offered (OK)

**Cipher suites supported:**

TLSv1.2:
- `ECDHE-RSA-AES256-GCM-SHA384` (ECDH 256-bit, AES-256-GCM)
- `ECDHE-RSA-AES128-GCM-SHA256` (ECDH 256-bit, AES-128-GCM)

TLSv1.3:
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

All suites provide forward secrecy (ECDHE/ECDH key exchange) and authenticated encryption (AEAD). No NULL, export, RC4, or DES ciphers are offered.

**Why TLSv1.2+ is required (prefer TLSv1.3):** TLS 1.0 and 1.1 use outdated primitives vulnerable to POODLE, BEAST, and CRIME attacks, and have been deprecated by RFC 8996. TLSv1.2 with AEAD ciphers is still secure, but TLSv1.3 removes legacy negotiation, mandates forward secrecy, reduces handshake round-trips, and eliminates a large class of protocol-level attacks. Preferring TLSv1.3 ensures the strongest available protection for clients that support it.

**Warnings / vulnerabilities from testssl:**
- `Chain of trust NOT ok` — self-signed certificate; expected in a local dev setup. To eliminate: use a locally-trusted CA (e.g. mkcert) or a public CA (Let's Encrypt) for a real domain.
- No CRL or OCSP URI provided — revocation checking is unavailable for this certificate.
- OCSP stapling not offered — can be enabled with a public CA and the `ssl_stapling on` directives (commented out in nginx.conf).
- DNS CAA record not present — only relevant for public domains.
- Overall grade capped to **T** solely due to the self-signed chain; all vulnerability tests (Heartbleed, POODLE, BEAST, RC4, CRIME, ROBOT, etc.) pass as NOT vulnerable.

**HSTS only on HTTPS:** HSTS appears in `analysis/headers-https.txt` (`strict-transport-security: max-age=31536000; includeSubDomains; preload`) and is absent from `analysis/headers-http.txt` — correct, since sending HSTS over plain HTTP is meaningless and potentially misleading.

---

**Rate-limit test output** (`analysis/rate-limit-test.txt`):

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

6 requests returned `401` (invalid credentials, passed through) and 6 returned `429` (rate-limited). The burst of 5 allows up to 6 requests to pass before the limiter kicks in (1 initial + 5 burst), matching the observed results.

**Rate limit configuration:** `rate=10r/m` permits 10 requests per minute per IP (one token every 6 seconds). `burst=5` allows a short spike of up to 5 extra requests to be queued and served immediately (`nodelay`), preventing false positives for rapid but legitimate multi-step flows (e.g. a page that fires several API calls on load). Above that, requests are rejected with `429`. This balances security — making brute-force attacks slow enough to be impractical — against usability, as legitimate users completing a login in a single click are unaffected.

**Timeout settings** (from `nginx.conf`):

| Directive | Value | Purpose & trade-off |
|---|---|---|
| `client_body_timeout` | 10s | Maximum time to receive the full request body. Protects against slow-body Slowloris variants that send the body 1 byte at a time to exhaust connections. Too low risks dropping legitimate clients on slow links. |
| `client_header_timeout` | 10s | Maximum time to receive request headers. Defends against slow-header Slowloris attacks. Same trade-off: very restrictive values may affect users on high-latency connections. |
| `proxy_read_timeout` | 30s | Time Nginx waits for the upstream (Juice Shop) to send a response. Set higher than client timeouts to give the app time to process heavier requests without surfacing errors to the user prematurely. |
| `proxy_send_timeout` | 30s | Time allowed between successive writes from Nginx to the upstream. Prevents stalled connections from tying up worker slots indefinitely. |

**Access log — 429 responses:**

```
172.19.0.1 - - [19/Apr/2026:14:24:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [19/Apr/2026:14:24:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [19/Apr/2026:14:24:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [19/Apr/2026:14:24:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [19/Apr/2026:14:24:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [19/Apr/2026:14:24:29 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
```

`rt=0.000` and `uct=-` confirm these requests never reached the upstream — Nginx rejected them at the rate-limit layer before any proxy connection was made.
