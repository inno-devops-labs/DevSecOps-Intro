# Lab 11 Submission — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

**Environment:** macOS host with Docker `28.5.2`, Docker Compose `v2.40.3`, `curl 8.7.1`, `jq 1.7.1`  
**Date completed:** 2026-04-20

This lab was validated locally on `http://localhost:8080` and `https://localhost:8443`. All runtime evidence was saved under `labs/lab11/analysis/` and `labs/lab11/logs/`.

## Task 1 — Reverse Proxy Compose Setup

### What I did

- Created the required directories: `labs/lab11/reverse-proxy/certs`, `labs/lab11/logs`, and `labs/lab11/analysis`
- Generated a self-signed RSA-2048 certificate with SAN entries for `localhost`, `127.0.0.1`, and `::1`
- Started the stack with `docker compose up -d`
- Verified that the app is reachable only through Nginx and that HTTP redirects to HTTPS
- Kept the generated certificate and private key as local-only runtime material rather than versioned artifacts

Relevant evidence files:

- `labs/lab11/analysis/docker-compose-ps.txt`
- `labs/lab11/analysis/http-redirect.txt`
- `labs/lab11/analysis/juice-startup.log`
- `labs/lab11/analysis/nginx-startup.log`

### Why a reverse proxy improves security

- It centralizes **TLS termination**, so the backend app can stay simple while clients still get HTTPS.
- It injects **security headers** even when the application does not set them itself.
- It provides a single place for **request filtering, rate limiting, logging, and timeout policy**.
- It creates a single externally reachable entrypoint, which simplifies auditing and makes bypasses harder.

### Why hiding direct app ports reduces attack surface

- Clients cannot bypass the proxy and reach Juice Shop without the added security headers and rate limits.
- Only one service is exposed to the host network, which reduces the number of externally reachable sockets.
- Logging and controls stay consistent because all traffic must flow through Nginx first.

### Container exposure evidence

`docker compose ps` shows that only Nginx publishes host ports and Juice Shop is internal-only:

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     Up              3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     Up              80/tcp, 0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

HTTP redirect verification:

```text
HTTP/1.1 308 Permanent Redirect
Location: https://localhost:8443/
```

## Task 2 — Security Headers

### Header verification

HTTP response headers were captured in `labs/lab11/analysis/headers-http.txt`, and HTTPS response headers were captured in `labs/lab11/analysis/headers-https.txt`.

Relevant HTTPS headers:

```text
HTTP/2 200
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

HTTP redirect response:

```text
HTTP/1.1 308 Permanent Redirect
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

`Strict-Transport-Security` appears only on HTTPS, which is the correct behavior. It is absent from the HTTP redirect response.

### What each header protects against

- **X-Frame-Options: DENY** blocks clickjacking by preventing the app from being embedded in frames.
- **X-Content-Type-Options: nosniff** prevents MIME sniffing, reducing the chance that browsers execute content as a different type than intended.
- **Strict-Transport-Security (HSTS)** tells browsers to prefer HTTPS for future requests, reducing downgrade and SSL stripping risk after the first secure visit.
- **Referrer-Policy: strict-origin-when-cross-origin** limits how much URL/referrer data leaks to other origins.
- **Permissions-Policy** disables sensitive browser features like camera, geolocation, and microphone unless explicitly allowed.
- **COOP/CORP** (`Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`) isolate the browsing context and resource sharing model, helping reduce XS-Leaks and unsafe cross-origin interactions.
- **CSP-Report-Only** defines a resource loading policy and surfaces violations without enforcing the policy yet, which is safer for an app like Juice Shop that may break under a strict enforced CSP.

## Task 3 — TLS, HSTS, Rate Limiting, and Timeouts

### TLS scan summary

Primary scan evidence:

- `labs/lab11/analysis/testssl.txt`
- `labs/lab11/analysis/testssl-clean.txt`
- `labs/lab11/analysis/testssl-summary.txt`
- `labs/lab11/analysis/testssl-ciphers.txt`

Protocol support from `testssl.sh`:

- TLS `1.2` is enabled
- TLS `1.3` is enabled
- SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are disabled
- ALPN offers `h2` and `http/1.1`

Supported cipher suites reported by the scan:

- TLS 1.2: `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-GCM-SHA256`
- TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`

Why TLS 1.2+ is required:

- TLS 1.0 and 1.1 are deprecated and lack modern security guarantees expected by current clients and standards.
- TLS 1.2 and especially TLS 1.3 provide stronger ciphers, better handshake behavior, and broader modern client support.
- Keeping only TLS 1.2+ reduces exposure to older protocol weaknesses and makes downgrade attacks harder.

Warnings and scan observations:

- The certificate hostname matched correctly for `localhost`.
- The certificate chain is **not trusted** because it is a **self-signed local development certificate**.
- `OCSP URI` is absent and `OCSP stapling` is not offered.
- `Certificate Transparency` is absent.
- The overall grade is capped to `T` because of the self-signed certificate, which is expected in this localhost lab.
- During `testssl.sh`, Nginx recorded `SSL_do_handshake() failed ... wrong version number` entries in `error.log`; this is expected probe noise from the scanner rather than an application outage.
- No major classic TLS flaws were detected in the scan results: Heartbleed, CCS, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, and RC4 checks all came back OK/not vulnerable.

HSTS verification:

- HTTPS response includes `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- HTTP redirect response does **not** include HSTS

This matches the recommended pattern: HSTS should only be sent over HTTPS.

### Rate limiting results

Evidence files:

- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/rate-limit-summary.txt`
- `labs/lab11/analysis/access-429.log`
- `labs/lab11/analysis/access-tail.txt`

The login test sent 12 rapid POST requests to `/rest/user/login`:

```text
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

Summary:

```text
401 6
429 6
```

Interpretation:

- The first 6 requests were allowed through to Juice Shop and failed normally with `401 Unauthorized` because the credentials were invalid.
- The next 6 requests were blocked by Nginx with `429 Too Many Requests`.
- This matches the configured policy: `rate=10r/m` with `burst=5` and `nodelay`. In practice, that allows one request at the configured rate plus a small burst window for short spikes, then rejects excess traffic immediately.

Why these values are a reasonable balance:

- `10r/m` is restrictive enough to slow brute-force attacks on login endpoints.
- `burst=5` allows short legitimate bursts from impatient users, browser retries, or racey frontends.
- `nodelay` avoids queuing requests for too long; excess traffic is rejected quickly instead of tying up proxy resources.
- The trade-off is that aggressive login retries from a shared IP can hit the limit sooner, so production values should be tuned to expected real-user behavior.

Relevant `429` log lines from `access.log`:

```text
192.168.163.1 - - [20/Apr/2026:16:48:45 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.163.1 - - [20/Apr/2026:16:48:45 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.163.1 - - [20/Apr/2026:16:48:45 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.163.1 - - [20/Apr/2026:16:48:45 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.163.1 - - [20/Apr/2026:16:48:45 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.163.1 - - [20/Apr/2026:16:48:45 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

### Timeout settings and trade-offs

The proxy uses these main timeout controls in `labs/lab11/reverse-proxy/nginx.conf`:

- `client_body_timeout 10s` limits how long Nginx waits for the client request body. This helps against slow POST uploads and slowloris-style behavior, but can affect legitimately slow clients on poor networks.
- `client_header_timeout 10s` limits how long request headers may trickle in. This is useful against slow header attacks, but very slow clients may be dropped earlier.
- `proxy_read_timeout 30s` limits how long Nginx waits for the upstream app to send a response. This prevents hung upstreams from occupying proxy resources forever, but very long-running application responses may need a larger value.
- `proxy_send_timeout 30s` limits how long Nginx waits while sending data to the upstream. This prevents stuck backend connections from lingering indefinitely.
- `proxy_connect_timeout 5s` fails fast if the upstream cannot be reached.
- `send_timeout 10s` and `keepalive_timeout 10s` further reduce the impact of slow or idle clients.

These values are a good hardening baseline for an interactive web app, but production tuning should consider actual user latency, large uploads, and long-running requests.

## Files Changed

- `labs/lab11/docker-compose.yml`
- `labs/lab11/reverse-proxy/nginx.conf`
- `labs/submission11.md`

## Deliverables

- Compose and startup evidence: `labs/lab11/analysis/docker-compose-ps.txt`, `labs/lab11/analysis/http-redirect.txt`, `labs/lab11/analysis/juice-startup.log`, `labs/lab11/analysis/nginx-startup.log`
- Header evidence: `labs/lab11/analysis/headers-http.txt`, `labs/lab11/analysis/headers-https.txt`
- TLS evidence: `labs/lab11/analysis/testssl.txt`, `labs/lab11/analysis/testssl-clean.txt`, `labs/lab11/analysis/testssl-summary.txt`, `labs/lab11/analysis/testssl-ciphers.txt`
- Rate limit and logs: `labs/lab11/analysis/rate-limit-test.txt`, `labs/lab11/analysis/rate-limit-summary.txt`, `labs/lab11/analysis/access-429.log`, `labs/lab11/analysis/access-tail.txt`, `labs/lab11/analysis/error-tail.txt`, `labs/lab11/logs/access.log`, `labs/lab11/logs/error.log`

## Submission Note

The lab instructions expect a branch, commit, and PR as the final delivery step. In this workspace I prepared all required artifacts locally under `labs/lab11/` and `labs/submission11.md`, but I intentionally did not perform the git branch/commit/PR step here.

## Final Checklist

- [x] Nginx reverse proxy running
- [x] Juice Shop not directly exposed on host ports
- [x] Security headers verified on HTTP/HTTPS
- [x] HSTS verified only on HTTPS
- [x] TLS enabled and scanned with `testssl.sh`
- [x] Rate limiting verified with `429` responses and log evidence
- [x] Timeouts and trade-offs documented
