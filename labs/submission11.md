# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### Stack startup
I deployed OWASP Juice Shop behind an Nginx reverse proxy using Docker Compose. A local self-signed certificate with SAN entries for `localhost`, `127.0.0.1`, and `::1` was generated so that Nginx could start with HTTPS enabled.

### Reverse proxy value for security
Using a reverse proxy improves security because it provides:
- **TLS termination** at a single controlled entry point
- **Security header injection** without modifying application code
- **Request filtering and rate limiting** before traffic reaches the app
- **A single access point** that simplifies exposure control and monitoring

### Why hiding the direct app port matters
Keeping Juice Shop internal reduces attack surface because clients cannot connect to the application container directly. This forces all traffic through Nginx, where TLS, headers, limits, and timeouts are enforced consistently.

### Compose evidence
Output from `docker-compose ps`:

```text
NAME                IMAGE                           COMMAND                  SERVICE             CREATED             STATUS              PORTS
lab11-juice-1       bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice               2 minutes ago       Up 2 minutes        3000/tcp
lab11-nginx-1       nginx:stable-alpine             "/docker-entrypoint.…"   nginx               2 minutes ago       Up 2 minutes        0.0.0.0:8080->8080/tcp, :::8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, :::8443->8443/tcp
```

This shows that:

Nginx publishes host ports 8080 and 8443
Juice Shop has no published host ports and is only reachable internally
HTTP redirect evidence
HTTP 308

This confirms that HTTP on port 8080 redirects to HTTPS on port 8443.

## Task 2 — Security Headers

### HTTP header verification

Relevant headers seen on HTTP:

X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

### HTTPS header verification

Relevant headers seen on HTTPS:

strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

### Header analysis

X-Frame-Options: DENY
Prevents clickjacking by stopping the site from being embedded inside a frame or iframe.

X-Content-Type-Options: nosniff
Stops browsers from MIME-sniffing content types and reduces the risk of content being interpreted as executable script when it should not be.

Strict-Transport-Security (HSTS)
Forces browsers to use HTTPS for future requests and helps prevent SSL stripping attacks. In this setup it appears only on HTTPS responses, which is the correct behavior.

Referrer-Policy: strict-origin-when-cross-origin
Reduces leakage of full URLs and query data to other origins while still preserving useful referrer data for same-origin navigation.

Permissions-Policy
Disables browser features such as camera, geolocation, and microphone for this application unless explicitly allowed. This reduces unnecessary client-side capability exposure.

COOP / CORP

Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin

These headers help isolate browsing contexts and reduce some cross-origin interaction risks, including classes of cross-origin data leakage and window reference abuse.

CSP-Report-Only
A report-only CSP is useful for testing policy strictness without breaking app functionality. This is especially important for Juice Shop because it is JavaScript-heavy and likely to break under a strict enforced CSP. Report-Only provides visibility into what would be blocked while keeping the lab usable.

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### TLS scan summary

The testssl.sh scan showed the following protocol support:

SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final

This means only TLS 1.2 and TLS 1.3 are enabled, which is the desired configuration.

### Supported cipher suites

Observed supported cipher suites included:

TLSv1.2
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-RSA-AES128-GCM-SHA256

TLSv1.3
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
Why TLS 1.2+ is required

TLS 1.0 and 1.1 are deprecated and lack the stronger protections expected in modern deployments. Enabling only TLS 1.2 and TLS 1.3 reduces exposure to legacy protocol weaknesses and improves compatibility with modern strong cipher suites. TLS 1.3 is preferred because it simplifies configuration and improves security and performance.

Warnings / expected dev limitations from testssl

The main negative findings were related to the development certificate:

Chain of trust               NOT ok (self signed)
OCSP URI                     --
NOT ok -- neither CRL nor OCSP URI provided
OCSP stapling                not offered
Overall Grade                T
Grade cap reasons            Grade capped to T. Issues with chain of trust (self signed)

These results are expected with a local self-signed certificate. In production, they would be addressed by using a trusted public CA or a trusted local CA such as mkcert, and by enabling OCSP stapling when using a real certificate chain.

### HSTS verification

HSTS appeared on HTTPS responses:

strict-transport-security: max-age=31536000; includeSubDomains; preload

It did not appear in the HTTP header output, which is correct.

Rate limiting test results

Rate limiting was tested against /rest/user/login using repeated POST requests.

Observed output:

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

Counts:

200 count: 0
429 count: 6

Interpretation:

The first six requests returned 401, meaning the requests reached the application but used invalid credentials.
The next six requests returned 429, meaning Nginx rate limiting activated and blocked additional requests.

This confirms the login endpoint is protected by the configured proxy-side request limiting.

### Rate limit configuration analysis

The lab uses:

rate=10r/m
burst=5
limit_req_status 429

This is a reasonable trade-off:

A low sustained rate reduces brute-force and automated credential stuffing risk.
A burst allowance lets normal users make a few quick retries without being blocked immediately.
Returning 429 clearly signals throttling instead of silently failing.

The trade-off is that limits set too aggressively can affect legitimate users, especially if multiple users share an IP or if someone retries quickly after a typo.

### Timeout analysis

The Nginx configuration also includes timeout controls such as:

client_body_timeout
client_header_timeout
proxy_read_timeout
proxy_send_timeout

These help reduce abuse such as slow client attacks and resource exhaustion.

Trade-offs:

Lower timeout values improve resilience against slowloris-style behavior and stalled upstream interactions.
If set too low, they can break legitimate slow clients or long-running responses.
In practice, these should be tuned based on expected application behavior and client characteristics.
Access log evidence for 429 responses

Relevant lines from Nginx access log:

172.20.0.1 - - [22/Apr/2026:19:32:23 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [22/Apr/2026:19:32:23 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [22/Apr/2026:19:32:23 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [22/Apr/2026:19:32:23 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [22/Apr/2026:19:32:23 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.20.0.1 - - [22/Apr/2026:19:32:23 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-

## Overall conclusion

This lab demonstrated how an operations team can materially improve application security without changing application code. By placing Juice Shop behind Nginx, I was able to:

terminate TLS at the proxy
inject important browser security headers
enforce HTTPS with HSTS
reduce brute-force and burst abuse through rate limiting
reduce slow-client and stalled-connection risk with timeout settings

The main trade-off is usability versus strictness: stronger headers, lower timeouts, and tighter rate limits improve security, but if tuned too aggressively they can affect application compatibility or legitimate users. Using CSP in Report-Only mode was a good example of balancing hardening with app stability.
