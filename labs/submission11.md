Отлично, у тебя уже **вся лаба фактически готова**: есть `docker compose ps`, заголовки, `testssl`, `rate-limit-test.txt` и строки `429` из `access.log` 

Ниже — **готовый `labs/submission11.md`**, который можешь вставить почти целиком.

````md
# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse proxy compose setup

OWASP Juice Shop was deployed behind an Nginx reverse proxy. A reverse proxy is valuable for security because it provides a single controlled entry point to the application. It can terminate TLS, inject security headers, enforce request filtering such as rate limiting, and centralize logging without changing application code.

Hiding the direct application port reduces the attack surface. If the backend service is not exposed to the host, clients cannot bypass the reverse proxy and connect directly to the application. This ensures that all requests pass through the Nginx security controls.

### docker compose ps

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     5 seconds ago   Up 4 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     5 seconds ago   Up 4 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
````

The output shows that only Nginx publishes host ports. The Juice Shop container is internal only and does not expose port 3000 directly to the host.

### HTTP redirect check

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost:8443/
```

This confirms that HTTP traffic is redirected to HTTPS.

---

## Task 2 — Security headers

### HTTPS response headers

```text
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Header analysis

* **X-Frame-Options: DENY** — protects against clickjacking by preventing the page from being embedded in an iframe.
* **X-Content-Type-Options: nosniff** — prevents MIME type sniffing and reduces the risk of the browser interpreting content as a different type.
* **Strict-Transport-Security (HSTS)** — tells browsers to use HTTPS only for future requests after the first successful HTTPS visit.
* **Referrer-Policy: strict-origin-when-cross-origin** — limits how much referrer information is shared with other origins.
* **Permissions-Policy** — disables access to sensitive browser features such as camera, geolocation, and microphone.
* **Cross-Origin-Opener-Policy (COOP)** — isolates the browsing context from cross-origin documents to reduce cross-origin attacks.
* **Cross-Origin-Resource-Policy (CORP)** — restricts how cross-origin resources can be loaded by other origins.
* **Content-Security-Policy-Report-Only** — allows testing a CSP policy without breaking application functionality, because violations are only reported and not enforced.

### HSTS verification

HSTS appears only on the HTTPS response and not on the HTTP redirect response. This is the correct behavior because HSTS should only be sent over secure connections.

---

## Task 3 — TLS, HSTS, rate limiting, and timeouts

### TLS scan summary

The TLS scan showed that:

* **TLS 1.2** is enabled.
* **TLS 1.3** is enabled.
* **SSLv2, SSLv3, TLS 1.0, and TLS 1.1** are not offered.

This is the desired configuration because old protocol versions are outdated and have known weaknesses. TLS 1.2 is the minimum acceptable version in modern deployments, and TLS 1.3 is preferred because it improves both security and performance.

### Supported cipher suites

**TLS 1.2**

* `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
* `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

**TLS 1.3**

* `TLS_AES_256_GCM_SHA384`
* `TLS_CHACHA20_POLY1305_SHA256`
* `TLS_AES_128_GCM_SHA256`

These are modern strong cipher suites with forward secrecy.

### testssl findings

The scan did not report major protocol or cipher vulnerabilities. It showed that the server was **not vulnerable** to issues such as:

* Heartbleed
* CCS injection
* Ticketbleed
* CRIME
* POODLE
* SWEET32
* FREAK
* DROWN
* LOGJAM
* BEAST
* LUCKY13
* RC4-related weaknesses

### Expected warnings

Some warnings were expected because the lab uses a **self-signed certificate** on localhost:

* Chain of trust: **NOT ok (self signed)**
* Hostname/domain mismatch in the scan context
* No OCSP/CRL URI
* No OCSP stapling
* No Certificate Transparency information
* Final grade capped because of trust issues with the local self-signed certificate

These results are normal in a local development environment. In a production deployment, this would be fixed by using a certificate from a trusted public CA or a trusted local CA such as `mkcert`, and by enabling OCSP stapling.

### HSTS confirmation

The HTTPS response includes:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

The HTTP response did not include HSTS, which is correct.

---

## Rate limiting

### Rate-limit test output

```text
500
500
500
500
500
500
429
429
429
429
429
429
```

This confirms that repeated login requests eventually triggered **HTTP 429 Too Many Requests** on `/rest/user/login`.

The earlier `500` responses were application responses during invalid login attempts, but the important security result is that Nginx began rejecting excessive requests with `429`, confirming that rate limiting was active.

### Rate-limit configuration analysis

The configuration uses:

* `rate=10r/m`
* `burst=5`

This means:

* up to **10 requests per minute** are allowed at the normal rate,
* with an additional **burst of 5 requests** allowed temporarily.

This is a reasonable balance between security and usability. It slows down brute-force login attempts and automated abuse, while still allowing short bursts of legitimate user activity without immediate blocking.

### access.log evidence of 429

```text
172.25.0.1 - - [21/Apr/2026:12:40:34 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.25.0.1 - - [21/Apr/2026:12:40:34 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.25.0.1 - - [21/Apr/2026:12:40:34 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.25.0.1 - - [21/Apr/2026:12:41:25 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.25.0.1 - - [21/Apr/2026:12:41:25 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.25.0.1 - - [21/Apr/2026:12:41:25 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

### Timeout settings and trade-offs

The Nginx timeout settings such as:

* `client_body_timeout`
* `client_header_timeout`
* `proxy_read_timeout`
* `proxy_send_timeout`

help reduce the risk of slow client attacks such as slowloris and stalled upstream connections.

* **client_body_timeout** limits how long the server waits for the request body.
* **client_header_timeout** limits how long the server waits for request headers.
* **proxy_read_timeout** limits how long Nginx waits for a response from the backend.
* **proxy_send_timeout** limits how long Nginx waits while sending data to the backend.

These settings improve resilience against abuse, but aggressive timeout values can affect slow clients or unstable networks. The trade-off is between availability for legitimate slow connections and resistance to resource exhaustion attacks.

---

## Conclusion

The lab objectives were completed successfully:

* Juice Shop was placed behind an Nginx reverse proxy.
* The backend application was not directly exposed to the host.
* Security headers were added and verified.
* HTTP was redirected to HTTPS.
* HSTS was present only on HTTPS responses.
* TLS 1.2 and TLS 1.3 were enabled with modern cipher suites.
* TLS scan results were strong apart from expected localhost self-signed certificate warnings.
* Login rate limiting successfully returned HTTP 429 for excessive requests.
* Access logs confirmed that the rate limit was enforced.
`


