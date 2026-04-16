# Reverse Proxy Hardening with Nginx

## Reverse Proxy Setup

OWASP Juice Shop was started behind an Nginx reverse proxy with Docker Compose. Only Nginx published host ports: `8080` for HTTP and `8443` for HTTPS. Juice Shop exposed only `3000/tcp` inside the Compose network, so clients cannot bypass the proxy and reach the app directly.

Reverse proxies improve security by acting as a single controlled entry point for TLS termination, security headers, request filtering, logging, and rate limiting. Hiding the direct app port reduces attack surface because external clients cannot bypass these proxy controls.

Evidence: `labs/lab11/analysis/compose-ps.txt`, `labs/lab11/analysis/http-redirect.txt`.

## Security Headers

Security headers were verified on both HTTP and HTTPS. HTTP responses included the hardening headers but did not include HSTS, while HTTPS responses included HSTS as expected.

Relevant HTTPS headers:

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

- `X-Frame-Options` blocks clickjacking through framing.
- `X-Content-Type-Options` prevents browser MIME sniffing.
- `Strict-Transport-Security` forces future browser requests to HTTPS.
- `Referrer-Policy` reduces referrer leakage to other origins.
- `Permissions-Policy` disables unused browser features such as camera, geolocation, and microphone.
- `COOP/CORP` reduce cross-origin window and resource exposure.
- `CSP-Report-Only` observes CSP violations without breaking Juice Shop functionality.

Evidence: `labs/lab11/analysis/headers-http.txt`, `labs/lab11/analysis/headers-https.txt`.

## TLS and HSTS

TLS was enabled with a local self-signed certificate for `localhost`, `127.0.0.1`, and `::1`. `testssl.sh` showed that only TLS 1.2 and TLS 1.3 are offered; SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are disabled.

Supported cipher suites:

- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

TLSv1.2+ is required to avoid obsolete protocol weaknesses; TLSv1.3 is preferred because it removes legacy cryptographic options and provides strong forward secrecy by default. 
`testssl.sh` did not report common TLS vulnerabilities such as Heartbleed, POODLE, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, or RC4. 
The remaining warnings are expected for localhost: self-signed trust chain, no OCSP/CRL/CT/CAA, and no OCSP stapling. In production, this should use a trusted CA certificate and OCSP stapling where applicable.


Evidence: `labs/lab11/analysis/testssl.txt`.

## Rate Limiting and Timeouts

The login endpoint was tested with 12 rapid failed requests. The result was `6` responses with `401`, followed by `6` responses with `429`, so the Nginx login rate limit was enforced.

```text
401 401 401 401 401 401
429 429 429 429 429 429
```

The relevant access log lines show Nginx returning `429` for `/rest/user/login`.

Evidence: `labs/lab11/analysis/rate-limit-test.txt`, `labs/lab11/analysis/access-429.txt`, `labs/lab11/logs/access.log`.

The login limit is `rate=10r/m` with `burst=5` and `nodelay`. This allows a few normal retry attempts while quickly slowing brute-force attempts; in production the values should be tuned from real authentication traffic and acceptable false-positive risk.

Timeouts are also configured to reduce slow-client and upstream exhaustion risk: `client_body_timeout 10s`, `client_header_timeout 10s`, `proxy_read_timeout 30s`, and `proxy_send_timeout 30s`. The trade-off is that tighter timeouts protect capacity but can affect users on slow networks or legitimate long-running requests.
