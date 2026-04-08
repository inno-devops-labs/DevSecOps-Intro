# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Goal

Place OWASP Juice Shop behind an Nginx reverse proxy and harden it with security headers, TLS, and request rate limiting without changing app code.

## Task 1 — Reverse Proxy Setup

I started the stack with Docker Compose and generated a local self-signed certificate for `localhost`.

Evidence:

- `labs/lab11/reverse-proxy/certs/localhost.crt`
- `labs/lab11/reverse-proxy/certs/localhost.key`
- `labs/lab11/reverse-proxy/nginx.conf`
- `labs/lab11/analysis/compose-ps.txt`
- `labs/lab11/analysis/http-redirect.txt`

`docker compose ps` shows:

- `juice` is only exposed internally on `3000/tcp`
- `nginx` publishes `8080` and `8443`

The HTTP endpoint redirects to HTTPS:

- `HTTP 308`

Why this design helps:

- TLS terminates at the proxy, so the app itself does not need to manage certificates.
- Security headers are injected centrally and consistently.
- Request filtering and rate limiting can be enforced at the edge.
- The app is not directly published on a host port, which reduces attack surface.

## Task 2 — Security Headers

I captured the proxy headers in:

- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`

Relevant HTTPS headers observed:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), geolocation=(), microphone=()`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'`

Header purpose:

- `X-Frame-Options`: blocks clickjacking by preventing the site from being framed.
- `X-Content-Type-Options`: prevents MIME sniffing and content-type confusion.
- `Strict-Transport-Security`: forces browsers to use HTTPS for future requests.
- `Referrer-Policy`: limits how much URL context is leaked in the `Referer` header.
- `Permissions-Policy`: disables unnecessary browser APIs such as camera, geolocation, and microphone.
- `COOP/CORP`: reduces cross-origin data leakage and isolates the browsing context.
- `CSP-Report-Only`: provides visibility into CSP violations without breaking Juice Shop functionality.

HTTP vs HTTPS behavior:

- The HTTP redirect response includes the non-HSTS headers, but not HSTS.
- HSTS appears only on the HTTPS response, which is the expected behavior.

## Task 3 — TLS, HSTS, Rate Limiting, and Timeouts

TLS scan evidence:

- `labs/lab11/analysis/testssl.txt`

Protocol support from `testssl.sh`:

- TLS 1.2: offered
- TLS 1.3: offered
- TLS 1.0/1.1: not offered
- SSLv2/SSLv3: not offered

Cipher suites observed:

- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES128-GCM-SHA256`

Important TLS observations:

- The certificate is self-signed, so chain-of-trust validation is expected to fail in `testssl`.
- OCSP/CRL/CAA information is not available for this local certificate.
- HSTS is present on HTTPS and confirms browser enforcement for future connections.
- TLS 1.2+ is the minimum acceptable baseline; TLS 1.3 is preferred because it reduces handshake complexity and removes older legacy negotiation paths.
- `testssl.sh` was run against `https://host.docker.internal:8443` on Docker Desktop, so the hostname mismatch warning is expected because the cert is issued for `localhost`.

Rate limiting evidence:

- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/access-log-429.txt`
- `labs/lab11/analysis/access-log-tail.txt`

Rate-limit result:

- First six login requests returned `401`
- Subsequent six returned `429`

This matches the configured `limit_req` policy:

- `rate=10r/m`
- `burst=5`

Why this is a good balance:

- Legitimate users get a small burst window for retries or normal browser behavior.
- Automated brute-force attempts are throttled quickly.
- The app stays usable without making the limit so strict that it creates false positives.

Timeout settings in `nginx.conf`:

- `client_body_timeout 10s`
- `client_header_timeout 10s`
- `proxy_read_timeout 30s`
- `proxy_send_timeout 30s`
- `keepalive_timeout 10s`
- `send_timeout 10s`

Trade-offs:

- Short timeouts reduce slowloris-style resource exhaustion risk.
- Longer upstream timeouts can still tolerate normal app latency.
- Tight values improve resilience, but overly aggressive settings can break slow clients or large uploads.

## Notes

- Juice Shop was kept behind Nginx only; no direct host port was published for the app container.
- The generated certificate is intentionally local and self-signed, so trust-chain warnings are expected.
- The rate-limit logs show `429` entries in the proxy access log as expected.

## Artifacts

- `labs/lab11/analysis/compose-ps.txt`
- `labs/lab11/analysis/http-redirect.txt`
- `labs/lab11/analysis/headers-http.txt`
- `labs/lab11/analysis/headers-https.txt`
- `labs/lab11/analysis/testssl.txt`
- `labs/lab11/analysis/rate-limit-test.txt`
- `labs/lab11/analysis/access-log-tail.txt`
- `labs/lab11/analysis/access-log-429.txt`
- `labs/lab11/reverse-proxy/certs/localhost.crt`
- `labs/lab11/reverse-proxy/certs/localhost.key`
