# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### Stack startup
Commands used:
```bash
cd labs/lab11

docker run --rm -v "$(pwd)/reverse-proxy/certs":/certs \
  alpine:latest \
  sh -c "apk add --no-cache openssl && cat > /tmp/san.cnf << 'EOF' && \
cat /tmp/san.cnf && \
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /certs/localhost.key -out /certs/localhost.crt \
  -config /tmp/san.cnf -extensions v3_req
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF"

docker compose up -d
docker compose ps
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
```

Observed result:

- HTTP redirected to HTTPS with status 308
- The reverse proxy was exposed on host ports
- The Juice Shop container had no published host ports and remained internal only

### Why reverse proxies improve security

A reverse proxy provides a single controlled entry point for traffic. It allows TLS termination, centralized security header injection, request filtering, rate limiting, and logging without modifying the application code.

### Why hiding direct app ports matters

Not exposing the application directly reduces attack surface and prevents bypassing proxy protections such as HTTPS enforcement, headers, and rate limiting.

## Task 2 — Security Headers

### HTTP header check

Command used:
```bash
curl -sI http://localhost:8080/ | tee analysis/headers-http.txt
```

Observed result:
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### HTTPS header check

Command used:
```bash
curl -skI https://localhost:8443/ | tee analysis/headers-https.txt
```

Observed security headers:
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
#### Header analysis

- **X-Frame-Options: DENY** helps prevent clickjacking by blocking framing.
- **X-Content-Type-Options: nosniff** prevents MIME sniffing and reduces the risk of incorrect browser content interpretation.
- **Strict-Transport-Security (HSTS)** tells browsers to use HTTPS only and helps prevent downgrade and SSL stripping attacks.
- **Referrer-Policy** limits referrer data leakage to other origins.
- P**ermissions-Policy** disables unnecessary browser capabilities such as camera, microphone, and geolocation.
- **Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy** improve isolation and reduce certain cross-origin attack and data leakage risks.
- **Content-Security-Policy-Report-Only** allows CSP testing without breaking Juice Shop functionality, which is important because the app is JavaScript-heavy.

### HSTS verification

HSTS was present on HTTPS responses and absent on HTTP responses, which is the correct behavior.

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts
### TLS scan

Command used:
```bash
docker run --rm --network host drwetter/testssl.sh:latest https://localhost:8443 | tee analysis/testssl.txt
```

### TLS summary

Enabled protocol versions:

- TLS 1.2
- TLS 1.3

Disabled legacy versions:

- SSLv2
- SSLv3
- TLS 1.0
- TLS 1.1

Supported cipher suites:

- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES128-GCM-SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

Additional TLS observations:

- HTTP/2 was offered via ALPN
- Strong AEAD ciphers with forward secrecy were offered
- Server cipher order was enabled

### TLS analysis

TLS 1.2+ is required because older protocols are deprecated and insecure. TLS 1.3 is preferred because it provides stronger defaults, better performance, and simpler secure negotiation.

The testssl scan showed a good protocol and cipher configuration with no major classic TLS vulnerabilities. Legacy and weak protocols were disabled, and forward secrecy was supported.

Expected localhost/dev warnings included:

- self-signed certificate / chain of trust not trusted
- no CRL or OCSP URI provided
- OCSP stapling not offered
- certificate transparency / CAA not present

These warnings are acceptable in a local lab with a self-signed certificate, but in production they should be addressed by using a trusted CA certificate and enabling related validation features where appropriate.

### HSTS confirmation

The testssl output confirmed:

- `Strict Transport Security 365 days=31536000 s, includeSubDomains, preload`

This matches the Nginx HTTPS configuration and confirms HSTS is active on the TLS endpoint.

### Rate limit test

Command used:
```bash
for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done | tee analysis/rate-limit-test.txt
```

Observed result:
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

### Rate limit analysis

The login endpoint was protected by `limit_req` and returned `429 Too Many Requests` once the request threshold was exceeded.

Summary:

- `401`: 6 responses
- `429`: 6 responses

This confirms that rate limiting was active and enforced on /rest/user/login.

### Rate limit rationale

The configuration uses:

- `rate=10r/m`
- `burst=5`

This means clients are allowed a moderate baseline request rate with a small burst capacity for short legitimate spikes. This helps balance security and usability:

- reduces brute-force login attempts
- slows repeated automated abuse
- still allows normal users to retry a few times quickly

### Timeout analysis

The Nginx configuration also included timeout controls:

- `client_body_timeout`
- `client_header_timeout`
- `proxy_read_timeout`
- `proxy_send_timeout`

These settings reduce the risk of slow client and slowloris-style resource exhaustion.

Trade-offs:

- shorter timeouts improve resilience and free resources faster
- overly aggressive timeout values may affect slow clients or long-running legitimate requests

In this setup, the timeouts are short enough to improve protection while still being practical for a small web application.

### 429 log evidence

Relevant access log lines:
```
172.22.0.1 - - [20/Apr/2026:17:13:20 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.14.1" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:17:13:20 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.14.1" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:17:13:20 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.14.1" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:17:13:20 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.14.1" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:17:13:20 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.14.1" rt=0.000 uct=- urt=-
172.22.0.1 - - [20/Apr/2026:17:13:20 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.14.1" rt=0.000 uct=- urt=-
```

## Conclusion

This lab demonstrated practical reverse proxy hardening without modifying application code. Nginx successfully enforced HTTPS, added important browser security headers, limited abusive login traffic, and applied timeout settings to reduce resource exhaustion risk.

The main trade-off is that stricter controls can impact compatibility or usability if applied too aggressively. For example:

- a strict enforcing CSP could break Juice Shop functionality
- very low rate limits can affect legitimate users
- self-signed certificates are acceptable for local testing but not for production