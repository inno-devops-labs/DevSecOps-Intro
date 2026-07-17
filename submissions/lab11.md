# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    return 308 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    location / {
        proxy_pass http://juice;
    }
}
```

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/

X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Server Temp Key: X25519, 253 bits
```

### C. Security headers proof (all 6 present)

```text
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)

- **HSTS:** Forces browsers to use HTTPS for future connections, preventing SSL stripping and protocol downgrade attacks.
- **X-Content-Type-Options: nosniff:** Prevents browsers from MIME type sniffing, reducing the risk of executing malicious files as scripts.
- **X-Frame-Options: DENY:** Blocks the site from being embedded in iframes, protecting against clickjacking attacks.
- **Referrer-Policy:** Limits the amount of referrer information shared with external websites, reducing information leakage.
- **Permissions-Policy:** Disables access to browser features such as camera, microphone, and geolocation unless explicitly allowed.
- **Content-Security-Policy-Report-Only:** Reports potential Content Security Policy violations without blocking requests, helping identify XSS risks while safely testing a CSP configuration.

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200       | 0               |
| 429       | 54              |
| 5xx       | 6               |

The configured Nginx rate limiting successfully blocked the majority of excessive login requests with **HTTP 429 (Too Many Requests)**. A small number of requests reached the upstream application and returned **HTTP 500** under heavy concurrent load.

### Timeout enforced

```text
(no output)
```

The configured `client_header_timeout` is set to **10 seconds**. During testing, Nginx closed the incomplete client connection without forwarding the request to the upstream application, demonstrating that the timeout protection is enforced.

### Cipher hardening

```text
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

The reverse proxy negotiates **TLS 1.3**, uses the **TLS_AES_256_GCM_SHA384** cipher suite, and performs key exchange using the **X25519** elliptic curve, providing a modern and secure TLS configuration.

### Cert rotation runbook (7 steps)

1. **Detect expiry:** Monitor certificate expiration dates using automated monitoring or scheduled checks and begin the renewal process before the certificate expires.
2. **Order new certificate:** Request a new certificate from the Certificate Authority and complete the required domain validation.
3. **Validate:** Verify that the new certificate, private key, and certificate chain are correct and match the target domain before deployment.
4. **Atomic swap:** Replace the old certificate and private key with the new files and reload Nginx so active connections are not interrupted.
5. **Verify:** Confirm that the new certificate is presented by the server and that TLS connections succeed using tools such as `openssl s_client` or a web browser.
6. **Rollback plan:** If any problems occur after deployment, restore the previous certificate and private key and reload Nginx to return to the last known working state.
7. **Audit:** Record the rotation date, certificate serial number, validation results, verification steps, and any operational issues for future reference and compliance.

### What OCSP stapling buys you (2–3 sentences, reference Reading 11)

OCSP stapling allows the web server to include a signed OCSP response during the TLS handshake, enabling clients to verify certificate revocation without contacting the Certificate Authority directly. This improves client privacy, reduces certificate validation latency, and decreases the load on the CA's OCSP infrastructure. In this lab a **self-signed certificate** is used, so there is no trusted Certificate Authority or OCSP responder, making OCSP stapling unavailable and unnecessary.
