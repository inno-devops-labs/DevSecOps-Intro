# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + headers)

```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_conf_command Ciphersuites 
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
ssl_ecdh_curve X25519:secp384r1;

ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; 
preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" 
always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; 
img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; 
style-src 'self' 'unsafe-inline'" always;
```

---

### HTTPS redirect proof

```text
```

Вставь сюда содержимое файла

```bash
cat labs/lab11/results/http-redirect.txt
```

---

### TLS 1.3 proof

```text
```

Вставь сюда

```bash
cat labs/lab11/results/tls13.txt
```

---

### Security headers proof

```text
```

Вставь сюда

```bash
cat labs/lab11/results/headers.txt
```

---

### What each header defends against

- **HSTS** prevents browsers from connecting over HTTP after the first 
secure visit.
- **X-Content-Type-Options: nosniff** prevents MIME-type sniffing attacks.
- **X-Frame-Options: DENY** protects against clickjacking attacks.
- **Referrer-Policy** limits information leaked through the Referer 
header.
- **Permissions-Policy** disables unnecessary browser features such as 
camera, microphone and geolocation.
- **Content-Security-Policy-Report-Only** reports policy violations and 
helps detect XSS without breaking the application.

---

# Task 2: Production Posture

## Rate limit proof

```text
```

Вставь сюда

```bash
cat labs/lab11/results/ratelimit.txt
```

---

## Timeout enforced

The server closes incomplete client connections after the configured 
timeout (`client_header_timeout 10s`), mitigating Slowloris-style attacks.

---

## Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

---

## Certificate rotation runbook

1. Monitor certificate expiration.
2. Request a new certificate from the CA.
3. Validate the new certificate before deployment.
4. Replace the certificate atomically on the server.
5. Verify the HTTPS endpoint and certificate chain.
6. Roll back to the previous certificate if validation fails.
7. Record the rotation in the operational audit log.

---

## OCSP stapling

OCSP stapling allows the server to provide a signed certificate status 
response during the TLS handshake, reducing latency and improving privacy. 
It is useful in production with CA-issued certificates, but it provides no 
benefit for this lab because the certificate is self-signed and has no 
OCSP responder.
