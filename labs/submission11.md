# Lab 11 — Reverse Proxy Hardening (Nginx)

## Overview

In this lab, OWASP Juice Shop was deployed behind an Nginx reverse proxy and hardened using:
- Security headers
- TLS (HTTPS with self-signed certificate)
- Rate limiting and timeout controls

No changes were made to the application itself — all protections were applied at the proxy layer.

---

# Task 1 — Reverse Proxy Setup

## Why Reverse Proxies Improve Security

A reverse proxy provides:
- **TLS termination** (centralized HTTPS handling)
- **Security header injection** without modifying app code
- **Request filtering and rate limiting**
- **Single entry point** to the application

This simplifies security management and reduces exposure.

## Why Hiding App Ports Matters

The Juice Shop container is not exposed directly to the host:
- Prevents bypassing security controls (headers, TLS, rate limiting)
- Reduces attack surface
- Ensures all traffic flows through Nginx

## Evidence

```bash
docker compose ps
````

Output:

```
NAME            IMAGE                           PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   3000/tcp
lab11-nginx-1   nginx:stable-alpine             0.0.0.0:8080->8080/tcp, 0.0.0.0:8443->8443/tcp
```

✔ Only Nginx exposes ports to host
✔ Juice Shop is internal only

## HTTP → HTTPS Redirect

```bash
curl -I http://localhost:8080
```

Result:

```
HTTP/1.1 308 Permanent Redirect
Location: https://localhost:8443/
```

✔ Redirect works correctly

---

# Task 2 — Security Headers

## HTTPS Headers Evidence

```bash
curl -k -I https://localhost:8443/
```

Key headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; ...
```

## Header Analysis

* **X-Frame-Options: DENY**
  Prevents clickjacking attacks by blocking iframe embedding.

* **X-Content-Type-Options: nosniff**
  Prevents MIME-type sniffing and content confusion attacks.

* **Strict-Transport-Security (HSTS)**
  Forces browsers to use HTTPS and prevents downgrade attacks.

* **Referrer-Policy**
  Limits sensitive information leakage via HTTP referrer headers.

* **Permissions-Policy**
  Disables access to sensitive browser features (camera, geolocation, microphone).

* **COOP (Cross-Origin-Opener-Policy)**
  Protects against cross-origin attacks like tabnabbing.

* **CORP (Cross-Origin-Resource-Policy)**
  Restricts which origins can load resources.

* **CSP (Report-Only)**
  Detects XSS and content injection attempts without breaking functionality.

✔ Headers are correctly applied via Nginx
✔ HSTS appears only on HTTPS (correct behavior)

---

# Task 3 — TLS, HSTS, Rate Limiting & Timeouts

## TLS Configuration Summary

From `testssl.sh`:

* Supported protocols:

  * **TLSv1.2**
  * **TLSv1.3 (preferred)**

* Strong cipher:

  * `TLS_AES_256_GCM_SHA384`

* Forward secrecy:

  * Enabled (X25519, ECDHE)

* Legacy clients:

  * ❌ IE 8 / Java 7 → not supported (expected)

## TLS Security Analysis

✔ Modern secure protocols only
✔ Strong encryption
✔ Forward secrecy enabled

### Expected Issues (Lab Environment)

* Self-signed certificate → not trusted
* Chain of trust warning
* Domain mismatch (localhost)

These are acceptable for local development.

---

## Rate Limiting Test

### Command

```bash
for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "Content-Type: application/json" \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done
```

### Result

```
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

✔ First requests allowed
✔ Later requests blocked with **429 Too Many Requests**

---

## Access Log Evidence

```
POST /rest/user/login HTTP/1.1" 429
POST /rest/user/login HTTP/1.1" 429
POST /rest/user/login HTTP/1.1" 429
```

✔ Confirms rate limiting is enforced by Nginx

---

## Rate Limiting Configuration

* `rate=10r/m` → 10 requests per minute
* `burst=5` → allows short spikes
* `limit_req_status 429` → blocks excessive requests

### Trade-offs

* Too strict → blocks legitimate users
* Too loose → ineffective against brute-force

✔ Current values provide balanced protection

---

## Timeout Configuration

* `client_body_timeout` → prevents slow upload attacks
* `client_header_timeout` → protects against slowloris
* `proxy_read_timeout` → limits backend wait time
* `proxy_send_timeout` → limits client send duration

### Trade-offs

* Lower timeouts → better DoS protection
* Higher timeouts → better user experience

✔ Configuration balances resilience and usability

---

# Conclusion

This lab demonstrates how a reverse proxy can significantly improve application security without modifying code.

Implemented protections:

* Reverse proxy isolation
* HTTPS with TLS 1.2/1.3
* Security headers
* Rate limiting
* DoS mitigation via timeouts

✔ All acceptance criteria met
✔ All artifacts generated and validated

---