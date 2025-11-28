# Lab 11 Submission

## Task 1

### Why reverse proxies strengthen security:

**1. TLS Termination:**  
The reverse proxy manages TLS encryption/decryption, simplifying certificate handling and removing the need for each backend service to deal with TLS. This keeps crypto operations centralized while backend apps can focus solely on their logic.

**2. Security Headers Injection:**  
Security headers (HSTS, CSP, X-Frame-Options, etc.) can be uniformly applied at the proxy level. This ensures consistent protection across services without modifying application code.

**3. Request Filtering:**  
Reverse proxies can block malicious traffic, enforce rate limits, and inspect requests before they reach the app. This provides an additional protective layer that mitigates attacks like DDoS, brute force, or request tampering.

**4. Centralized Entry Point:**  
All incoming traffic goes through one controlled interface, enabling unified access control, logging, and monitoring. This makes it easier to enforce and maintain a standard security posture.

### Why hiding application ports reduces the attack surface:

Keeping app ports unexposed prevents attackers from bypassing security controls enforced by the reverse proxy. This blocks:
- Direct exploitation of backend vulnerabilities  
- Avoiding rate limits and header-based protections  
- Access to debug/admin interfaces  
- Protocol-level attacks on the application server  

The proxy becomes the only accessible gateway, guaranteeing that all requests pass through enforced security policies.

### Docker Compose Port Exposure Verification:

```bash
NAME            IMAGE                           COMMAND                  SERVICE   CREATED              STATUS              PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     About a minute ago   Up About a minute   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     About a minute ago   Up About a minute   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

**Analysis:**

* **Nginx** exposes public ports (`8080`, `8443`) as expected.
* **Juice Shop** exposes only `3000/tcp` internally and has *no* host binding.

This verifies that the app is properly isolated behind the reverse proxy.

## Task 2

### Security Headers from HTTPS Response:

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

### Header Security Analysis:

**X-Frame-Options: DENY** – Blocks the site from being placed inside frames, mitigating clickjacking attempts.

**X-Content-Type-Options: nosniff** – Prevents MIME type guessing, avoiding attacks where content is interpreted as a different file type.

**Strict-Transport-Security (HSTS):**
Enforces HTTPS for one year, covers subdomains, and is set for preload lists. This blocks protocol downgrades and MITM attacks.

**Referrer-Policy: strict-origin-when-cross-origin** – Limits referrer leakage, protecting sensitive data in URLs.

**Permissions-Policy:**
Disables access to privileged APIs (camera, microphone, geolocation), reducing privacy risks.

**COOP/CORP:**
Reinforces isolation against cross-origin data leaks by blocking access to window objects and preventing unauthorized resource loading.

**CSP-Report-Only:**
Defines allowed sources for resources while still logging violations. This helps detect unsafe patterns before enforcing a strict CSP.

## Task 3

### Testssl Summary:

**TLS Protocol Support:**

* SSLv2: Disabled (good)
* SSLv3: Disabled (good)
* TLS 1.0: Disabled
* TLS 1.1: Disabled
* TLS 1.2: Enabled
* TLS 1.3: Enabled

**Supported Cipher Suites:**

*TLS 1.2:*

* ECDHE-RSA-AES256-GCM-SHA384
* ECDHE-RSA-AES128-GCM-SHA256

*TLS 1.3:*

* TLS_AES_256_GCM_SHA384
* TLS_CHACHA20_POLY1305_SHA256
* TLS_AES_128_GCM_SHA256

### Why TLS 1.2+ (preferably 1.3) is necessary:

Older TLS versions include weak ciphers and known vulnerabilities. TLS 1.3 offers:

* Mandatory forward secrecy
* Streamlined handshake
* Removal of legacy/unsafe ciphers
* Strong AEAD-only cipher suites

### testssl Warnings:

* **Chain of trust: not ok** (self-signed dev cert – expected)
* **OCSP: not ok** (expected for self-signed)
* **BREACH: possible** due to gzip compression
* **Overall grade: T** (limited by self-signed cert)

Other tests (Heartbleed, ROBOT, CRIME, etc.) passed successfully.

### HSTS Verification:

* HTTP (8080): No HSTS (correct)
* HTTPS (8443): HSTS present

### Rate Limiting & Timeouts:

**Rate Limit Test Output:**

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

**Interpretation:**
After 6 unauthorized attempts, the proxy begins returning `429` responses, confirming that rate limiting is functioning.

**Rate Limit Configuration:**

* `rate=10r/m`
* `burst=5`

This configuration helps balance legitimate usage with protection against brute force attacks.

### Timeout Settings (nginx.conf):

* `client_body_timeout 30s`
* `client_header_timeout 30s`
* `proxy_read_timeout 60s`
* `proxy_send_timeout 60s`

These protect against slow client attacks while remaining generous enough for legitimate operations.

### Access Log (429 responses):

```
172.18.0.1 - - [21/Nov/2025:19:05:24 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
...
```

The near-zero `rt` confirms the proxy rejects excessive requests immediately, demonstrating effective brute force prevention.
