# Lab 11 — Reverse Proxy Hardening (Nginx TLS, Security Headers, and Rate Limiting)

## Task 1 — Reverse Proxy Compose Setup


### Why Reverse Proxies Are Valuable for Security
1. **TLS termination** — The proxy manages HTTPS encryption and decryption. Application containers no longer handle private keys, reducing exposure risk.  
2. **Security headers injection** — Nginx adds industry-standard security headers (X-Frame-Options, CSP, etc.) globally, even if the app itself does not set them.  
3. **Request filtering** — Rate limits and timeouts block excessive or suspicious activity before it reaches the app, mitigating brute-force and DoS attempts.  
4. **Single access point** — All inbound requests pass through a single, observable control plane where logging, monitoring, and hardening are centralized.  
5. **Reduced attack surface** — The backend container is not reachable directly; attackers cannot scan or exploit its internal ports.

### Verification
After generating a self-signed certificate and starting the stack:

```bash
docker compose ps
```

**Output:**
```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     4 minutes ago   Up 4 minutes    3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     4 minutes ago   Up 27 seconds   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```

Only **Nginx** publishes host ports (`8080` for HTTP, `8443` for HTTPS).  
**Juice Shop** shows only `3000/tcp`, which is internal to the Docker network.  
This confirms the app is hidden behind the proxy — reducing its attack surface.

---

## Task 2 — Security Headers Validation

Headers captured from `headers-https.txt`:

```
HTTP/2 200 
server: nginx
date: Wed, 12 Nov 2025 17:59:16 GMT
content-type: text/html; charset=UTF-8
content-length: 75002
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Wed, 12 Nov 2025 17:23:41 GMT
etag: W/"124fa-19a79183684"
vary: Accept-Encoding
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Header Explanations

| Header | What It Protects Against |
|---------|--------------------------|
| **X-Frame-Options: DENY** | Prevents the site from being embedded in an `<iframe>` on another page, blocking **clickjacking** attempts that could trick users into performing actions invisibly. |
| **X-Content-Type-Options: nosniff** | Instructs browsers **not to guess file types**, stopping them from executing uploaded content as scripts and reducing risk of **MIME-type confusion** exploits. |
| **Strict-Transport-Security (HSTS)** | Forces browsers to use **HTTPS only** for one year and preload this policy (`max-age=31536000; includeSubDomains; preload`). Mitigates protocol-downgrade and session-hijacking attacks. Visible **only on HTTPS** responses. |
| **Referrer-Policy: strict-origin-when-cross-origin** | Limits information sent in the `Referer` header on cross-site requests so that **sensitive URL data or tokens** aren’t leaked to third-party domains. |
| **Permissions-Policy & Feature-Policy** | Control access to powerful browser features. `Permissions-Policy: camera=(), geolocation=(), microphone=()` and `feature-policy: payment 'self'` restrict camera, mic, location, and payment API usage, defending against **privacy leaks** and unwanted hardware access. |
| **Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy (COOP / CORP)** | Enforce **site isolation**: tabs and iframes from other origins can’t share resources or browsing context, mitigating **side-channel and data-leak** attacks between windows. |
| **Content-Security-Policy-Report-Only (CSP)** | Defines trusted sources for scripts, images, and styles while running in “report-only” mode. Violations are logged but not blocked — ideal for monitoring before full enforcement. Helps prevent **XSS and data injection**. |

All expected hardening headers are present on the HTTPS response.  
`Strict-Transport-Security` appears only on HTTPS (not HTTP), confirming correct configuration.

---

## Task 3 — TLS Configuration and Rate Limiting Validation

### TLS / testssl Summary

Excerpt from `testssl.txt`:
```
TLS 1.2 offered (OK)
TLS 1.3 offered (OK)
SSLv2, SSLv3, TLS1.0, TLS1.1 not offered (GOOD)
Supported cipher suites:
  TLS_AES_256_GCM_SHA384
  TLS_CHACHA20_POLY1305_SHA256
  TLS_AES_128_GCM_SHA256
  ECDHE-RSA-AES256-GCM-SHA384
  ECDHE-RSA-AES128-GCM-SHA256
Strict Transport Security: 365 days, includeSubDomains, preload
OCSP stapling: not offered
```

**Summary:**
- **Enabled protocols:** TLS 1.2 and TLS 1.3 only.  
- **Disabled:** SSLv2, SSLv3, TLS 1.0 and 1.1 — preventing obsolete, insecure handshakes.  
- **Cipher suites:** modern AEAD ciphers (AES-GCM, ChaCha20) supporting forward secrecy (ECDHE).  
- **Why TLS 1.2+ only:** TLS 1.0/1.1 have known cryptographic weaknesses (BEAST, POODLE, etc.); TLS 1.3 further reduces handshake complexity and removes insecure cipher negotiation.  
- **Warnings:** expected “NOT ok” items for self-signed certificate (no CA chain, OCSP stapling disabled). These are acceptable in local development environments.  
- **HSTS header:** appears **only** on HTTPS, confirming correct deployment.

---

### Rate Limiting and Timeouts

**Rate-limit test output (`rate-limit-test.txt`):**
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
- The first six requests return 401 (invalid credentials).  
- The following six return 429 (“Too Many Requests”), proving that Nginx is enforcing the per-IP login limit.

**Configuration:**
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_status 429;
}
```

- `rate=10r/m` — allows 10 login attempts per minute per IP.  
- `burst=5` — tolerates short spikes of 5 extra requests before applying 429.  
- `nodelay` — immediately rejects requests beyond the burst instead of queuing them.  
This balances security (preventing brute-force) and usability (allowing small bursts for retries).

**Timeout settings from `nginx.conf`:**
```
client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
```

| Directive | Purpose | Security/Usability trade-off |
|------------|----------|------------------------------|
| `client_body_timeout` | How long Nginx waits for client to send body. Protects against “slow POST” DoS. | Too short may interrupt large uploads. |
| `client_header_timeout` | Wait time for complete request headers. | Prevents Slowloris attacks; short value may drop slow clients. |
| `proxy_read_timeout` | Time Nginx waits for backend to respond. | Protects against backend hangs; too short could abort valid long responses. |
| `proxy_send_timeout` | Time Nginx waits for backend to accept data. | Prevents stalls if backend stops reading. |

**Access log sample confirming 429:**
```
127.0.0.1 - - [12/Nov/2025:19:45:12 +0000] "POST /rest/user/login HTTP/1.1" 401 85 "-" "curl/8.5.0" rt=0.012
127.0.0.1 - - [12/Nov/2025:19:45:17 +0000] "POST /rest/user/login HTTP/1.1" 429 0 "-" "curl/8.5.0" rt=0.001
```


