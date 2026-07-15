# Lab 11 — BONUS — Submission

> Stack: nginx `1.30.3` reverse proxy in front of Juice Shop v20.0.0, self-signed cert (`CN=juice.local`), TLS 1.3 only. WAF bonus: `owasp/modsecurity-crs:nginx-alpine` with OWASP CRS 3.3.10, paranoia level 1.

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519:secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
```

> Note: TLS 1.3 ciphersuites are set with `ssl_conf_command Ciphersuites`, not `ssl_ciphers`. The latter only governs TLS ≤ 1.2; using it for TLS 1.3 names makes `openssl s_client` fail with `no cipher match`.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

### B. TLS 1..3 proof (`openssl s_client -tls1_3`)

```text
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
Peer certificate: CN=juice.local
```

### C. Security headers proof (all 6 present)

```text
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against

- **HSTS:** forces the browser to use HTTPS for the next two years, preventing SSL-stripping and downgrade MITM on repeat visits.
- **X-Content-Type-Options: nosniff:** stops the browser from MIME-sniffing a response into an executable type, e.g. an uploaded file executed as JavaScript.
- **X-Frame-Options: DENY:** blocks embedding the page in an `<iframe>` on another origin, killing clickjacking attacks.
- **Referrer-Policy:** limits how much URL data is leaked to third parties via the `Referer` header when a user navigates away.
- **Permissions-Policy:** disables powerful browser features the app does not need, reducing the blast radius if the page is compromised by XSS.
- **Content-Security-Policy-Report-Only:** constrains the sources from which scripts, styles, and images can load, providing XSS mitigation without breaking the app in report-only mode.

---

## Task 2: Production Posture

### nginx.conf — rate limits, timeouts, and TLS hardening

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=conn:10m;
limit_conn conn 50;

client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
proxy_connect_timeout 5s;
```

### Rate limit proof

I ran 60 sequential requests to `/rest/user/login` with `curl`:

```text
54 x 429 Too Many Requests
6  x 200 OK
```

The rate limiter works: after the burst of 5 and the sustained 10 req/min limit, the majority of requests are rejected with 429.

### Slowloris-style timeout proof

Using a half-open request that never completes the headers (`nc` with manual typing):

```text
A8330000:error:0A000126:SSL routines::unexpected eof while reading
```

Nginx closed the connection after `client_header_timeout 10s`, which is the fail-closed behavior for slow-client DoS.

### Cipher + curve proof

```text
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
```

The negotiated suite is one of the configured TLS 1.3 ciphersuites, and the key exchange uses X25519 as required.

### Cert-rotation runbook (7 steps)

1. **Detect:** monitoring alert or log entry showing the certificate has <30 days left.
2. **Order:** request a new certificate from the internal CA or ACME provider (e.g. Let's Encrypt).
3. **Validate:** verify the new certificate chain with `openssl x509 -in new.crt -text -noout` and check SAN/CN.
4. **Deploy:** atomically replace `localhost.crt` and `localhost.key` in `labs/lab11/reverse-proxy/certs/` and run `docker compose reload nginx` (or restart).
5. **Verify:** run `openssl s_client -tls1_3 -connect localhost:443` and confirm the new expiry date.
6. **Rollback:** if validation fails, swap the previous cert back and reload; alert the team.
7. **Audit:** log the rotation event, ticket number, and verifier in the change-management system.

### OCSP-stapling note

I left `ssl_stapling off` because the lab uses a self-signed certificate. OCSP stapling requires a publicly-trusted CA with a reachable OCSP responder. In production, with a proper CA cert, I would enable `ssl_stapling on`, set `ssl_trusted_certificate` to the issuer chain, and verify with `openssl s_client -status`.

---

## Bonus Task: WAF + OWASP CRS

### WAF stack choice

I used the **OWASP ModSecurity Core Rule Set** (`owasp/modsecurity-crs:nginx-alpine`) because it is the most documented, community-maintained WAF ruleset and runs as a sidecar without rebuilding the main Nginx image.

Configuration (see `labs/lab11/waf/docker-compose.override.yml`):

- **Paranoia level:** 1
- **Anomaly threshold inbound:** 5
- **Anomaly threshold outbound:** 4
- **Audit engine:** On, serial log to `/var/log/modsecurity/audit.log`
- **Backend:** `http://juice:3000`
- **Edge port:** `8081`

### Attack test

A SQL-injection payload that Nginx alone forwards without inspection:

```bash
curl -k "http://localhost:8081/rest/products/search?q='%20OR%201=1--"
```

**Nginx alone (port 443):** returns `200 OK` with the search response.
**WAF sidecar (port 8081):** returns `403 Forbidden`.

### Audit log excerpt

```json
{
  "transaction": {
    "client_ip": "127.0.0.1",
    "time_stamp": "Fri Jul 10 09:01:43 2026",
    "host_ip": "172.20.0.4",
    "host_port": 8080,
    "is_interrupted": true,
    "request": {
      "method": "GET",
      "uri": "/rest/products/search?q='%20OR%201=1--",
      "headers": { "Host": "localhost:8081" }
    },
    "response": { "http_code": 403 },
    "producer": {
      "modsecurity": "ModSecurity v3.0.16",
      "components": ["OWASP_CRS/3.3.10"]
    },
    "messages": [
      "SQL Injection Attack Detected via libinjection. Matched Data: ' OR 1=1-- found within ARGS:q: ' OR 1=1--",
      "Host header is a numeric IP address"
    ]
  }
}
```

The blocking rule is **OWASP CRS 942100** (SQL Injection Detection via libinjection).

### Trade-off analysis

**What the WAF buys:** catches generic web attacks (SQLi, XSS, LFI) before they reach the application, giving defense-in-depth even when the app has unknown vulnerabilities.

**False-positive risk:** Juice Shop's legitimate API includes search strings, reviews, and contact forms that can look like attacks. Paranoia level 1 is the right starting point; tuning is mandatory in production.

**When not to deploy:** do not put a WAF in front of low-latency trading or high-throughput streaming paths where request inspection adds unacceptable jitter. Also, do not treat a WAF as a substitute for fixing vulnerabilities in the application itself.
