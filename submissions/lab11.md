# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### Relevant `nginx.conf` sections

```nginx
limit_req_zone $binary_remote_addr
    zone=login:10m
    rate=10r/m;

limit_req_status 429;

limit_conn_zone $binary_remote_addr
    zone=conn:10m;

server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Content-Type-Options
        "nosniff"
        always;

    add_header X-Frame-Options
        "DENY"
        always;

    add_header Referrer-Policy
        "strict-origin-when-cross-origin"
        always;

    add_header Permissions-Policy
        "camera=(), microphone=(), geolocation=()"
        always;

    add_header Content-Security-Policy-Report-Only
        "default-src 'self';
         img-src 'self' data: https:;
         script-src 'self' 'unsafe-inline' 'unsafe-eval';
         style-src 'self' 'unsafe-inline';
         connect-src 'self';
         frame-ancestors 'none';
         base-uri 'self';
         form-action 'self';"
        always;

    return 308 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    limit_conn conn 50;

    ssl_certificate
        /etc/nginx/certs/localhost.crt;

    ssl_certificate_key
        /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    ssl_ciphers HIGH:!aNULL:!MD5;

    ssl_conf_command Ciphersuites
        TLS_AES_128_GCM_SHA256:
        TLS_AES_256_GCM_SHA384:
        TLS_CHACHA20_POLY1305_SHA256;

    ssl_ecdh_curve
        X25519:secp384r1;

    ssl_session_cache
        shared:SSL:10m;

    ssl_session_timeout 1d;
    ssl_session_tickets off;

    client_body_timeout 10s;
    client_header_timeout 10s;
    proxy_read_timeout 30s;
    proxy_connect_timeout 5s;
    send_timeout 10s;

    add_header Strict-Transport-Security
        "max-age=63072000;
         includeSubDomains;
         preload"
        always;

    add_header X-Content-Type-Options
        "nosniff"
        always;

    add_header X-Frame-Options
        "DENY"
        always;

    add_header Referrer-Policy
        "strict-origin-when-cross-origin"
        always;

    add_header Permissions-Policy
        "camera=(), microphone=(), geolocation=()"
        always;

    add_header Content-Security-Policy-Report-Only
        "default-src 'self';
         img-src 'self' data: https:;
         script-src 'self' 'unsafe-inline' 'unsafe-eval';
         style-src 'self' 'unsafe-inline';
         connect-src 'self';
         frame-ancestors 'none';
         base-uri 'self';
         form-action 'self';"
        always;

    location = /rest/user/login {
        limit_req zone=login burst=5 nodelay;
        limit_req_log_level warn;
        proxy_pass http://juice;
    }

    location / {
        proxy_pass http://juice;
    }
}
```

> The excerpt above is formatted across multiple lines for readability.
> The active configuration is stored in
> [`labs/lab11/reverse-proxy/nginx.conf`](../labs/lab11/reverse-proxy/nginx.conf).

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/
```

Full result:
[`http-redirect.txt`](../labs/lab11/results/http-redirect.txt)

### B. TLS 1.3 proof

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

TLS 1.2 was explicitly rejected:

```text
tlsv1 alert protocol version
SSL alert number 70
```

Full results:

- [`tls13.txt`](../labs/lab11/results/tls13.txt)
- [`tls12-rejected.txt`](../labs/lab11/results/tls12-rejected.txt)

### C. Security headers proof

| Header | Observed value |
|---|---|
| Strict-Transport-Security | `max-age=63072000; includeSubDomains; preload` |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options | `DENY` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |
| Content-Security-Policy-Report-Only | Present |

Full result:
[`headers.txt`](../labs/lab11/results/headers.txt)

### What each header defends against

- **HSTS:** prevents SSL-stripping and protocol-downgrade attacks by requiring browsers to use HTTPS.
- **X-Content-Type-Options:** prevents MIME sniffing and forces browsers to respect the declared content type.
- **X-Frame-Options:** prevents framing of the application and reduces clickjacking risk.
- **Referrer-Policy:** limits URL information disclosed through the `Referer` header to external origins.
- **Permissions-Policy:** disables unnecessary access to sensitive browser APIs such as camera, microphone, and geolocation.
- **Content-Security-Policy:** restricts permitted resource origins and reduces the impact of XSS and content injection.

`Content-Security-Policy-Report-Only` was selected so violations
can be observed without breaking the Juice Shop frontend while the
policy is refined.

## Task 2: Production Posture

### Rate limit configuration

```nginx
limit_req_zone $binary_remote_addr
    zone=login:10m
    rate=10r/m;

limit_req_status 429;

location = /rest/user/login {
    limit_req zone=login burst=5 nodelay;
    limit_req_log_level warn;
    proxy_pass http://juice;
}
```

### Rate limit proof

| HTTP code | Count out of 60 |
|---:|---:|
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

The first six requests passed through Nginx and were rejected by
Juice Shop because the credentials were invalid. The remaining 54
requests were rejected by the Nginx rate limiter with HTTP `429`.

Full result:
[`ratelimit.txt`](../labs/lab11/results/ratelimit.txt)

### Connection limit and timeouts

```nginx
limit_conn_zone $binary_remote_addr
    zone=conn:10m;

limit_conn conn 50;

client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_connect_timeout 5s;
send_timeout 10s;
```

### Timeout enforced

```text
unexpected eof while reading
SSL_shutdown: shutdown while in init
```

The client opened a TLS connection, sent an incomplete HTTP request,
and waited longer than `client_header_timeout 10s`. Nginx closed the
connection before the request was completed.

Full result:
[`timeout.txt`](../labs/lab11/results/timeout.txt)

### Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits
```

The proxy allows only TLS 1.3, uses an approved TLS 1.3 cipher suite,
and negotiates the modern X25519 key-exchange curve.

Full result:
[`cipher.txt`](../labs/lab11/results/cipher.txt)

### Certificate rotation runbook

1. **Detect expiry:** monitor certificate expiration continuously, warn 30 days before expiration, and escalate at 7 days.
2. **Order new certificate:** renew through an ACME client such as Certbot or request it from the approved certificate authority.
3. **Validate:** inspect the certificate using `openssl x509` and verify its trust chain using `openssl verify`.
4. **Atomic swap:** keep stable symbolic links for the active certificate and key, repoint them to the new files, and reload Nginx.
5. **Verify:** check the deployed certificate, chain, expiration, TLS version, cipher suite, and endpoint availability.
6. **Rollback:** retain the previous certificate and key securely for approximately seven days and restore their symbolic links if deployment checks fail.
7. **Audit:** record the certificate serial number, issuer, expiration date, operator, deployment time, and verification results.

Example validation commands:

```bash
openssl x509 \
  -in newcert.pem \
  -text \
  -noout

openssl verify \
  -CAfile ca.pem \
  newcert.pem
```

Example atomic deployment:

```bash
ln -sfn newcert.pem current.pem
ln -sfn newkey.pem current.key
nginx -s reload
```

### What OCSP stapling provides

OCSP stapling lets the server periodically retrieve a signed
certificate-revocation response from the certificate authority and
include it in the TLS handshake. This reduces client-side latency and
prevents the certificate authority from learning which websites each
client accesses.

It is useful for publicly trusted production certificates because
they have a certificate chain and an OCSP responder. It provides no
benefit for this lab certificate because the certificate is
self-signed and has no external certificate authority or OCSP
responder.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used:** ModSecurity v3 with the Nginx connector
- **Container image:** `owasp/modsecurity-crs:4.10.0-nginx-alpine-202501050801`
- **OWASP CRS version:** 4.10.0
- **Blocking paranoia level:** 1
- **Detection paranoia level:** 1
- **Inbound anomaly threshold:** 5
- **Rule engine:** `On`
- **Exposed WAF endpoint:** `http://localhost:9443`

The ModSecurity implementation was selected because the lab explicitly
permits it and its OWASP CRS integration is well documented. The WAF
proxies accepted requests to the hardened Nginx endpoint over HTTPS.

### WAF configuration

```yaml
services:
  waf:
    image: owasp/modsecurity-crs:4.10.0-nginx-alpine-202501050801
    restart: unless-stopped

    depends_on:
      - nginx

    ports:
      - "9443:8080"

    environment:
      BACKEND: "https://nginx:443"
      PROXY_SSL_VERIFY: "off"
      SERVER_NAME: "localhost"
      PORT: "8080"

      MODSEC_RULE_ENGINE: "On"

      BLOCKING_PARANOIA: "1"
      DETECTION_PARANOIA: "1"

      ANOMALY_INBOUND: "5"
      ANOMALY_OUTBOUND: "4"

      MODSEC_AUDIT_ENGINE: "RelevantOnly"
      MODSEC_AUDIT_LOG: "/var/log/modsec_audit.log"
      MODSEC_AUDIT_LOG_TYPE: "Serial"
      MODSEC_AUDIT_LOG_FORMAT: "Native"
      MODSEC_AUDIT_LOG_PARTS: "ABIJDEFHZ"
      MODSEC_AUDIT_LOG_RELEVANT_STATUS: "^(?:5|4(?!04))"

    volumes:
      - ./waf/logs/audit.log:/var/log/modsec_audit.log
```

Full configuration:
[`docker-compose.override.yml`](../labs/lab11/waf/docker-compose.override.yml)

### Attack payload sent

```text
GET /rest/products/search?q=' OR 1=1--
```

URL-encoded request:

```text
/rest/products/search?q=%27%20OR%201%3D1--
```

### Before WAF: Nginx only

```text
no-waf: HTTP 500
```

The hardened Nginx reverse proxy did not identify the SQL injection
pattern and forwarded the request to Juice Shop. Juice Shop then
returned an internal application error. Therefore, the `500` response
is an application response rather than an edge-layer security block.

### After WAF

```text
with-waf: HTTP 403
```

The WAF rejected the request during ModSecurity phase 2 before it was
forwarded to the Nginx and Juice Shop application path.

Full comparison:
[`waf-comparison.txt`](../labs/lab11/results/waf-comparison.txt)

### Audit log excerpt

```text
GET /rest/products/search?q=%27%20OR%201%3D1-- HTTP/1.1
HTTP/1.1 403
ModSecurity: Warning. detected SQLi using libinjection.
[id "942100"]
[msg "SQL Injection Attack Detected via libinjection"]
[data "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"]
[ver "OWASP_CRS/4.10.0"]
[tag "paranoia-level/1"]

ModSecurity: Access denied with code 403 (phase 2).
[id "949110"]
[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
[ver "OWASP_CRS/4.10.0"]
```

- **Detection rule:** `942100`
- **Rule name:** `SQL Injection Attack Detected via libinjection`
- **Blocking rule:** `949110`
- **Reason for blocking:** inbound anomaly score reached the configured threshold of `5`

Compact excerpt:
[`waf-audit-excerpt.txt`](../labs/lab11/results/waf-audit-excerpt.txt)

Full captured transaction:
[`waf-audit.txt`](../labs/lab11/results/waf-audit.txt)

### Tradeoff analysis

The WAF provides runtime inspection of incoming traffic and can block
malicious patterns that passed through Nginx and were not prevented by
earlier SAST, DAST, container, or policy-as-code controls. Those earlier
controls identify weaknesses during development and delivery, whereas
the WAF applies a compensating control to real production requests.

The cost is additional latency, configuration and certificate
complexity, audit-log management, rule tuning, and the risk of false
positives. Higher paranoia levels detect more suspicious patterns but
can also block legitimate requests, so rules should first be observed
and tuned before stricter enforcement is enabled.

A WAF may not be appropriate for a private service with no untrusted
traffic, an extremely latency-sensitive endpoint, or a protocol that
the WAF cannot parse correctly. It should also not be deployed merely
as a substitute for fixing known vulnerabilities in the application.
