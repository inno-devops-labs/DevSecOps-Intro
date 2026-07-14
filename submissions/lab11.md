# Lab 11 — BONUS — Submission

## Environment and reproducibility

- Docker Engine: 29.2.1
- Docker Compose: v5.1.0
- Application: `bkimminich/juice-shop:v20.0.0`
- Edge proxy: `nginx:stable-alpine`
- WAF: ModSecurity v3 (`libmodsecurity 3.0.16`) with OWASP CRS 4.28.0
- Verification: `bash labs/lab11/scripts/verify.sh`

The self-signed certificate has SANs for `localhost`, `juice.local`, and
`127.0.0.1`. Its private key and the generated Nginx logs are excluded by
`.gitignore`.

The final stack was healthy:

```text
NAME            SERVICE   STATUS                   PORTS
lab11-juice-1   juice     Up                       3000/tcp
lab11-nginx-1   nginx     Up                       80->80, 443->443
lab11-waf-1     waf       Up (healthy)             8081->8080, 8443->8443
```

Nginx validated its loaded configuration before the tests:

```text
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

## Task 1: TLS + Security Headers

### Relevant `nginx.conf` sections

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
      always;

    return 308 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve X25519:secp384r1;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_conf_command Ciphersuites
      TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;

    add_header Strict-Transport-Security
      "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
      always;

    location / {
        proxy_pass http://juice;
    }
}
```

`ssl_conf_command Ciphersuites` is intentional: with OpenSSL, the Nginx
`ssl_ciphers` directive configures pre-TLS-1.3 suites, while TLS 1.3 suites use
the separate `Ciphersuites` setting. The negotiated result is verified below.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
```

### B. TLS 1.3 proof

```text
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=localhost
Peer Temp Key: X25519, 253 bits
```

As a negative control, an explicit TLS 1.2 handshake failed:

```text
tlsv1 alert protocol version
SSL alert number 70
```

### C. Security headers proof

```text
HTTP/2 200
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
```

### What each header defends against

- **HSTS:** After a trusted HTTPS visit, the browser refuses HTTP downgrades for the origin, reducing SSL-stripping exposure.
- **X-Content-Type-Options (`nosniff`):** It prevents a browser from reinterpreting a response as executable content when its declared MIME type says otherwise.
- **X-Frame-Options (`DENY`):** It prevents every origin from framing the application, blocking the UI overlay needed for clickjacking.
- **Referrer-Policy:** It limits cross-origin referrers to the origin rather than leaking sensitive URL paths and query strings.
- **Permissions-Policy:** It denies camera, microphone, and geolocation APIs even if injected or third-party JavaScript tries to request them.
- **Content-Security-Policy:** The allow-list exposes unexpected script, object, framing, and form destinations; it is deliberately Report-Only in this lab so violations can be tuned before enforcement without breaking Juice Shop.

## Task 2: Production Posture

### Controls configured

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=conn:10m;

ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_connect_timeout 5s;

server {
    limit_conn conn 50;

    location = /rest/user/login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://juice;
    }
}
```

### Rate limit proof

Sixty concurrent invalid login POSTs produced:

| HTTP code | Count out of 60 | Meaning |
|-----------|----------------:|---------|
| 401 | 6 | Initial requests reached Juice Shop and failed authentication |
| 429 | 54 | Nginx rejected the burst at the edge |
| 5xx | 0 | No proxy or application failure |

```text
   6 401
  54 429
```

In production behind a load balancer, `$binary_remote_addr` must be populated
from a strictly trusted real-IP chain; otherwise every client may appear as the
load balancer or an attacker may spoof the key.

### Timeout enforced

The lab's plain `nc localhost 443` command does not perform a TLS handshake, so
the verification script instead opened TLS, sent an incomplete HTTP header, and
kept stdin open. Nginx closed it exactly at the configured header timeout:

```text
configured client_header_timeout: 10s
observed connection lifetime: 10s
result: nginx closed TLS connection before the incomplete header was finished
SSL routines::unexpected eof while reading
```

The connection close is the expected fail-closed outcome; Nginx freed the worker
without forwarding an incomplete request upstream.

### Cipher hardening

```text
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Certificate rotation runbook

1. **Detect expiry:** Export certificate expiry to monitoring, warn at 30 days, and page at 7 days; confirm manually with `openssl x509 -in current.crt -noout -enddate -serial -fingerprint -sha256`.
2. **Order new certificate:** Renew through the ACME client or approved CA into a new versioned directory without overwriting the active certificate and key.
3. **Validate:** Check dates, SANs, issuer and chain with `openssl x509`/`openssl verify`; compare the certificate and private-key public-key digests, permissions, ownership, and expected hostname.
4. **Atomic swap:** Stage immutable versioned files, run `nginx -t`, atomically repoint `current.crt` and `current.key` symlinks, then use `nginx -s reload` for a zero-downtime reload.
5. **Verify:** From outside the host, inspect the served serial, expiry, SAN and chain with `openssl s_client`; run `curl`, a health check, and `testssl.sh`, and watch handshake/error metrics.
6. **Rollback:** Retain the previous protected certificate and key for at least seven days; on failure atomically restore both previous symlinks, run `nginx -t`, reload, and repeat external verification.
7. **Audit:** Record the change ticket, operator/automation identity, CA order, old/new serials and SHA-256 fingerprints, expiry, validation output, deployment time, and rollback status in the audit log/SIEM.

The certificate and key must always rotate as a matched pair. A reload occurs
only after validation, and the active pair is never edited in place.

### What OCSP stapling buys

With a public CA certificate, stapling lets Nginx periodically fetch the signed
revocation status and attach it to the handshake, avoiding a client-to-CA round
trip and the privacy leak of telling the CA which site a user visits. The lab
certificate is self-signed, has no issuer chain or OCSP responder, so there is
nothing meaningful to staple; `ssl_stapling` remains off until a trusted
certificate, trusted chain, and monitored resolver are configured.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF:** Official ModSecurity v3 + Nginx image
- **Image:** `owasp/modsecurity-crs:4.28.0-nginx-alpine-202607100407`
- **OWASP CRS:** 4.28.0
- **Blocking/detection paranoia level:** 1
- **Inbound anomaly threshold:** 5
- **Audit log:** JSON at `/var/log/modsec/audit.log`

I selected the ModSecurity v3 option explicitly permitted and recommended by
the lab because the official CRS container is multi-architecture, versioned,
and exposes the rule/audit evidence required by the rubric. The WAF terminates
TLS on `8443` and proxies accepted requests over TLS to hardened Nginx on `443`,
which then proxies to Juice Shop.

### Attack payload

```http
GET /rest/products/search?q=1%27%20OR%20%271%27%3D%271
```

Decoded parameter: `q=1' OR '1'='1`.

### Before WAF — Nginx alone

```text
no-waf: HTTP 200
```

The request reached Juice Shop, demonstrating that Nginx TLS, headers, and rate
limits do not themselves inspect SQL injection syntax.

### After WAF

```text
with-waf: HTTP 403
```

The URI and method were identical; only the route through OWASP CRS changed.

### Audit log excerpt

```json
{
  "request": {
    "method": "GET",
    "uri": "/rest/products/search?q=1%27%20OR%20%271%27%3D%271"
  },
  "response": { "http_code": 403 },
  "messages": [
    {
      "message": "SQL Injection Attack Detected via libinjection",
      "rule_id": "942100",
      "data": "Matched Data: s&sos found within ARGS:q: 1' OR '1'='1",
      "severity": "2",
      "tags": ["attack-sqli", "paranoia-level/1", "OWASP_CRS"]
    },
    {
      "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
      "rule_id": "949110"
    }
  ]
}
```

Rule **942100**, **SQL Injection Attack Detected via libinjection**, contributed
an anomaly score of 5 at paranoia level 1; rule **949110** enforced the inbound
threshold and returned 403.

### Trade-off analysis

The WAF supplies request-time virtual patching and generic attack-pattern
detection after SAST, DAST, and policy gates have finished, including attacks
against code or dependencies that were not known during CI. It costs latency,
another TLS/config/logging lifecycle, and false-positive tuning—especially when
paranoia levels are raised. I would not deploy it on a private, narrowly scoped
machine-to-machine service whose strict schema, authentication, and network
controls are stronger and where a false block is more damaging than the added
generic detection.

For this A/B demonstration, direct Nginx ports remain published so the same
payload can bypass the WAF intentionally. In production, only the WAF endpoint
would be published; Nginx would remain on an internal Docker/Kubernetes network,
otherwise an attacker could simply route around the WAF.

## Evidence files

- [`http-redirect.txt`](../labs/lab11/results/http-redirect.txt)
- [`tls13.txt`](../labs/lab11/results/tls13.txt) and [`tls12-rejected.txt`](../labs/lab11/results/tls12-rejected.txt)
- [`headers.txt`](../labs/lab11/results/headers.txt)
- [`cipher.txt`](../labs/lab11/results/cipher.txt)
- [`ratelimit.txt`](../labs/lab11/results/ratelimit.txt)
- [`timeout.txt`](../labs/lab11/results/timeout.txt)
- [`waf-baseline.txt`](../labs/lab11/results/waf-baseline.txt) and [`waf-blocked.txt`](../labs/lab11/results/waf-blocked.txt)
- [`waf-audit.txt`](../labs/lab11/results/waf-audit.txt)
- [`nginx-test.txt`](../labs/lab11/results/nginx-test.txt) and [`stack.txt`](../labs/lab11/results/stack.txt)

