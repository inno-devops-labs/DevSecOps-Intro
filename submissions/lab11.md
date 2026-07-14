# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf

Relevant upstream, HTTPS redirect, TLS, and security-header configuration:

```nginx
upstream juice {
  server juice:3000;
  keepalive 32;
}

server {
  listen 80;
  listen [::]:80;
  server_name _;

  limit_conn conn 50;

  return 308 https://$host$request_uri;
}

server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;

  server_name _;

  limit_conn conn 50;

  ssl_certificate /etc/nginx/certs/localhost.crt;
  ssl_certificate_key /etc/nginx/certs/localhost.key;

  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;

  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
  ssl_ecdh_curve X25519:secp384r1;

  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;

  client_max_body_size 2m;
  client_body_timeout 10s;
  client_header_timeout 10s;
  send_timeout 10s;

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "DENY" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
  add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; connect-src 'self' https: wss:;" always;

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

The backend application is configured through the `juice` Docker Compose service on port `3000`.

TLS 1.3 cipher suites are configured through `ssl_conf_command Ciphersuites`, while TLS 1.3 is enforced using `ssl_protocols TLSv1.3`.

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Tue, 14 Jul 2026 05:59:44 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
```

The HTTP endpoint redirects requests to the equivalent HTTPS URL with status code `308`.

### B. TLS 1.3 proof

```text
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
Signature type: RSA-PSS
Verification error: self-signed certificate
Server Temp Key: X25519, 253 bits
DONE
```

The certificate verification warning is expected because the lab uses a locally generated self-signed certificate.

A separate connection attempt using TLS 1.2 was rejected:

```text
TLS 1.2 rejection test:
error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version
SSL alert number 70
```

This confirms that the server accepts TLS 1.3 but does not allow TLS 1.2.

### C. Security headers proof

```text
HTTP/2 200
server: nginx
content-type: text/html; charset=UTF-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; connect-src 'self' https: wss:;
```

All six required security headers are present on the real Juice Shop response.

### What each header defends against

- **Strict-Transport-Security:** forces compatible browsers to use HTTPS and protects against HTTPS downgrade and SSL-stripping attacks.
- **X-Content-Type-Options:** prevents browsers from MIME-sniffing a response as a different and potentially executable content type.
- **X-Frame-Options:** prevents Juice Shop from being embedded inside a frame and reduces the risk of clickjacking.
- **Referrer-Policy:** limits the amount of URL information sent in the `Referer` header during cross-origin requests.
- **Permissions-Policy:** disables browser access to the camera, microphone, and geolocation APIs for this application.
- **Content-Security-Policy-Report-Only:** detects potentially unsafe content loading without immediately blocking resources and breaking the Juice Shop frontend.

---

## Task 2: Production Posture

### Rate limiting, connection limits, timeouts, and TLS hardening

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

limit_conn_zone $binary_remote_addr zone=conn:10m;
limit_conn_status 429;

proxy_connect_timeout 5s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;

server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;

  limit_conn conn 50;

  ssl_protocols TLSv1.3;
  ssl_prefer_server_ciphers off;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
  ssl_ecdh_curve X25519:secp384r1;

  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;

  client_body_timeout 10s;
  client_header_timeout 10s;
  send_timeout 10s;

  location = /rest/user/login {
    limit_req zone=login burst=5 nodelay;
    limit_req_log_level warn;

    proxy_pass http://juice;
  }
}
```

### Rate-limit proof

Sixty concurrent POST requests were sent to `/rest/user/login`.

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

```text
   6 401
  54 429
```

The six `401` responses reached Juice Shop and were rejected because deliberately invalid credentials were used. The remaining fifty-four requests were rejected by Nginx with `429 Too Many Requests`.

The Nginx error log also recorded rate-limit enforcement:

```text
limiting requests, excess: 5.972 by zone "login", client: 192.168.65.1, server: _, request: "POST /rest/user/login HTTP/2.0", host: "localhost"
```

### Timeout enforced

A TLS client sent an incomplete HTTP request header and then stopped transmitting data. Nginx closed the connection after the configured ten-second `client_header_timeout`.

```text
Connection closed/responded after: 10.0 seconds
```

A connection close is acceptable here because the configured timeout stopped the incomplete Slowloris-style request without forwarding it to Juice Shop.

### Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
```

The connection used TLS 1.3, the `TLS_AES_256_GCM_SHA384` authenticated encryption cipher suite, and an ephemeral X25519 key exchange.

### Certificate rotation runbook

1. **Detect expiry:** monitor the active certificate expiry date and generate an alert before the remaining lifetime reaches the renewal threshold, for example thirty days.
2. **Order new certificate:** request a replacement certificate from the approved public certificate authority through ACME automation or the organisation's certificate-management process.
3. **Validate:** verify the certificate subject alternative names, issuer chain, validity dates, private-key match, file permissions, and full certificate chain before deployment.
4. **Atomic swap:** save the new certificate and key under versioned paths, run `nginx -t`, atomically replace the active files or symbolic links, and reload Nginx without terminating existing connections.
5. **Verify:** connect externally with `openssl s_client` and `curl`, verify the new serial number and expiry date, and confirm that the HTTPS application and health endpoints still work.
6. **Rollback plan:** retain the previously working certificate and private key so they can be restored immediately, followed by another `nginx -t` check and Nginx reload.
7. **Audit:** record the certificate issuer, serial number, expiry date, deployment time, automation or operator identity, verification output, and any rollback activity.

### What OCSP stapling buys you

OCSP stapling allows the server to include a recently signed certificate-status response during the TLS handshake. This reduces client dependence on the certificate authority's OCSP service, improves connection performance, and prevents the client from disclosing every visited domain to the certificate authority.

OCSP stapling is useful for a publicly trusted production certificate because its issuing certificate authority provides a valid revocation-status response. The lab certificate is self-signed and has no public issuing authority or OCSP responder, so there is no meaningful OCSP response that Nginx can staple.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used:** ModSecurity v3 with the official OWASP CRS Nginx image
- **Container image:** `owasp/modsecurity-crs:4.25.1-nginx-lts`
- **OWASP CRS version:** 4.25.1 LTS
- **ModSecurity version:** 3.0.16
- **ModSecurity Nginx connector version:** 1.0.4
- **Paranoia level:** 1
- **Inbound anomaly threshold:** 5
- **Rule engine:** `On`
- **Rules loaded:** 849

ModSecurity v3 was selected because the lab permits either ModSecurity or Coraza and the official OWASP CRS image provides a reproducible WAF configuration with ModSecurity, the Nginx connector, CRS rules, blocking mode, and audit logging already integrated.

### WAF Docker Compose configuration

```yaml
services:
  waf:
    image: owasp/modsecurity-crs:4.25.1-nginx-lts
    restart: unless-stopped

    depends_on:
      - nginx

    ports:
      - "8080:8080"

    environment:
      BACKEND: "http://nginx:8081"

      SERVER_NAME: "localhost-waf"
      PORT: "8080"
      NGINX_ALWAYS_TLS_REDIRECT: "off"

      MODSEC_RULE_ENGINE: "On"

      BLOCKING_PARANOIA: "1"
      DETECTION_PARANOIA: "1"
      ANOMALY_INBOUND: "5"

      MODSEC_AUDIT_ENGINE: "On"
      MODSEC_AUDIT_LOG: "/var/log/modsec/audit.log"
      MODSEC_AUDIT_LOG_FORMAT: "Native"
      MODSEC_AUDIT_LOG_PARTS: "ABIJDEFHZ"
      MODSEC_AUDIT_LOG_TYPE: "Serial"

      ERRORLOG: "/var/log/modsec/error.log"
      LOGLEVEL: "warn"
      SSL_OCSP_STAPLING: "off"

    volumes:
      - ./waf/logs:/var/log/modsec:rw
```

### Architecture

```text
Baseline path without WAF:
Client → hardened Nginx :443 → Juice Shop :3000

Protected path with WAF:
Client → ModSecurity and OWASP CRS :8080 → internal Nginx :8081 → Juice Shop :3000
```

The internal Nginx listener on port `8081` is available only inside the Docker Compose network and is not published on the host.

### WAF stack proof

```text
NAME            IMAGE                                    SERVICE   STATUS
lab11-juice-1   bkimminich/juice-shop:v20.0.0            juice     Up
lab11-nginx-1   nginx:stable-alpine                      nginx     Up
lab11-waf-1     owasp/modsecurity-crs:4.25.1-nginx-lts   waf       Up (healthy)
```

The WAF container loaded ModSecurity and OWASP CRS successfully:

```text
ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 0/849/0)
libmodsecurity3 version 3.0.16
```

A normal request passed through the WAF:

```text
normal-through-waf: HTTP 200
```

The Juice Shop version endpoint was also reachable through the WAF:

```json
{
  "version": "20.0.0"
}
```

### Attack payload sent

The following SQL injection payload was placed in the JSON `email` field:

```http
POST /rest/user/login HTTP/1.1
Content-Type: application/json
```

```json
{
  "email": "' or 1=1--",
  "password": "x"
}
```

### Before WAF: Nginx alone

```text
no-waf: HTTP 200
```

The hardened Nginx proxy forwarded the request because TLS controls, security headers, timeouts, connection limits, and request-rate limits do not inspect the SQL meaning of values inside the JSON request body.

### After WAF

```text
with-waf: HTTP 403
```

ModSecurity inspected the JSON request body, OWASP CRS detected the SQL injection pattern, and the request was blocked before it reached Juice Shop.

### Audit-log excerpt

```text
ModSecurity: Warning. detected SQLi using libinjection.
[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]
[line "46"]
[id "942100"]
[msg "SQL Injection Attack Detected via libinjection"]
[data "Matched Data: s&1c found within ARGS:json.email: ' or 1=1--"]
[severity "2"]
[ver "OWASP_CRS/4.25.1"]
[tag "attack-sqli"]
[tag "paranoia-level/1"]
[uri "/rest/user/login"]

ModSecurity: Access denied with code 403 (phase 2).
[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"]
[line "222"]
[id "949110"]
[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
[ver "OWASP_CRS/4.25.1"]
[uri "/rest/user/login"]
```

Rule ID **942100**, named **SQL Injection Attack Detected via libinjection**, identified the malicious value inside `ARGS:json.email`.

Rule ID **949110**, named **Inbound Anomaly Score Exceeded**, blocked the request because its accumulated inbound anomaly score reached the configured threshold of five.

### Tradeoff analysis

The WAF provides runtime request inspection and blocking for attacks that SAST, DAST, and infrastructure-policy checks cannot stop when a real malicious request reaches the running service. Its costs include additional latency, configuration and maintenance overhead, audit-log management, an extra runtime dependency, and false-positive risk that increases at higher paranoia levels. I would not deploy a WAF in front of a small low-risk internal service when strict application-level validation already covers its limited API and the extra failure mode and tuning burden would outweigh the expected security benefit.
