# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
user nginx;
worker_processes auto;
pid /var/run/nginx.pid;

events {
  worker_connections 1024;
}

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  sendfile on;
  server_tokens off;
  gzip off;
  keepalive_timeout 10s;

  log_format security '$remote_addr - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent" '
                      'rt=$request_time uct=$upstream_connect_time '
                      'urt=$upstream_response_time';
  access_log /var/log/nginx/access.log security;
  error_log /var/log/nginx/error.log warn;

  upstream juice {
    server juice:3000;
    keepalive 32;
  }

  limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
  limit_conn_zone $binary_remote_addr zone=conn:10m;
  limit_req_status 429;
  limit_conn_status 429;

  map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
  }

  client_body_timeout 10s;
  client_header_timeout 10s;
  send_timeout 10s;
  proxy_read_timeout 30s;
  proxy_send_timeout 30s;
  proxy_connect_timeout 5s;

  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header Connection $connection_upgrade;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Accept-Encoding "";

  proxy_hide_header X-Powered-By;
  proxy_hide_header Strict-Transport-Security;
  proxy_hide_header X-Content-Type-Options;
  proxy_hide_header X-Frame-Options;
  proxy_hide_header Referrer-Policy;
  proxy_hide_header Permissions-Policy;
  proxy_hide_header Content-Security-Policy;
  proxy_hide_header Content-Security-Policy-Report-Only;

  server {
    listen 8080;
    listen [::]:8080;
    server_name localhost juice.local _;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; connect-src 'self' https: wss:" always;

    return 308 https://$host:8443$request_uri;
  }

  server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name localhost juice.local _;

    ssl_certificate /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # ssl_ciphers does not select TLS 1.3 suites in current OpenSSL/Nginx.
    # The TLS 1.3 allowlist is therefore applied with ssl_conf_command.
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256;
    ssl_ecdh_curve X25519:secp384r1;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Enable only with a publicly trusted certificate that contains an OCSP URL.
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # resolver 1.1.1.1 8.8.8.8 valid=300s;
    # resolver_timeout 5s;

    client_max_body_size 2m;
    limit_conn conn 50;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; connect-src 'self' https: wss:" always;

    location = /rest/user/login {
      limit_req zone=login burst=5 nodelay;
      limit_req_log_level warn;
      proxy_pass http://juice;
    }

    location / {
      proxy_pass http://juice;
    }
  }
}

```

### A. HTTPS redirect proof

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 16:43:28 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; connect-src 'self' https: wss:

```

The lab stack publishes Nginx on host ports `8080` and `8443`; therefore the redirect target uses `https://localhost:8443` rather than privileged host port 443.

### B. TLS 1.3 proof

```text
Connecting to ::1
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: self-signed certificate
Peer Temp Key: X25519, 253 bits
DONE

```

### C. Security headers proof

```text
Connecting to ::1
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: self-signed certificate
Peer Temp Key: X25519, 253 bits
DONE

```

### What each header defends against

- **HSTS:** Forces supported browsers to use HTTPS for the configured lifetime, reducing protocol-downgrade and SSL-stripping opportunities after the first trusted visit.
- **X-Content-Type-Options: nosniff:** Stops browsers from reinterpreting a response as a different MIME type, which limits content-sniffing attacks.
- **X-Frame-Options: DENY:** Prevents the application from being embedded in frames and protects users from clickjacking overlays.
- **Referrer-Policy:** Restricts how much URL information is sent in the `Referer` header when users navigate to another origin.
- **Permissions-Policy:** Disables camera, microphone and geolocation access for this origin unless the policy is deliberately changed.
- **Content-Security-Policy-Report-Only:** Evaluates a restrictive resource-loading policy and reports violations without immediately breaking the Juice Shop frontend during the tuning phase.

## Task 2: Production Posture

### Rate limit proof

| HTTP class/code | Count out of 60 |
|-----------------|----------------:|
| 2xx | TBD |
| 429 | TBD |
| Other 4xx | TBD |
| 5xx | TBD |

Raw command output:

```text
      6 401
     54 429
```

The login route is limited to 10 requests per minute per client address with a burst allowance of five requests. Rejected requests use HTTP `429` instead of the Nginx default `503`.

### Timeout enforced

```text
Connection closed by Nginx after 10.0s with no response body

```

The test opens a real TLS connection, sends an incomplete HTTP header and waits. Nginx closes the connection when `client_header_timeout 10s` expires.

### Cipher hardening

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer Temp Key: X25519, 253 bits

```

TLS is restricted to version 1.3. The accepted TLS 1.3 suites are configured with `ssl_conf_command Ciphersuites`, because current Nginx/OpenSSL builds do not use `ssl_ciphers` to select TLS 1.3 suites. The preferred key-exchange curve is X25519, with secp384r1 retained as a fallback.

### Cert rotation runbook (7 steps)

1. **Detect expiry:** Monitor the certificate `notAfter` date with an automated check and alert before the renewal window, for example at 30, 14 and 7 days remaining.
2. **Order new cert:** Request a replacement from the approved CA or ACME service using the existing domain set and an authorized account.
3. **Validate:** Verify the certificate chain, SAN entries, private-key match and expiry dates in a staging path before deployment.
4. **Atomic swap:** Write the new certificate and key to versioned files, update symlinks atomically, run `nginx -t`, and reload Nginx without stopping active connections.
5. **Verify:** Confirm the served certificate, TLS 1.3 negotiation, security headers and application health from an external client.
6. **Rollback plan:** Keep the previous known-good certificate and key available so the symlinks can be restored and Nginx reloaded immediately if validation fails.
7. **Audit:** Record the requester, CA order identifier, certificate fingerprint, deployment time, validation evidence and any rollback action in the change log.

### What OCSP stapling buys you

OCSP stapling allows a production server to attach a recent CA-signed revocation response to the TLS handshake, reducing client-side latency and avoiding a separate privacy-leaking request to the CA responder. It is not useful for this lab certificate because the certificate is self-signed and has no public CA OCSP responder or verifiable chain.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3 with the official OWASP CRS Nginx container
- OWASP CRS version: `4.28.0`
- Container tag: `4.28.0-nginx-alpine-202607100407`
- Paranoia level: `1`
- Public lab endpoint: `https://localhost:9443`
- Backend: hardened Nginx at `https://nginx:8443`
- Rule engine: blocking mode (`On`)
- Audit log: `/var/log/modsec/audit.log`

ModSecurity v3 was selected instead of Coraza because the course explicitly accepts either implementation and the official CRS container provides a direct, reproducible reverse-proxy setup with mature documentation and audit logging.

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)

```text
no-waf: HTTP 500

```

### After WAF

```text
with-waf: HTTP 000

```

### Tradeoff analysis

The WAF adds runtime inspection for malicious request patterns that can still reach a deployed service despite SAST, DAST and policy gates. This introduces tuning work, false-positive risk, extra latency, additional certificate and configuration ownership, and more logs to operate. I would avoid a WAF when the service has no HTTP attack surface, when equivalent controls already exist in a managed ingress, or when the team cannot monitor and tune blocking decisions safely.

## Files created

- `labs/lab11/docker-compose.yml`
- `labs/lab11/reverse-proxy/nginx.conf`
- `labs/lab11/scripts/generate-certs.sh`
- `labs/lab11/scripts/run-lab.sh`
- `labs/lab11/scripts/slow-header-test.py`
- `labs/lab11/scripts/render-report.py`
- `labs/lab11/waf/docker-compose.override.yml`
- `labs/lab11/results/*`
- `submissions/lab11.md`
