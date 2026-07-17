# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
user  nginx;
worker_processes  auto;

events { worker_connections 1024; }

http {
  include       /etc/nginx/mime.types;
  default_type  application/octet-stream;
  sendfile      on;
  keepalive_timeout  10;
  server_tokens off;
  gzip off;

  log_format security '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent" '
                     'rt=$request_time uct=$upstream_connect_time '
                     'urt=$upstream_response_time';
  access_log /var/log/nginx/access.log security;
  error_log  /var/log/nginx/error.log warn;

  upstream juice {
    server juice:3000;
    keepalive 32;
  }

  # Rate limit zone for login
  limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
  limit_conn_zone $binary_remote_addr zone=conn:10m;
  limit_req_status 429;

  map $http_upgrade $connection_upgrade { default upgrade; '' close; }

  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_http_version 1.1;
  proxy_set_header Connection $connection_upgrade;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Accept-Encoding "";
  proxy_read_timeout 30s;
  proxy_send_timeout 30s;
  proxy_connect_timeout 5s;
  proxy_hide_header X-Powered-By;
  proxy_hide_header X-Frame-Options;
  proxy_hide_header X-Content-Type-Options;
  proxy_hide_header Referrer-Policy;
  proxy_hide_header Permissions-Policy;
  proxy_hide_header Cross-Origin-Opener-Policy;
  proxy_hide_header Cross-Origin-Resource-Policy;
  proxy_hide_header Content-Security-Policy;
  proxy_hide_header Content-Security-Policy-Report-Only;
  proxy_hide_header Access-Control-Allow-Origin;

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
    ssl_session_timeout 10m;
    ssl_session_cache   shared:SSL:10m;
    ssl_protocols TLSv1.3;
    ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:EECDH+AESGCM:EDH+AESGCM";
    ssl_ecdh_curve X25519:secp384r1;
    ssl_prefer_server_ciphers off;
    ssl_stapling off;
    # If using a publicly-trusted certificate, you may enable OCSP stapling:
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # resolver 1.1.1.1 8.8.8.8 valid=300s;
    # resolver_timeout 5s;
    # ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

    limit_conn conn 50;

    client_max_body_size 2m;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 10s;
    send_timeout 10s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

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

```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 13:08:31 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
Redirect from HTTP to HTTPS is performed with status 308 (Permanent Redirect), ensuring that all subsequent requests use HTTPS.

### B. TLS 1.3 proof
```
New, TLSv1/SSLv3, Cipher is AEAD-CHACHA20-POLY1305-SHA256
    Protocol  : TLSv1.3
    Cipher    : AEAD-CHACHA20-POLY1305-SHA256
```
The TLSv1.3 protocol is successfully negotiated, confirming that only TLS 1.3 is allowed.

### C. Security headers proof (all 6 present)

```
HTTP/2 200 
server: nginx
date: Fri, 17 Jul 2026 13:08:46 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 13:07:54 GMT
etag: W/"26af-19f7030ced0"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```
All six required security headers are present in the response:

- `Strict-Transport-Security` 
- `X-Content-Type-Options` 
- `X-Frame-Options` 
- `Referrer-Policy` 
- `Permissions-Policy` 
- `Content-Security-Policy-Report-Only`

Additionally, Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy are included for enhanced isolation.

### What each header defends against (1 sentence each)

- <b>HSTS</b>: Forces the browser to always use HTTPS, protecting against protocol downgrade attacks and certificate spoofing.
- <b>X-Content-Type-Options</b>: nosniff: Prevents the browser from performing MIME sniffing, mitigating attacks that rely on content-type confusion (e.g., loading scripts from files disguised as images).
- <b>X-Frame-Options</b>: DENY: Prevents the page from being embedded in a frame, protecting against clickjacking.
- <b>Referrer-Policy</b>: strict-origin-when-cross-origin: Controls what referrer information is sent when navigating between origins, reducing data leakage.
- <b>Permissions-Policy</b>: Restricts access to sensitive browser APIs (camera, microphone, geolocation), shrinking the attack surface.
- <b>Content-Security-Policy (Report-Only)</b>: Tells the browser which resources are allowed to be loaded, mitigating XSS and data injection; the `Report-Only` mode allows violation collection without blocking.

## Task 2: Production Posture

### Rate limit proof

```
  54 429
   6 500
```
Out of 60 parallel requests to `/rest/user/login`, 54 were rejected with status `429` (Too Many Requests), confirming the limit of 10 requests per minute with a burst of 5. The remaining 6 returned `500` – likely because Juice Shop does not accept GET requests on that endpoint, but this does not affect the evidence of rate limiting.

### Timeout enforced

The `timeout` utility is not available on macOS, so the actual test could not be performed. However, the Nginx configuration explicitly sets:

- `client_body_timeout 10s`;
- `client_header_timeout 10s`;
- `proxy_read_timeout 30s`;
- `proxy_connect_timeout 5s;`
- 
These timeouts are configured to close connections when waiting times are exceeded, following the "fail‑closed" principle. The relevant excerpt from `nginx.conf` is:
```
client_max_body_size 2m;
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 10s;
send_timeout 10s;
```

### Cipher hardening

```
New, TLSv1/SSLv3, Cipher is AEAD-CHACHA20-POLY1305-SHA256
    Cipher    : AEAD-CHACHA20-POLY1305-SHA256
```

The cipher `AEAD-CHACHA20-POLY1305-SHA256` is part of the recommended TLS 1.3 cipher suite, and the directive `ssl_ecdh_curve X25519:secp384r1` ensures modern elliptic curves are used.

### Cert rotation runbook (7 steps)

1. <b>Detect expiry</b>: Set up monitoring (e.g., a cron job checking `openssl x509 -enddate -noout -in cert.pem`) and send alerts 30 days before expiration.
2. <b>Order new cert</b>: Request a new certificate from Let's Encrypt (or an internal CA) with the same CN/SAN, using an automated tool like Certbot.
3. <b>Validate</b>: Verify the new certificate’s chain, validity period, key match, and run `openssl verify` to ensure no errors.
4. <b>Atomic swap</b>: Replace the old `.crt` and `.key` files with the new ones (using symlinks or a copy script), then reload Nginx (`nginx -s reload`) without stopping the service.
5. <b>Verify</b>: Confirm that the new certificate is active by running `openssl s_client -connect` and checking the serial number and expiration date.
6. <b>Rollback plan</b>: If verification fails, restore the previous certificate (saved copies) and reload Nginx again.
7. <b>Audit</b>: Log the operation including the date, certificate source, and verification results.

### What OCSP stapling buys you (2-3 sentences)

OCSP stapling allows the web server to send a signed OCSP response to the client, saving a separate round‑trip to the OCSP server and improving privacy (the client does not expose its IP). In production, this boosts performance and reliability because the client is not blocked waiting for the OCSP response. For a self‑signed certificate, OCSP stapling is not meaningful (and won't work) because there is no external OCSP server to verify the certificate.

