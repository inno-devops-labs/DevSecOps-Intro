# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

> **Note:** The stack uses ports `8080` (HTTP) and `8443` (HTTPS) instead of `80/443` to avoid conflicts with other services.

```nginx
http {
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_status 429;

    # HTTP server — redirect to HTTPS
    server {
        listen 8080;
        listen [::]:8080;
        server_name _;

        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Resource-Policy "same-origin" always;
        add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

        return 308 https://$host:8443$request_uri;
    }

    # HTTPS server
    server {
        listen 8443 ssl;
        listen [::]:8443 ssl;
        http2 on;
        server_name _;

        ssl_certificate     /etc/nginx/certs/localhost.crt;
        ssl_certificate_key /etc/nginx/certs/localhost.key;

        ssl_session_timeout 1d;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_tickets off;

        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_ecdh_curve X25519:secp384r1;

        client_body_timeout 10s;
        client_header_timeout 10s;
        keepalive_timeout 10s;
        send_timeout 10s;
        proxy_read_timeout 30s;
        proxy_connect_timeout 5s;

        limit_conn_zone $binary_remote_addr zone=conn:10m;
        limit_conn conn 50;

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
            proxy_pass http://juice:3000;
        }

        location / {
            proxy_pass http://juice:3000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}

A. HTTPS redirect proof
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 19:45:12 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

B. TLS 1.3 proof
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local

TLS 1.3 negotiated with a modern cipher suite (the exact suite may vary by OpenSSL version, but the protocol is TLSv1.3).

C. Security headers proof (all 6 present)
text

HTTP/2 200 
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'

What each header defends against

    HSTS: Forces browsers to use HTTPS only for the specified duration and subdomains, preventing downgrade attacks like SSL stripping.

    X-Content-Type-Options: nosniff: Stops browsers from MIME-sniffing responses, blocking attacks that try to execute uploaded content with a different Content-Type than declared.

    X-Frame-Options: DENY: Prevents the page from being loaded inside an iframe on any origin, mitigating clickjacking attacks.

    Referrer-Policy: Limits referrer information sent to third-party sites, protecting sensitive data (e.g., tokens in URLs) from leaking via the Referer header.

    Permissions-Policy: Disables unnecessary browser features (camera, geolocation, microphone) that Juice Shop does not require, reducing the impact of potential XSS.

    Content-Security-Policy-Report-Only: Restricts resource loading sources and reports violations (Report-Only mode used here to avoid breaking Juice Shop’s inline scripts and eval usage); serves as a foundation for future strict enforcement.


Task 2: Production Posture
Rate limit proof
HTTP code	Count out of 60
429	53
500	7

53 requests were correctly rate-limited with 429 Too Many Requests. The few 500s are expected upstream Juice Shop behavior under heavy concurrent load (empty login payloads).



Timeout enforced
GET / HTTP/1.0
HTTP/1.1 408 Request Time-out
Server: nginx
...


Nginx closed the connection after client_header_timeout 10s when a slow/partial request was sent, returning 408 (or connection reset). This confirms the timeout is enforced.

Cipher hardening
Cipher    : TLS_AES_256_GCM_SHA384
Server Temp Key: ECDH, X25519, 253 bits

Matches Mozilla Modern profile: TLS 1.3 only + strong AEAD ciphers + X25519 curve.

Cert rotation runbook (7 steps)

    Detect expiry: Use a daily cron job with openssl x509 -noout -enddate -in /etc/nginx/certs/localhost.crt or Prometheus ssl_expiry_seconds metric; alert at ≥30 days remaining.

    Order new cert: Run certbot renew (Let’s Encrypt) or submit CSR to internal CA; place new files in a staging directory.

    Validate: Verify chain with openssl verify and test handshake with openssl s_client against staging certs.

    Atomic swap: Copy new cert/key into place, run nginx -t, then nginx -s reload.

    Verify: Confirm new cert is served with openssl s_client -connect localhost:443 and check updated expiry date.

    Rollback plan: Keep .bak copies of previous cert/key; restore with cp + reload if issues arise (under 30s downtime).

    Audit: Log event (old/new serial, operator, timestamp) to audit trail; update secrets manager and close ticket with verification evidence.




What OCSP stapling buys you

OCSP stapling allows Nginx to proactively fetch and cache the CA’s revocation status response, then attach it directly to the TLS handshake. This gives clients proof of non-revocation without extra round-trips to the CA and without leaking browsing history to the CA. In this lab with a self‑signed certificate there is no real OCSP responder, so ssl_stapling on has no effect (and would log warnings); it becomes valuable only with a publicly trusted CA in production.


Bonus: WAF Sidecar with OWASP CRS

Setup choice

    WAF used: ModSecurity v3.0 + nginx connector (official owasp/modsecurity-crs:nginx image)

    OWASP CRS version: 4.28.0

    Paranoia level: 1

    SecRuleEngine: On (blocking mode)


Attack payload sent

GET /rest/products/search?q=' OR 1=1--

(URL-encoded: q=%27%20OR%201=1--)

Before WAF (Nginx alone)

no-waf: HTTP 500

The request reached Juice Shop unfiltered (the app errored, but the proxy did not block).

After WAF

with-waf: HTTP 403

Audit log excerpt (the rule that fired)

{
  "transaction": {
    "client_ip": "172.24.0.1",
    "time_stamp": "Fri Jul 17 17:58:19 2026",
    "is_interrupted": true,
    "request": {
      "method": "GET",
      "uri": "/rest/products/search?q='%20OR%201=1--"
    },
    "response": { "http_code": 403 },
    "producer": {
      "modsecurity": "ModSecurity v3.0.16",
      "components": ["OWASP_CRS/4.28.0"]
    },
    "messages": [
      {
        "message": "SQL Injection Attack Detected via libinjection",
        "details": {
          "ruleId": "942100",
          "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
          "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
          "severity": "2"
        }
      },
      {
        "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
        "details": { "ruleId": "949110" }
      }
    ]
  }
}


Rule ID: 942100 — SQL Injection Attack Detected via libinjection (REQUEST-942-APPLICATION-ATTACK-SQLI.conf). Anomaly score reached threshold → blocked by 949110.

Tradeoff analysis

The WAF provides real‑time, runtime protection that catches exploit attempts (including novel variations) that static SAST/DAST scans and code reviews miss — it acts as a compensating control while the underlying SQL injection in Juice Shop is being fixed.
The cost includes operational overhead (tuning false positives at higher paranoia levels, reviewing rules after config changes) and added latency/memory usage.
A WAF should not be the primary defense for a service; it is best used as an additional layer when patching cannot be done immediately or for legacy/high‑risk applications. For greenfield services, fixing the vulnerability in the application code is always preferred.


