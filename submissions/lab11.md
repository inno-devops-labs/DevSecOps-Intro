# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_conn_zone $binary_remote_addr zone=conn:10m;
    limit_req_status 429;

    # Timeouts (fail-closed)
    client_body_timeout 10s;
    client_header_timeout 10s;
    proxy_read_timeout 30s;
    proxy_connect_timeout 5s;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Upstream definition
    upstream juice_backend {
        server juice:3000;
    }

    # HTTP → HTTPS redirect
    server {
        listen 80;
        server_name juice.local;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS server
    server {
        # FIXED: http2 as separate directive instead of listen parameter
        listen 443 ssl;
        http2 on;
        server_name juice.local;

        # SSL/TLS Configuration
        ssl_certificate /etc/nginx/certs/localhost.crt;
        ssl_certificate_key /etc/nginx/certs/localhost.key;
        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;

        # FIXED: Use OpenSSL 1.1.1 compatible cipher names
        # Alpine's OpenSSL uses different cipher names for TLSv1.3
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_ecdh_curve X25519:secp384r1;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        # OCSP stapling (documentation-only for self-signed)
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 1.1.1.1 valid=300s;

        # Connection limits
        limit_conn conn 50;

        # Security Headers (all with 'always' keyword)
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self';" always;

        # Root location
        location / {
            proxy_pass http://juice_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Rate-limited login endpoint
        location /rest/user/login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://juice_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check endpoint (no rate limit)
        location /health {
            proxy_pass http://juice_backend;
            proxy_set_header Host $host;
            access_log off;
        }
    }
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 301 Moved Permanently
Server: nginx/1.30.3
Date: Fri, 10 Jul 2026 22:33:21 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: https://juice.local/
```

### B. TLS 1.3 proof
```
Connecting to 127.0.0.1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

### C. Security headers proof (all 6 present)
```
HTTP/2 200 
server: nginx/1.30.3
date: Fri, 10 Jul 2026 22:49:44 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
access-control-allow-origin: *
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 10 Jul 2026 22:32:46 GMT
etag: W/"26af-19f4e297212"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self';
```

### What each header defends against (1 sentence each)
- **HSTS**: Forces the browser to only ever connect over HTTPS for the `max-age` window, closing the gap where an attacker on the network downgrades the first request to plaintext HTTP and intercepts or tampers with it (SSL-stripping).
- **X-Content-Type-Options: nosniff**: Stops the browser from MIME-sniffing a response into an executable context (e.g. treating an uploaded "image" as HTML/JS), which is how content-type confusion turns into stored XSS.
- **X-Frame-Options: DENY**: Prevents the page from being rendered inside an `<iframe>` on another origin, which is what clickjacking attacks rely on to trick users into clicking UI they can't actually see.
- **Referrer-Policy**: `strict-origin-when-cross-origin` stops the full URL — including query strings, tokens, or IDs — from leaking to third-party sites via the `Referer` header when a user clicks an outbound link.
- **Permissions-Policy**: Explicitly denies camera, microphone, and geolocation access to the page and any embedded iframe, so even injected or compromised script can't silently request those APIs.
- **Content-Security-Policy**: Restricts which origins scripts, styles, fonts, and connections are allowed to load from, so even if an attacker manages to inject markup (reflected/stored XSS), the browser refuses to execute or fetch anything outside the allow-list.

> **Note on CSP:** This config ships `Content-Security-Policy-Report-Only` rather than an enforcing `Content-Security-Policy`. This is intentional, per the lab's own guidance (see "Common Pitfalls": *"CSP `default-src 'self'` breaks Juice Shop frontend — Juice Shop loads inline scripts + remote fonts. Use `Content-Security-Policy-Report-Only` for the lab; tighten iteratively in real deployments."*). Report-Only mode still sends the header and lets the policy be observed against real traffic without breaking the app, which is the correct posture for a lab environment where the policy hasn't been iteratively tuned against Juice Shop's actual script/style sources yet. In a real deployment, the next step would be to run traffic against this policy, review the CSP violation reports, add any legitimate sources that get flagged, and only then flip it to enforcing `Content-Security-Policy`.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced

Test command:
```bash
time { (printf "GET / HTTP/1.1\r\nHost: localhost\r\n"; sleep 15) \
  | openssl s_client -connect localhost:443 -tls1_3 -quiet -ign_eof 2>&1 \
  | tee labs/lab11/results/timeout.txt ; }
```

> Note: the lab sheet's suggested `nc`-based timeout test (`echo "GET / HTTP/1.0" | nc localhost 443`)
> doesn't work against this vhost — port 443 is TLS-only, and `nc` sends raw unencrypted
> bytes, so nginx drops the connection as an invalid TLS handshake before it ever reaches
> the HTTP layer / `client_header_timeout` logic. Used `openssl s_client` instead to
> complete a real TLS handshake first, then drip an incomplete HTTP request.

Output:
```
Connecting to 127.0.0.1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=juice.local
verify return:1
40E704ECB5760000:error:0A000126:SSL routines::unexpected eof while reading:ssl/record/rec_layer_s3.c:698:
```

### Cipher hardening
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: Run an automated daily check — either `openssl x509 -enddate -noout -in localhost.crt` on a cron job, or a monitoring probe (e.g. Prometheus `blackbox_exporter`'s `probe_ssl_earliest_cert_expiry` metric) — and alert at 30/14/3 days before expiry so rotation is never a same-day scramble.

2. **Order new cert**: Generate a new CSR with the same key parameters (RSA size or curve, SAN list) as the current cert, and submit it to the CA — `certbot renew` for Let's Encrypt, or the equivalent request flow for a commercial CA. The private key is generated on the host that will serve it and never leaves that host in plaintext.

3. **Validate**: Before touching production, verify the new cert's chain and metadata: `openssl verify -CAfile chain.pem new.crt` to confirm chain of trust, `openssl x509 -noout -text -in new.crt` to check SANs/expiry, and confirm the private key actually matches the cert by comparing moduli: `openssl x509 -noout -modulus -in new.crt | md5sum` vs `openssl rsa -noout -modulus -in new.key | md5sum`.

4. **Atomic swap**: Write the new `.crt`/`.key` to a staging path on the same filesystem, then `mv` them over the live `/etc/nginx/certs/localhost.{crt,key}` paths. `mv` on the same filesystem is an atomic rename — there's no window where nginx could read a half-written file. Follow with `nginx -s reload`, which re-reads config and certs on a graceful reload with zero dropped connections (no bind/listen interruption).

5. **Verify**: Re-run the Task 1 proof commands against the live endpoint — `openssl s_client -connect ... -tls1_3` to confirm the served cert's CN/SAN/expiry match the new cert, `curl -skI` to confirm headers and TLS still negotiate correctly — and check nginx's error log for a spike immediately after reload.

6. **Rollback plan**: Keep the previous cert/key pair archived (not deleted) for at least one full rotation cycle. Rollback is the same atomic `mv` run in reverse plus `nginx -s reload` — executable in under a minute if the new cert breaks something (wrong SAN, chain issue, etc.), so the blast radius of a bad rotation is capped at "one reload cycle," not "however long it takes to re-issue."

7. **Audit**: Log who or what triggered the rotation, the old and new cert serial numbers and SHA-256 fingerprints, and the timestamp, shipped to a tamper-evident log (SIEM, append-only audit store). This makes cert provenance traceable for compliance review and gives you a clean paper trail if a rotation ever needs to be investigated after the fact.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
OCSP stapling lets nginx pre-fetch the CA's signed revocation status for its own certificate and attach ("staple") it directly to the TLS handshake, so the client doesn't have to make its own separate call to the CA's OCSP responder, which saves a round trip and, more importantly, stops the CA from learning which sites every visitor connects to (a real privacy leak in the non-stapled model). It matters in production because a CA-issued cert can be revoked mid-lifetime (key compromise, mis-issuance) and clients need a fast way to check that without stalling page loads. For this lab it's documentation-only: a self-signed cert has no CA-operated OCSP responder to staple a response from, so `ssl_stapling on;` is inert against `localhost.crt`, so it only becomes meaningful the day this config is pointed at a Let's Encrypt or commercial CA certificate.  

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: **ModSecurity v3** (`owasp/modsecurity-crs:nginx-alpine`, the CRS project's official prepackaged Nginx + ModSecurity v3 image), per the lab's own steer toward option (c) for the richer OWASP CRS documentation.
- OWASP CRS version: **3.3.10** (as reported by the audit log's `ver` field — the `nginx-alpine` tag pulled at setup time shipped CRS 3.3.10 rather than a 4.x release; noted here rather than silently claiming 4.x per the original plan, since the actual deployed version matters more than the target).
- Paranoia level: **1** (`PARANOIA=1`), inbound anomaly threshold 5, outbound 4 — CRS defaults, confirmed live in the container's rule-configuration log (`Configuring 900000 for PARANOIA with paranoia_level=1`).

> **Setup notes / deviations found along the way:**
> - The lab sheet's `https://localhost-waf` endpoint and `/var/log/modsec/audit.log` path don't apply to this image — used `http://localhost:8080` (the WAF's actual exposed port; it terminates plain HTTP client-side and re-establishes TLS to the backend nginx internally) and the image's real audit log path instead.
> - This image's mTLS-to-backend directives use env vars `PROXY_SSL_CERT` / `PROXY_SSL_CERT_KEY` (matching the nginx directive names literally), not the shorter names one might guess by analogy with `PROXY_SSL_VERIFY`. Both must point at real, parseable files even with `PROXY_SSL_VERIFY=off`, or nginx fails at config-parse time (`unknown "proxy_ssl_cert" variable`).
> - The image only grants the `nginx` uid (101) write access to `/var/log/modsecurity/audit/` — the parent `/var/log/modsecurity/` is `root:root` and read-only to the worker. `MODSEC_AUDIT_LOG` must point *inside* the writable subdirectory (`/var/log/modsecurity/audit/audit.log`), not the parent — pointing at the parent silently produces zero log output with no error surfaced anywhere in the container's stdout/stderr, making this the least obvious of the setup issues to diagnose.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone, port 443)
```
no-waf: HTTP 500
```
Nginx alone proxies the payload straight through with no blocking — the 500 is Juice Shop's own backend choking on the raw SQL tautology, not a WAF or Nginx rejection. The point of this baseline is the absence of blocking, which is confirmed: the request reached the application layer untouched.

### After WAF (through ModSecurity sidecar, port 8080)
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```json
{"transaction":{"client_ip":"172.19.0.1","time_stamp":"Fri Jul 17 08:34:45 2026","unique_id":"178427728594.197947","is_interrupted":true,"request":{"method":"GET","uri":"/rest/products/search?q=%27%20OR%201=1--"},"response":{"http_code":403},"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.","ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--","tags":["attack-sqli","paranoia-level/1","OWASP_CRS","PCI/6.5.2"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"match":"Matched \"Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' )","ruleId":"949110","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"}}]}}
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection** (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`). This is the specific detection rule — it ran libinjection's SQLi parser against `ARGS:q` and flagged the tautology directly, rather than a generic pattern match. It contributed to the inbound anomaly score, which then tripped the separate aggregate blocking rule **949110** (`REQUEST-949-BLOCKING-EVALUATION.conf`, "Inbound Anomaly Score Exceeded") once the running total hit the paranoia-level-1 threshold of 5 — this two-rule structure (specific detector + aggregate blocking gate) is how CRS's anomaly-scoring engine works: individual rules add points, one gate rule enforces the cutoff and returns the actual 403.

### Tradeoff analysis
A WAF is the only one of the three controls (SAST, DAST, and the L7 Conftest gate) still watching *after* deployment, against whatever traffic is live right now — SAST caught bugs in code as written and DAST caught them in a scan window before ship, but neither is watching production traffic in real time, including against exploitation attempts or dependency 0-days that never showed up in either scan; this run demonstrated exactly that gap, since Nginx alone passed the SQLi payload straight to a 500 while the WAF caught and blocked it inline based on the actual request content. The cost is real: paranoia levels above 1 have a well-documented false-positive rate against legitimate traffic (file uploads, JSON APIs with special characters, free-text search boxes), so ongoing rule tuning and exclusions become real ops work, on top of the added hop, TLS re-termination point, and config/cert surface the WAF itself introduces — this bonus alone took several rounds of debugging undocumented env-var names and file-permission quirks before it worked. You'd skip a WAF in front of a purely internal, schema-strict service with no untrusted input path (e.g. an internal gRPC service only ever called by other trusted services with a fixed protobuf schema), or anywhere the added latency would blow a tight SLO while the input surface is already narrow and well-typed enough that the marginal protection isn't worth the cost.