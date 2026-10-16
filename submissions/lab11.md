# Lab 11 Submission — Edge Hardening with a Reverse Proxy

**Git identity:** `shnupel <ufamail.com2@gmail.com>`

## Task 1

The HTTP endpoint returns **308 Permanent Redirect** to the equivalent HTTPS URL. I chose 308 because it permanently redirects while preserving the request method and body for API requests.

The HTTPS endpoint is configured for TLS 1.2 and TLS 1.3. TLS 1.3 suites are restricted with `ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`; the TLS 1.2 list contains AES-GCM suites. A live connection negotiated `TLSv1.3` with `TLS_AES_256_GCM_SHA384`. The verification command used was:

```bash
openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
```

The six required response headers are:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

I used `Content-Security-Policy-Report-Only` first so Juice Shop can report violations without breaking its existing scripts, inline code, styles, and resource connections. Enforcing this initial policy would likely make parts of the application fail to load or function. I would collect violation reports, inventory legitimate sources, replace unsafe inline code with nonces or hashes where possible, and refine the policy in stages. After monitoring shows no expected traffic is blocked, I would enforce it with a staged rollout and rollback plan.

## Task 2

The login limit is `10r/m` per client address with `burst=5 nodelay`. A test sequence returned:

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

The proxy also has `limit_conn_zone $binary_remote_addr zone=perip:10m` and `limit_conn perip 20`.

TLS 1.3 allows only `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`. A connection offering `TLS_CHACHA20_POLY1305_SHA256` produced `Cipher is (NONE)`, confirming that the suite is refused. The explicit timeouts are `proxy_connect_timeout 5s`, `proxy_read_timeout 30s`, `proxy_send_timeout 30s`, `client_body_timeout 10s`, `client_header_timeout 10s`, and `send_timeout 10s`. They limit time spent connecting to an unavailable upstream, waiting for upstream data, sending request data upstream, receiving slow client bodies or headers, and sending responses to slow clients. A timeout test can use a deliberately stalled request, for example `curl -sk --limit-rate 1b --max-time 12 -X POST https://localhost/rest/user/login -d @/dev/zero`.

OCSP stapling lets the server attach the certificate status response during the TLS handshake, saving the client a CA lookup and improving privacy and latency. I leave it off for this self-signed local certificate because there is no public CA responder or trusted chain to staple. For a public certificate I would enable it with a resolver and trusted issuer chain, then monitor refresh failures.

Certificate rotation runbook:

1. Obtain the replacement certificate and key, and check the certificate dates, subject, SANs, chain, and key match.
2. Copy them to versioned files with permissions readable by Nginx.
3. Atomically update the `localhost.crt` and `localhost.key` symlinks or bind-mounted files.
4. Run `nginx -t` inside the proxy container.
5. Reload Nginx with `nginx -s reload`; keep the previous pair for rollback.
6. Verify the live certificate with `openssl s_client -connect localhost:443 -servername localhost -showcerts` and verify HTTPS requests with `curl -skI https://localhost`.
7. Record the serial and expiry, then remove the old pair after the rollback window.

An IP-based limit can be bypassed with a botnet or distributed cloud workers, and shared NAT can make many attackers appear as one address. I would add identity- or account-based limits, a trusted edge with real-client IP handling, reputation or bot controls, and an application-level lockout/backoff policy.

## Bonus

The WAF runs as a separate `owasp/modsecurity-crs:nginx` service on port 8443, with CRS in blocking mode and the Juice Shop service exposed only through the proxy services. The comparison request was:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' "https://localhost/rest/products/search?q=1%27%20OR%20%271%27=%271"
curl -sk -o /dev/null -w '%{http_code}\n' "https://localhost:8443/rest/products/search?q=1%27%20OR%20%271%27=%271"
```

The plain proxy forwards the request with status **200**. The WAF returns **403**. The CRS log records rule **942100**, `SQL Injection Attack Detected via libinjection`, which checks request arguments for SQL injection syntax using libinjection. Rule 949110 then blocks after the inbound anomaly score reaches the threshold.

I tested a legitimate request to `/rest/products/search?q=apple`; it returned successfully, so I found no false positive in this small check. In production I would begin in detection-only mode, collect rule matches and application-owner feedback, and tune exclusions narrowly. I would canary the WAF for a small percentage of traffic, monitor false positives and latency, and promote rules to blocking mode in stages. Every exclusion would be tied to a route and parameter with an expiry and regression test.
