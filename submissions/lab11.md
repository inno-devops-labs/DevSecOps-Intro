# Lab 11 — Edge Hardening with a Reverse Proxy

## Task 1 — TLS and headers

A request to `http://localhost/` returned **308 Permanent Redirect** with `Location: https://localhost/`. I chose 308 because it permanently redirects the request while preserving its HTTP method and body.

### TLS protocols and cipher suite

The TLS 1.3 connection negotiated:

| Parameter | Result |
|---|---|
| Protocol | TLSv1.3 |
| Cipher suite | TLS_AES_256_GCM_SHA384 |

The protocol scan reported:

| Protocol | Server result |
|---|---|
| SSLv2 | Not offered |
| SSLv3 | Not offered |
| TLS 1.0 | Not offered |
| TLS 1.1 | Not offered |
| TLS 1.2 | Offered |
| TLS 1.3 | Offered |

The Nginx configuration allows only TLS 1.2 and TLS 1.3. The scanner also reported ALPN support for `h2` and `http/1.1`.


### Security headers

The HTTPS response contained all six required headers:

| Header | Returned value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), geolocation=(), microphone=()` |
| `Content-Security-Policy-Report-Only` | `default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'` |

The Content Security Policy is in report-only mode because Juice Shop may rely on inline scripts, `eval`, or resources that this policy would block. Enforcing it immediately could break application scripts or other features. I would first collect CSP violation reports while exercising the application, review which sources are required, and remove unnecessary allowances. I would then enforce a tested policy gradually, monitor application errors, and keep a rollback path.

## Task 2 — Availability controls


The login endpoint is limited to **10 requests per minute per client IP**, with a **burst of 5** and `nodelay`. Requests over the limit receive HTTP **429**. A 14-request test returned six 401 responses from Juice Shop followed by eight 429 responses from Nginx:

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

The limit applies specifically to `/rest/user/login`, not to the whole site. The configuration uses the `login:10m` zone and sets `limit_req_status` to 429.



### Per-client connection limit and TLS 1.3 suites\n\nNginx defines the `conn_per_ip` shared-memory zone using `$binary_remote_addr` and allows up to **20 concurrent connections per client address** in the HTTPS server.

TLS 1.3 is restricted to these AES-GCM cipher suites:

```nginx
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

I offered `TLS_CHACHA20_POLY1305_SHA256` using `openssl s_client` and observed an alert/failure, confirming that a suite outside the configured list is refused:

```bash
echo | openssl s_client -connect localhost:443 -tls1_3 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 \
  | grep -icE 'alert|failure'
```

### Timeouts

| Timeout | Value | What it limits |
|---|---:|---|
| `proxy_connect_timeout` | 5s | Time allowed to establish a connection to Juice Shop |
| `proxy_read_timeout` | 30s | Maximum gap while waiting for the upstream to send data |
| `proxy_send_timeout` | 30s | Maximum gap while sending a request to the upstream |

To verify that the read timeout fires, I paused Juice Shop and requested its application version through Nginx:

```bash
docker pause lab11-juice-1

curl -sk --max-time 35 -o /dev/null \
  -w 'HTTP %{http_code}; total=%{time_total}s\n' \
  https://localhost/rest/admin/application-version

docker unpause lab11-juice-1
```

Nginx returned **HTTP 504** after approximately **30.06 seconds**. I then unpaused the Juice Shop container.

### OCSP stapling

OCSP stapling lets the server include a recent certificate-status response in the TLS handshake, so clients do not each need to contact the certificate authority to check revocation. This can reduce lookup latency and avoid revealing the client’s destination to the CA. I disabled stapling for this lab because the certificate is self-signed and has no CA-issued OCSP responder. With a publicly trusted certificate, I would configure the issuer chain and a resolver, enable stapling and verification, and check that the server provides a valid stapled response.

### Certificate rotation runbook

1. Obtain or generate the replacement certificate and private key, using the expected filenames and permissions that allow Nginx to read them.
2. Before replacing the live files, check the certificate’s validity dates and subject/SAN, and verify that the private key matches the certificate.
3. Stage the new files, then replace both files in the mounted certificate directory. Do not reload Nginx between replacing the certificate and the key.
4. Validate the configuration with `docker compose -f labs/lab11/docker-compose.yml exec nginx nginx -t`. If it succeeds, gracefully reload Nginx with `docker compose -f labs/lab11/docker-compose.yml exec nginx nginx -s reload`. Keep the previous certificate and key available for rollback.
5. Verify the certificate served by a fresh TLS connection, confirm that the application still responds over HTTPS, and check the Nginx error log.

For example, inspect the certificate served by Nginx with:

```bash
echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 -subject -dates
```

A graceful Nginx reload lets existing connections finish on the old workers while new workers serve requests with the replacement certificate.


### Limits of IP-based rate limiting

An attacker can distribute requests across many source addresses using a botnet or rotating proxy pool. An attacker with a large IPv6 address range may also rotate source addresses if the limit treats every address as a separate client. I would use carefully configured client-address handling and consider appropriate IPv6 aggregation at this layer. Above the proxy, I would add account-based throttling, progressive delays or MFA, and centralized bot detection. Forwarded-address headers should only be trusted from known proxy ranges.

## Bonus — WAF with OWASP CRS

### request results

I sent the same SQL injection probe through the plain reverse proxy and the WAF:

```text
GET /rest/products/search?q=' OR 1=1--
Plain proxy: HTTP 500
WAF:         HTTP 403
```

The plain proxy forwarded the request to Juice Shop, which returned 500. This status alone does not show that the probe succeeded; it indicates that the application returned an error. The WAF denied the request before forwarding it to the application.

The requests were made with:

```bash
curl -sk -o /dev/null -w 'plain proxy: %{http_code}\n' \
  'https://localhost/rest/products/search?q=%27%20OR%201%3D1--'

curl -s -o /dev/null -w 'WAF: %{http_code}\n' \
  'http://localhost:8081/rest/products/search?q=%27%20OR%201%3D1--'
```

### CRS rule and normal-request check

The WAF log reported rule **942100**, “SQL Injection Attack Detected via libinjection,” for the value in `ARGS:q`. The rule detected the SQL injection pattern. Rule **949110** then enforced the inbound anomaly threshold: the request’s total score was 5, meeting the configured blocking threshold, so ModSecurity returned 403.

I also sent a normal product search through the WAF:

```text
GET /rest/products/search?q=apple
WAF: HTTP 200
```

The check was performed with:

```bash
curl -s -o /dev/null -w 'WAF normal request: %{http_code}\n' \
  'http://localhost:8081/rest/products/search?q=apple'
```

This legitimate request was not blocked, so I found no false positive in this check. This was a limited test of one normal request, not proof that the WAF has no false positives across the application.


### Production rollout plan\n\nI would not begin a production rollout in blocking mode. First, I would deploy the WAF in detection-only mode in staging, followed by a monitored observation period with representative production traffic. I would review alerts against normal application behavior, tune exclusions narrowly, and run functional and security regression tests. After review, I would enable blocking gradually for a canary or selected routes, monitor blocks and application errors, and keep a documented rollback path.