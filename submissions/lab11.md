# Lab 11 — Edge Hardening with a Reverse Proxy

## Task 1

Port 80 returns a permanent HTTPS redirect with status `308`:

```text
$ curl -sI http://localhost | tee labs/lab11/results/http-redirect.txt | head -2
HTTP/1.1 308 Permanent Redirect
Server: nginx
```

`308` was used because it is permanent and preserves the original HTTP method and request body. That is safer than changing a non-GET request into a GET during a redirect.

A TLS 1.3 connection negotiated this protocol and cipher suite:

```text
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite' | tee labs/lab11/results/tls13.txt
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

The protocol scanner showed only TLS 1.2 and TLS 1.3 offered by the server:

```text
$ docker run --rm --network host instrumentisto/nmap -sV --script ssl-enum-ciphers -p 443 localhost | tee labs/lab11/results/protocols.txt
443/tcp open  ssl/http nginx
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|   TLSv1.3:
|     ciphers:
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (X25519MLKEM768) - A
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (X25519MLKEM768) - A
```

All six required security headers were returned by the proxy:

```text
$ curl -skI https://localhost | tee labs/lab11/results/headers.txt | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

`Content-Security-Policy-Report-Only` was used first because enforcing a strict CSP immediately can break Juice Shop browser flows, especially scripts, styles, and dynamic assets used by the single-page application. Report-only mode lets the browser surface violations without blocking the page. The safe process is to inspect violations in browser tooling, add a centralized CSP reporting endpoint when this becomes production work, adjust the policy until normal user flows are clean, then switch from report-only to enforcement. This avoids turning a security header into an availability problem.

## Task 2

The login endpoint has a specific rate limit, while the rest of the site is not rate-limited by that rule:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=addr:10m;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}

limit_conn addr 20;
```

The configured rate is `10r/m`, with `burst=5` and `nodelay`. The first requests reached Juice Shop and returned `401`; after the burst was consumed, Nginx returned `429`:

```text
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'; done | tee labs/lab11/results/rate-limit.txt; echo
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

TLS 1.3 cipher suites were restricted to AES-GCM with this configuration:

```nginx
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

A TLS 1.3 client restricted to `TLS_CHACHA20_POLY1305_SHA256` was refused:

```text
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | tee labs/lab11/results/chacha-refused.txt | grep -icE 'alert|failure|handshake failure|no ciphers available'
1
```

The proxy has explicit upstream timeouts:

```nginx
proxy_connect_timeout 5s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;
```

`proxy_connect_timeout` limits how long Nginx waits to connect to the upstream. `proxy_send_timeout` limits the allowed idle interval between successive writes while Nginx sends the request to the upstream. `proxy_read_timeout` limits the allowed idle interval between successive reads while Nginx receives the upstream response, which protects the edge from backend requests that hang.

A temporary test-only location used during validation had a `1ms` read timeout to prove a timeout firing:

```text
$ curl -sk -o /dev/null -w 'status=%{http_code} time=%{time_total}\n' https://localhost/timeout-proof | tee labs/lab11/results/timeout-proof.txt
status=504 time=0.016913
```

The Nginx log confirms the upstream read timeout:

```text
2026/10/13 13:01:03 [error] 23#23: *32 upstream timed out (110: Operation timed out) while reading response header from upstream, client: 172.20.0.1, server: _, request: "GET /timeout-proof HTTP/2.0", upstream: "http://172.20.0.2:3000/timeout-proof", host: "localhost"
```

OCSP stapling can save the client from contacting the certificate authority during certificate validation, which improves latency and privacy. It is not useful in this lab because the certificate is self-signed for localhost and has no public CA OCSP responder. In production, it should be enabled with a CA-issued certificate, a trusted chain, DNS resolver configuration, and monitoring for stapling failures.

Certificate rotation runbook for zero failed requests:

1. Obtain the new certificate and private key before the old certificate expires.
2. Validate the new certificate subject, SAN, expiration date, and key match offline.
3. Copy the new files into the mounted certificate directory under distinct versioned names with safe permissions.
4. Update the configuration so it references the new files, then run `nginx -t` to validate that exact configuration before reloading. The running workers continue using the previously loaded certificate.
5. Keep the old certificate and key in place rather than overwriting the live pair separately.
6. Start a continuous HTTPS curl loop before the reload and keep recording status codes throughout the change.
7. Gracefully reload Nginx and check the recorded status codes for failed requests.
8. Verify the live certificate with `openssl s_client -connect localhost:443 -servername localhost | openssl x509 -noout -dates -fingerprint`, comparing its fingerprint with the new certificate's fingerprint.
9. Keep the previous certificate, key, and configuration available for rollback until the new certificate and successful requests are confirmed.

A per-client-address rate limit can be bypassed by using many source IPs, such as proxies or a botnet. It can also be bypassed with low-and-slow attempts that stay below the threshold, or by rotating IPv6 addresses. At this layer, a WAF or CDN can add reputation and broader rate controls. Above this layer, account-based throttling, login risk scoring, MFA, and CAPTCHA can make the control harder to bypass.

## Bonus

The WAF runs in the same Compose project as Juice Shop, on a different published port from the plain reverse proxy. The Juice Shop container exposes port `3000` only inside the Docker network, so it is reachable from outside that network only through the proxy or the WAF. The recorded validation run showed:

```text
$ docker compose -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml ps | tee labs/lab11/results/compose-ps.txt
NAME            IMAGE                           SERVICE   STATUS                        PORTS
lab11-juice-1   bkimminich/juice-shop:v20.0.0   juice     Up 8 minutes                  3000/tcp
lab11-nginx-1   nginx:stable-alpine             nginx     Up 5 minutes                  0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
lab11-waf-1     owasp/modsecurity-crs:nginx     waf       Up About a minute (healthy)   0.0.0.0:8080->8080/tcp
```

The final Compose override binds the proxy ports `80` and `443` and the WAF port `8080` to `127.0.0.1`, keeping access local to the host. It uses `!override` to replace the base proxy port mappings and requires Docker Compose 2.24.4 or later.

The same SQL-injection-style request was sent through the plain proxy and through the WAF:

```text
$ payload='%27%20OR%201%3D1--'
$ curl -sk -o /dev/null -w 'plain=%{http_code}\n' "https://localhost/rest/products/search?q=${payload}"
plain=500
$ curl -s -o /dev/null -w 'waf=%{http_code}\n' "http://localhost:8080/rest/products/search?q=${payload}"
waf=403
```

The WAF log shows CRS rule `942100`, which checks for SQL injection using libinjection. Rule `949110` then blocked the request because the inbound anomaly score reached the blocking threshold:

```text
"message":"SQL Injection Attack Detected via libinjection","details":{"ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--"}
"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"}
```

A false-positive check was run with the home page and a benign product search. Both were allowed, so no false positive was found in these checks:

```text
$ curl -s -o /dev/null -w 'home=%{http_code}\n' "http://localhost:8080/"
home=200
$ curl -s -o /dev/null -w 'benign_search=%{http_code}\n' "http://localhost:8080/rest/products/search?q=apple"
benign_search=200
```

CRS blocking mode should not be enabled in front of a real application on day one. The safer rollout is to start in detection mode, collect logs from normal traffic, and tune false positives for the application's real behavior. After that, blocking can be enabled first for high-confidence rules and lower-risk paths. The rollout also needs monitoring, an exception process, and a rollback plan so the WAF does not become an availability risk.
