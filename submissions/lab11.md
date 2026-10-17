# Lab 11 — Edge Hardening with a Reverse Proxy

## Environment and reproducibility

| Item | Version or configuration |
|---|---|
| Run date | 17 October 2026 |
| Host | Windows, PowerShell, Docker Desktop with Linux containers |
| Docker / Compose | 29.2.1 / v5.1.0 |
| Application | Juice Shop v20.0.0 |
| Plain proxy | Nginx 1.30.5, stable-alpine image |
| WAF | ModSecurity 3.0.16, Nginx connector 1.0.4, OWASP CRS 4.29.0 |
| TLS client | OpenSSL 3.2.1 from Git for Windows |
| Protocol scanner | testssl.sh 3.2.4, image tag `3.2`, bundled legacy-capable OpenSSL |
| Published ports | `127.0.0.1:80`, `127.0.0.1:443`, WAF comparison at `127.0.0.1:8081` |
| Certificate | Local self-signed RSA-2048, 30 days, SANs `localhost` and `127.0.0.1` |

## Task 1

**Redirect status code:** `308 Permanent Redirect`. I selected 308 instead of 301 because it preserves both the HTTP method and request body during redirection. A 301 redirect may cause some clients, particularly older implementations, to change a POST request into a GET request. Since this proxy redirects all HTTP requests, including login submissions such as `POST /rest/user/login`, using 308 avoids potentially changing the semantics of these requests.

**TLS 1.3 protocol and cipher suite negotiated** (`echo | openssl s_client -connect localhost:443 -tls1_3`, LibreSSL output — no `-brief` support, so the results were taken from the complete handshake output):

```text
Protocol  : TLSv1.3
Cipher    : AEAD-AES256-GCM-SHA384
```

**Protocol table from a real scanner** (`docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 https://localhost`):

```text
 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

The server supports only TLS 1.2 and TLS 1.3. SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are unavailable. These results were verified using an independent scanner with its own TLS implementation, rather than relying on the protocols supported by the locally installed OpenSSL.

**All six headers, as returned by the server** (`curl -skI https://localhost`):

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

**What would break if `Content-Security-Policy-Report-Only` were enforced today.** Rather than relying on assumptions, I temporarily changed the header to `Content-Security-Policy`, enabled enforcement, reloaded Nginx, and examined Juice Shop's HTML using `curl`.

The application's index page contains an inline `@font-face` declaration that loads the VT323 retro display font, used in the main headings, from `https://fonts.gstatic.com/...woff2`. It also preconnects to `https://fonts.googleapis.com`. Neither domain is permitted by the current policy. Because `font-src` is not explicitly defined, font loading falls back to `default-src 'self'`; external fonts are therefore blocked. The main visible consequence would be that the headings use a generic system font instead of VT323. This would affect the appearance rather than the application's fundamental functionality.

After confirming the behavior, I immediately restored the report-only header. Before enforcing the policy permanently, I would collect violation reports during a representative period of real traffic. A reporting endpoint using `report-uri` or `report-to` must first be configured because neither is currently present. Legitimate violations should then be addressed by hosting the font locally or explicitly allowing `fonts.googleapis.com` and `fonts.gstatic.com` in the appropriate `style-src` and `font-src` directives. Enforcement should begin only after testing the application's complete UI and confirming that the reports no longer reveal new legitimate violations.

## Task 2

**Status code sequence** (`for i in $(seq 1 14); do curl ... POST /rest/user/login; done`):

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

**Configured rate:** `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;` with `limit_req zone=login burst=5 nodelay;` inside `location = /rest/user/login`, and `limit_req_status 429;` configured globally.

With `nodelay`, requests within the permitted burst can be processed immediately instead of being delayed. The bucket initially contains one token, and the burst allowance is five additional requests. Consequently, the first six rapid requests were accepted by the rate limiter, while the remaining eight requests, sent within the same second, received HTTP 429 responses. This matches the observed sequence.

**Cipher configuration:**

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";

ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

The `ssl_ciphers` directive specifies the permitted TLS 1.2 cipher suites and remains unchanged from the initial configuration. I added `ssl_conf_command Ciphersuites` to control TLS 1.3 separately, allowing only the two AES-GCM suites and excluding `TLS_CHACHA20_POLY1305_SHA256`.

**Proof a suite outside the list is refused.** Since LibreSSL's `s_client` does not support the `-ciphersuites` option, I tested the restriction using OpenSSL 3.x inside Docker:

```text
$ docker run --rm --network host alpine/openssl s_client -connect localhost:443 -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256

...

New, (NONE), Cipher is (NONE)
Protocol: TLSv1.3
```

The result `Cipher is (NONE)` demonstrates that the handshake could not negotiate a cipher suite. The client offered only ChaCha20-Poly1305, whereas the server accepts only AES-GCM for TLS 1.3.

As a control test, I repeated the command with an allowed suite:

```text
$ docker run --rm --network host alpine/openssl s_client -connect localhost:443 -tls1_3 \
    -ciphersuites TLS_AES_256_GCM_SHA384

New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

This handshake succeeded, confirming that the server accepts the configured suite while rejecting the excluded one.

**Timeout values, and what each protects against:**

| Directive | Value | Protects against |
|---|---|---|
| `client_body_timeout` | 10s | Clients that send request bodies extremely slowly, potentially one byte at a time, and keep connections occupied indefinitely. |
| `client_header_timeout` | 10s | Slow delivery of HTTP request headers, which can otherwise tie up connections. |
| `proxy_connect_timeout` | 5s | Unreachable upstream services or stalled TCP connection attempts, limiting how long Nginx waits before reporting a failure. |
| `proxy_read_timeout` / `proxy_send_timeout` | 30s each | Upstream servers that stop sending data during a response, or delays while Nginx sends data to a client. These limits help prevent connections from remaining occupied indefinitely. |
| `keepalive_timeout` | 10s | Idle persistent connections that remain open without sending another request and unnecessarily consume connection resources. |

**Command proving a timeout actually fires.** To verify the behavior rather than merely confirm the configuration, I used Python to open a raw TLS connection, send complete request headers declaring `Content-Length: 100`, transmit only 8 bytes of the body, and then wait.

```text
Sent headers + partial body only (client_body_timeout=10s configured)
Connection closed/response received after 10.0s
Bytes received: (connection closed with no response body)
```

Nginx closed the connection after 10.0 seconds, matching the configured `client_body_timeout 10s`. This demonstrates that the timeout was triggered during an actual connection rather than simply appearing in the configuration.

**OCSP stapling.** OCSP stapling allows a server to obtain and cache a certificate's revocation status from its issuing CA, then provide that status to clients during the TLS handshake. This can eliminate the need for a separate client request to the CA's OCSP responder, reducing handshake overhead and limiting the information exposed to the CA about the websites a client visits.

I deliberately left the feature **disabled** using `ssl_stapling off;`. The current certificate is self-signed, with no issuing CA providing a revocation response that the server could staple. Enabling OCSP stapling in this situation would not provide a meaningful revocation check and could introduce unnecessary resolver requirements or startup delays. It should be reconsidered when the certificate is replaced with one issued by a CA that supports OCSP. That replacement is the appropriate point to revisit this setting in the certificate rotation runbook.

**Cert rotation runbook, proven with zero failed requests:**

1. Generate or obtain a replacement certificate and private key using a command such as `openssl req -x509 -newkey rsa:2048 ... -out localhost-new.crt -keyout localhost-new.key`.
2. Replace the files mounted into Nginx on the host: `labs/lab11/reverse-proxy/certs/localhost.crt` and `.key`. The container itself does not need to be recreated.
3. Run `docker exec lab11-nginx-1 nginx -s reload`. This sends `SIGHUP` to Nginx, prompting it to reload the configuration and open the updated certificate and key files in new worker processes. Existing workers can finish handling in-flight connections before exiting, avoiding interruption to ongoing requests.
4. Verify the replacement by running `echo | openssl s_client -connect localhost:443 -tls1_3 | openssl x509 -noout -serial` and checking that the displayed serial number matches the new certificate.

I tested this procedure while sending 60 consecutive requests, one every 0.1 seconds, to `https://localhost/`. Approximately 1.5 seconds into the test, I replaced the certificate files and reloaded Nginx.

```text
=== results ===

 60 200
```

All 60 requests returned HTTP 200, with no failures during the rotation. I subsequently verified that Nginx was presenting the replacement certificate:

```text
$ echo | openssl s_client -connect localhost:443 -tls1_3 | openssl x509 -noout -serial

serial=B330D8A7A2DEC152       # matches the newly generated cert, not the original
```

The serial number matched the new certificate rather than the original one.

**Rate limit bypass — per client address.** The current `limit_req_zone $binary_remote_addr ...` configuration maintains separate rate-limit buckets based on source IP addresses. An attacker could circumvent this restriction in at least two ways.

1. **A botnet or a rotating proxy pool:** Requests can be distributed across numerous source IP addresses. Because each address has its own bucket, no individual address necessarily exceeds the limit, even when the combined request rate against `/rest/user/login` is high.
2. **IPv6 address rotation on a single host:** An attacker with access to an IPv6 `/64` or larger allocation may send requests from different addresses within that range. Since `$binary_remote_addr` treats distinct addresses as separate keys, this can bypass the per-address restriction without requiring a botnet.

To strengthen the configuration, I would introduce another `limit_req_zone` keyed to a less easily rotated identifier. For IPv6, one option is to normalize addresses to their `/64` network prefix using a `map` before using the result as the zone key. At the application layer, I would also implement account-based throttling or progressive delays on the login endpoint, keyed to the `email` field in the request body. Nginx alone cannot reliably implement this body-based control in the current setup. Application-level protection would help restrict credential-stuffing attempts against a particular account, even when requests originate from many different IP addresses.

## Bonus

**The same request through both paths:**

```text
$ curl -sk -o /dev/null -w "%{http_code}\n" "https://localhost/rest/products/search?q=%27%20OR%201%3D1--"

500    # plain nginx proxy (443) — forwarded straight to Juice Shop, which crashed on it


$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8443/rest/products/search?q=%27%20OR%201%3D1--"

403    # WAF path (8443) — blocked before it ever reached the app
```

The request produced HTTP 500 when it passed through the standard Nginx proxy on port 443, reaching Juice Shop directly. Through the WAF path on port 8443, the same malicious input was rejected with HTTP 403 before reaching the application.

**CRS rule that fired, from the WAF's JSON log:**

```json
{"message":"SQL Injection Attack Detected via libinjection","details":{
  "match":"detected SQLi using libinjection.","reference":"v28,10",
  "ruleId":"942100","file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
  "data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
  "tags":["attack-sqli","paranoia-level/1","OWASP_CRS"]}}
{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110",
  "file":"/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"}}
```

**Rule 942100** is defined in `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`. It uses the `libinjection` library to analyze request arguments for SQL injection patterns. Rather than simply searching for suspicious keywords, the library parses the supplied input as a potential SQL fragment. In this case, it identified the classic tautology `' OR 1=1--` in the `q` parameter.

Rule 949110 performs the final anomaly-score evaluation and determines whether the transaction should be blocked. Rule 942100 contributed 5 points to the score, reaching the default blocking threshold. Consequently, rule 949110 triggered the HTTP 403 response.

**False-positive hunt.** I also tested a search query containing an apostrophe, which could reasonably appear in a legitimate user's input, such as the name "O'Brien":

```text
$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8443/rest/products/search?q=O%27Brien"

500
```

Initially, the non-200 status appeared to indicate a possible false positive. However, the WAF log showed `"is_interrupted":false` and `"messages":[]`, confirming that no CRS rule had blocked the request. The request passed through to Juice Shop, where the application's own SQL handling caused the error.

The search endpoint concatenates the supplied query directly into a SQL statement. As a result, the apostrophe in "O'Brien" breaks the resulting query, producing `SQLITE_ERROR: near "Brien": syntax error`, which is visible in the application's error page.

Therefore, this test did not reveal a WAF false positive. Instead, it exposed a separate application vulnerability: the WAF correctly allowed the request, but Juice Shop failed to handle the input safely. This illustrates the distinction between a WAF blocking legitimate traffic and an application mishandling input that reaches it.

**Rollout plan.** Deploying CRS in blocking mode immediately, without first tuning it against the target application, risks disrupting legitimate functionality. Genuine false positives may only become apparent when real users or less common workflows encounter them, potentially leading operators to disable the WAF during an incident.

I would deploy the WAF in three stages:

1. **Detection-only:** Set `MODSEC_RULE_ENGINE: DetectionOnly` and monitor representative production traffic for at least one complete business cycle, with a minimum period of one week. This allows less frequent workflows and scheduled batch jobs to be observed without blocking requests.
2. **Triage the detection-only log:** Investigate every triggered rule associated with legitimate traffic. Apply narrowly targeted exclusions tied to the affected endpoint or parameter where appropriate, rather than disabling rules globally. If a reported issue is caused by unsafe application input handling rather than a genuine false positive, fix the application instead.
3. **Switch to blocking mode:** Enable request blocking after the detected issues have been reviewed and addressed. Begin with paranoia level 1 (`PARANOIA=1`), the least aggressive level in this configuration, and increase the level only after repeating the detection and triage process for each subsequent level.

This staged deployment helps maintain the security benefits of CRS while reducing the likelihood of disrupting legitimate application traffic.