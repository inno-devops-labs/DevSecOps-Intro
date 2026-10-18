# Lab 11 — Edge hardening with Nginx and OWASP CRS

Executed on **2026-10-18** using Docker Desktop on macOS arm64, Juice Shop **v20.0.0**, Nginx **1.30.6**, ModSecurity **3.0.17**, and CRS **4.30.0**. Tasks 1, 2 and the WAF bonus were exercised against running containers. The application publishes no host port; the plain proxy listens on 80/443 and the comparison WAF on loopback port 8081.

Configuration: [`nginx.conf`](../labs/lab11/reverse-proxy/nginx.conf), [`WAF override`](../labs/lab11/waf/docker-compose.override.yml). Reproduce from the repository root:

```bash
mkdir -p labs/lab11/reverse-proxy/certs labs/lab11/logs
openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
  -keyout labs/lab11/reverse-proxy/certs/localhost.key \
  -out labs/lab11/reverse-proxy/certs/localhost.crt \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
chmod 644 labs/lab11/reverse-proxy/certs/localhost.*
docker compose -f labs/lab11/docker-compose.yml \
  -f labs/lab11/waf/docker-compose.override.yml up -d
# Wait for application-version to return HTTP 200, not merely a successful TCP connection.
curl -fk https://localhost/rest/admin/application-version
python3 labs/lab11/scripts/verify.py
```

The verifier waits 36 seconds to drain the login burst before measuring it. It captures command output under `labs/lab11/results/` and asserts the control outcomes. Self-signed certificate warnings are expected; `-k` is only for this local lab.

## Task 1

### Redirect, protocols and cipher

```console
$ curl -sI 'http://localhost/a?b=c'
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/a?b=c

$ openssl s_client -connect localhost:443 -servername localhost -tls1_3 -brief </dev/null
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Verification error: self-signed certificate
```

**308** is permanent and preserves the method and body on redirects, unlike clients' historical POST-to-GET handling of 301. Clients should submit credentials to HTTPS directly, because a redirect cannot undo the exposure of an initial plaintext request.

The scanner runs on the Compose network against **the same nginx listener**, avoiding Docker Desktop's host-network differences:

```bash
docker run --rm --network lab11_default drwetter/testssl.sh:3.2 \
  --protocols --color 0 https://nginx:443
```

Captured using **testssl.sh 3.2.4**, with its bundled OpenSSL 1.0.2-bad and socket probes:

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

### Six response headers

`curl -skI https://localhost` returned HTTP 200 with:

```http
strict-transport-security: max-age=31536000
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Every directive uses `always`; the verifier also checks all six on a real **429** response. HSTS is sent over HTTPS only; I removed the starter's preload/subdomain commitments because those require a real domain and a subdomain audit. `X-Real-IP` and `X-Forwarded-For` carry the peer address, replacing untrusted incoming forwarding claims at this first trusted hop. On Docker Desktop the proxy sees the NAT gateway address, so multiple local clients share a limit bucket; a production load balancer requires a narrowly scoped trusted real-IP configuration.

### CSP migration

The policy is Report-Only, so it observes violations without blocking resources. Enforcing it today can block Juice Shop features that fetch third-party images, fonts or other resources outside `self`/`data:`, while the existing `unsafe-inline` and `unsafe-eval` allowances would still leave substantial script execution risk. I would first add a report collector (`report-to`/`report-uri`; none is configured in this local exercise), exercise full browser journeys and review violations, then fix resource origins and move scripts toward nonces/hashes. After staging and a small production canary, enable enforcement and monitor regressions; header presence alone does not establish browser compatibility.

## Task 2

### Login rate and connection limits

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=clients:10m;
limit_conn_status 429;
# HTTPS server:
limit_conn clients 20;
# Only location = /rest/user/login:
limit_req zone=login burst=5 nodelay;
```

Fourteen consecutive POSTs with `{"email":"a@b.c","password":"x"}` returned:

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

The bucket admits one immediate request plus five burst requests, replenishing at **10/minute** (one every six seconds). Other paths have no `limit_req`; application-version still returned **200** while login was limited. The connection limit is **20 active requests per peer**; nginx counts connections after reading the complete header, and HTTP/2 concurrent requests count separately, so this is not a cap on all open TCP sockets.

### Cipher policy and negative test

TLS 1.2 uses the starter's explicit ECDHE AEAD list (AES-GCM and ChaCha20-Poly1305); TLS 1.3 is independently restricted to:

```nginx
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
ssl_session_tickets off;
```

```console
$ openssl s_client -connect localhost:443 -servername localhost -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256 </dev/null
... tls alert handshake failure ... SSL alert number 40
SSL handshake has read 7 bytes and written 1465 bytes
New, (NONE), Cipher is (NONE)
```

The seven bytes received and server alert demonstrate a remote refusal, rather than a local `no cipher match` error. The allowed-suite handshake above is the positive control. `ssl_ciphers` cannot set TLS 1.3 suites; see [nginx's SSL module reference](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_conf_command).

### Timeouts and observed expiry

| Setting | Value | Protects against |
|---|---:|---|
| `proxy_connect_timeout` | 5s | Waiting too long to establish an upstream connection |
| `proxy_read_timeout` | 30s | An upstream that stops supplying response data between reads |
| `proxy_send_timeout` | 30s | An upstream that stops accepting request data between writes |
| `client_header_timeout` | 10s | Clients that never finish request headers |
| `client_body_timeout` | 10s | Clients that stop sending request body data between reads |
| `send_timeout` | 10s | Clients that stop consuming the response between writes |
| `keepalive_timeout` | 10s | Idle reusable client connections |

These are mostly inactivity limits, not a total request deadline. The verifier sends a TLS POST declaring a 100-byte body, sends only `{`, and waits; use `python3 labs/lab11/scripts/verify.py` to repeat it. An initial isolated run closed after **10.020 seconds**; nginx's access log recorded:

```text
"POST /rest/user/login HTTP/1.1" 408 0 "-" "-" rt=10.014 uct=- urt=-
```

Nginx closed this incomplete-body connection without transmitting an HTTP response; the **408** is server-log evidence, not a claimed client-visible status. The reproducible verifier uses `/rest/products/search` for this test so login throttling cannot intercept it. Only the body timeout was experimentally triggered; the three upstream timeout values were configuration-validated.

### OCSP

Stapling lets the server attach a CA-signed revocation status so a supporting client can avoid a separate OCSP responder request and the associated latency/privacy exposure. It stays **off** here because this self-signed localhost certificate has no CA OCSP responder. For a publicly trusted certificate I would first check whether its issuer offers OCSP, configure chain verification and DNS if appropriate, and monitor staple freshness.

### Certificate rotation runbook

1. Issue the replacement before expiry; store the new key, leaf and chain in a versioned directory inside the mounted `certs/` directory. Check SANs, dates and chain, and compare SHA-256 hashes of the certificate and private key's public-key DER encodings to confirm the pair matches.
2. First migrate the fixed `localhost.crt` and `localhost.key` paths to symlinks through a single `current/` directory, initially pointing to the existing pair. Run `nginx -t` and gracefully reload; verify service before scheduling rotation. Preserve the existing readable permissions required by this lab container, restricting access to the containing host directory.
3. Start a continuous fresh-connection HTTPS probe, recording failures and HTTP statuses. Create a new `current.next` symlink to the replacement version, then atomically rename it over `current` **within the same mounted directory**. This switches the certificate and key together.
4. Run `docker compose -f labs/lab11/docker-compose.yml exec -T nginx nginx -t`. On failure restore the previous symlink and do not reload. On success run the same command with `nginx -s reload`; existing workers finish their requests while new workers load the new pair.
5. On fresh connections, retrieve the served certificate using `openssl s_client -connect localhost:443 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -serial -dates -fingerprint -sha256`. Compare its fingerprint/serial with the replacement on disk and verify HTTP success and TLS policy. For real certificates, verify trust and hostname without `-k`.
6. Confirm zero failures in the continuous probe and no reload errors; retain the previous version for rollback. If necessary atomically restore `current`, validate and gracefully reload again. Record the rotation and monitor expiry.

This is an operational runbook; certificate rotation itself was not executed. Zero downtime relies on a valid replacement, graceful reload and successful continuous verification, not on merely copying files.

### Rate-limit bypasses

A botnet or rotating residential proxies distributes attempts over many source addresses, while IPv6 address rotation can cheaply create new per-address buckets. An attacker can also stay below the per-IP rate while spreading credential attacks across time and accounts. Add account/device-aware attempt budgets, progressive challenges and MFA above nginx, plus reputation and aggregate anomaly detection at the edge; trust forwarded client addresses only from known ingress proxies.

## Bonus

The WAF is in the same Compose project and forwards to `http://juice:3000`; `MODSEC_RULE_ENGINE=On`, paranoia **1**, inbound anomaly threshold **5**. Its HTTP endpoint on `127.0.0.1:8081` exists for the local comparison. A production deployment should terminate TLS before inspection and place the hardened edge controls on the WAF path too.

Identical payload, URL-encoded with `curl -G --data-urlencode`:

```bash
curl -skG -o /dev/null -w '%{http_code}\n' \
  --data-urlencode "q=' OR 1=1--" https://localhost/rest/products/search
# 500
curl -sG -o /dev/null -w '%{http_code}\n' \
  --data-urlencode "q=' OR 1=1--" http://localhost:8081/rest/products/search
# 403
```

**500** on the plain proxy means the request reached the vulnerable application, which errored; it is not an edge block. The WAF audit transaction recorded:

```json
{
  "is_interrupted": true,
  "http_code": 403,
  "messages": [
    {"ruleId": "942100", "message": "SQL Injection Attack Detected via libinjection",
     "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"},
    {"ruleId": "949110", "message": "Inbound Anomaly Score Exceeded (Total Score: 5)"}
  ]
}
```

This is an excerpt of the real log, shortened to the relevant fields. **942100** uses libinjection to identify SQL-injection token patterns; **949110** blocks once the accumulated score reaches the configured threshold. Raw evidence is in `labs/lab11/results/waf.log`.

### False-positive hunt

| Search query | Plain | WAF | Interpretation |
|---|---:|---:|---|
| `apple` | 200 | 200 | Allowed |
| `orange juice` | 200 | 200 | Allowed |
| `O'Reilly` | 500 | 500 | Application error on both paths, not a WAF false positive |
| `1 < 2` | 200 | 200 | Allowed |
| `select a gift` | 200 | 200 | Allowed |
| `union of fruits` | 200 | 200 | Allowed |
| `<script>alert(1)</script>` | 200 | 403 | XSS-pattern positive control |

No WAF false positive was found in the six benign searches; this small sample does not establish full application compatibility. In a code/documentation search application, searching literal script examples could itself be legitimate, requiring context-specific tuning.

For a real rollout, begin with `DetectionOnly` and paranoia 1 while replaying representative authenticated and anonymous journeys and reviewing audit events with application owners. Create narrow exclusions for a specific parameter, endpoint and rule, then retain regression cases for each exception. Canary blocking with the tuned rules and a monitored rollback switch before expanding coverage. Track false positives, latency, errors and bypass attempts, and increase paranoia only after the current level is stable. The [official CRS container documentation](https://github.com/coreruleset/modsecurity-crs-docker) describes the rule-engine modes and environment settings used here.

## Validation and cleanup

`nginx -t` succeeded; the automated verifier checks redirect preservation, TLS positive/negative handshakes, scanner protocol results, six headers on 200 and 429, login-only throttling, WAF SQLi blocking and an observed body timeout. Certificates and nginx logs remain ignored. Remove only this stack when finished:

```bash
docker compose -f labs/lab11/docker-compose.yml \
  -f labs/lab11/waf/docker-compose.override.yml down -v
```
