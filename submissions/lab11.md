# Lab 11 — Edge Hardening with a Reverse Proxy

Author: Irina (`1r444444`). Executed 18 October 2026, Europe/Moscow.

Environment: macOS ARM64, Docker Desktop engine 28.4.0, Compose 2.39.4,
Juice Shop v20.0.0, Nginx 1.30.6, ModSecurity 3.0.17 / connector 1.0.4,
OWASP CRS 4.30.0, Homebrew OpenSSL 3.6.4 and testssl.sh 3.2.4.
Exact pulled image digests are recorded in [images.txt](../labs/lab11/results/images.txt).
The branch starts from upstream `c6e3c2d`; other laboratories are not included.

Reproduce from repository root (Docker must be running; ports 80, 443 and 8081 available):

```bash
mkdir -p labs/lab11/reverse-proxy/certs labs/lab11/logs
openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
  -keyout labs/lab11/reverse-proxy/certs/localhost.key \
  -out labs/lab11/reverse-proxy/certs/localhost.crt \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 644 labs/lab11/reverse-proxy/certs/localhost.*
docker compose -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml up -d
# Wait for HTTP 200, not merely an established TLS connection:
until [ "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/rest/admin/application-version)" = 200 ]; do sleep 2; done
python3 labs/lab11/scripts/verify.py
python3 labs/lab11/scripts/rotate-test.py
```

`verify.py` uses Python's standard library and makes assertions against live responses.
It includes a 36-second quiet period to drain the login bucket and a real 10-second
timeout. Run without concurrent login traffic. The local self-signed certificate
explains `curl -k` and OpenSSL verification error 18. Keys, certificates and raw
logs are excluded from Git; the lab's readable key permissions are only for this
local demonstration. Only the proxies have published ports, bound to loopback.
Juice Shop has `expose: 3000`, with no host publication. Other local software
already owns host port 3000, so a curl to that port would not establish app isolation;
Compose configuration and container port bindings establish it instead.

## Task 1

### Permanent redirect

```text
POST http://localhost/test?x=1
HTTP 308
Location: https://localhost/test?x=1
```

308 preserves the request method and body, including login POSTs; 301 permits
clients to rewrite POST to GET. The server-level return applies to every HTTP
path and preserves path/query. Evidence: [redirect.json](../labs/lab11/results/redirect.json).
An initial HTTP request still travels unencrypted; clients should start on HTTPS.

### TLS negotiation and protocol enumeration

```bash
/opt/homebrew/opt/openssl@3/bin/openssl s_client -connect localhost:443 \
  -servername localhost -tls1_3 -brief </dev/null
# Linux/other hosts: use your OpenSSL 3 executable instead of the macOS path.
docker run --rm --platform linux/amd64 --network lab11_default \
  drwetter/testssl.sh:3.2 --protocols --color 0 https://nginx:443
```

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384

SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
NPN/SPDY   not offered
ALPN/HTTP2 h2, http/1.1 (offered)
```

Evidence: [tls13.txt](../labs/lab11/results/tls13.txt),
[protocols.txt](../labs/lab11/results/protocols.txt).
The scanner runs on the Compose network against the actual TLS listener, avoiding
Docker Desktop's host-network dependency. It carries a legacy-capable TLS stack;
local OpenSSL rejecting TLS 1.1 before connecting would not prove a server setting.

### Six response headers

As returned by HTTPS `/`:

```text
strict-transport-security: max-age=31536000
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

Every directive has `always`. The live checks assert all six headers on 200,
upstream 401, proxy-generated 413 and login-limit 429 responses.
Evidence: [headers.json](../labs/lab11/results/headers.json) and
[rate-limit.json](../labs/lab11/results/rate-limit.json).
The proxy forwards to `juice:3000` with `X-Real-IP` and `X-Forwarded-For` set to
`$remote_addr` and `X-Forwarded-Proto` to `$scheme`; it overwrites untrusted
forwarding input at this directly exposed edge. Docker Desktop presents its NAT
gateway as the client, so local callers share an address bucket. Upstream enforcing
CSP is preserved when present; the candidate edge policy is Report-Only.
HSTS omits preload and subdomain coverage because those require a domain audit.

### Why Report-Only first

Enforcing this candidate today would block Juice Shop's inline scripts/styles,
the inline stylesheet `onload` handler and external Google fonts, all visible in
the served index HTML. That could disrupt cookie-consent initialization, stylesheet
activation and typography; this is source inspection, not a claimed browser test.
First configure a reporting collector and `report-uri`/`report-to` (the current
policy has no collector), exercise representative workflows, then replace legitimate
inline code with external files or hashes/nonces and explicitly allow or self-host
required assets. Canary the validated policy in enforcement mode, monitor violations
and application errors, and keep an immediate rollback to Report-Only.

## Task 2

### Login rate and per-address connection limits

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;
limit_conn_zone $binary_remote_addr zone=per_client:10m;
limit_conn per_client 20;
limit_conn_status 429;

location ~* ^/rest/user/login/?$ {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

14 rapid invalid logins, after draining the bucket:

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

The initial request plus five excess requests reach Juice Shop immediately and
receive 401; the remaining eight receive 429. Only login is request-rate-limited:
14 consecutive application-version requests still return 200. The case-insensitive
regex also covers `/REST/USER/LOGIN` and `/rest/user/login/`, which Express accepts;
both return 429 after the canonical path exhausts the same bucket. The connection
check holds 20 requests with complete headers and incomplete bodies, then confirms
the 21st request returns 429. Idle sockets alone do not count towards `limit_conn`;
HTTP/2 concurrent requests are counted separately.
Evidence: [rate-limit.json](../labs/lab11/results/rate-limit.json),
[connections.json](../labs/lab11/results/connections.json).

### Cipher configuration and actual rejection

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
ssl_session_tickets off;
```

TLS 1.2 retains the starter's ECDHE/AEAD list. The separate `Ciphersuites` directive
restricts TLS 1.3 to AES-GCM; `ssl_ciphers` cannot do that.

```bash
/opt/homebrew/opt/openssl@3/bin/openssl s_client -connect localhost:443 \
  -servername localhost -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 </dev/null
```

The server sends `sslv3 alert handshake failure`, alert number 40; the client exits
1 and reports `no peer certificate available`. This is a remote handshake refusal,
not the local `no cipher match` error from using the wrong `-cipher` option.
The successful AES-256 handshake above is the positive control.
Evidence: [rejected-cipher.txt](../labs/lab11/results/rejected-cipher.txt).

### Timeouts and a timeout firing

| Directive | Value | Purpose |
|---|---|---|
| `proxy_connect_timeout` | 5s | Bound waiting for an upstream TCP connection. |
| `proxy_send_timeout` | 30s | Bound inactivity between writes of the request to an upstream that stops reading. |
| `proxy_read_timeout` | 30s | Bound inactivity between reads from an upstream that stops responding. |
| `client_header_timeout` | 10s | Bound time to receive complete client request headers. |
| `client_body_timeout` | 10s | Bound inactivity between reads of a client's request body. |
| `send_timeout` | 10s | Bound inactivity while sending a response to a client that stops reading. |
| `keepalive_timeout` | 10s | Release idle client keepalive connections. |

Proxy read/send timeouts measure gaps between I/O operations, not a total request
duration. Run `python3 labs/lab11/scripts/verify.py` for the live timeout proof:
it sends complete headers declaring a 100-byte body, sends only one body byte,
and waits. Nginx closes the TLS socket after **10.015s** and
logs status **408**, with no upstream connection (`uct=-`). In this case it sends
no HTTP response bytes, so asserting a received 408 would misdescribe the result.
The script checks both elapsed time and the matching 408 access-log entry.
Evidence: [timeout.json](../labs/lab11/results/timeout.json).

### OCSP stapling

Stapling can save an OCSP-capable client a separate revocation-status request to
the issuing CA, reducing latency and disclosure of browsing activity to that CA.
It is disabled here because the self-signed certificate has neither a CA responder
nor a useful issuer-signed OCSP response. For production, enable it only if the
chosen issuer supports OCSP, with a validated chain, resolver and monitoring;
public trust by itself does not guarantee OCSP support.

### Ordered certificate rotation runbook

1. Monitor live expiry; record the current serial, dates and fingerprint, and
   obtain a replacement before expiry. Serialize deployments so another reload
   cannot occur while installing the pair.
2. Stage the new certificate and key inside the mounted `certs/` directory under
   temporary names. Verify SANs, validity dates and chain; compare public-key hashes
   from `openssl x509 -in next.crt -pubkey -noout` and
   `openssl pkey -in next.key -pubout` to establish that the pair matches.
   For a CA-issued certificate, validate its chain with `openssl verify` and the
   appropriate trust store. Ensure file ownership/permissions are readable inside
   Nginx; production private keys should use restricted access.
3. Keep a rollback copy of BOTH current files. Rename both staged files over
   `localhost.crt` and `localhost.key` on the same filesystem. Each rename is
   atomic; the pair is not one atomic operation, so do not allow a reload between
   the renames. Running workers retain the old certificate in memory throughout.
4. Run `docker compose -f labs/lab11/docker-compose.yml exec -T nginx nginx -t`
   **after both replacements**, then `... exec -T nginx nginx -s reload` only if
   validation passes. If validation fails, restore both backups; the current
   workers continue serving the old pair. Use graceful reload rather than restart.
5. Open a fresh TLS connection with SNI and compare its serial/fingerprint/dates
   with the staged certificate:
   `openssl s_client -connect localhost:443 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -serial -dates -fingerprint -sha256`.
   Check successful HTTPS responses, error logs and the TLS protocol posture.
6. Watch error rates and expiry monitoring. If needed restore both rollback files,
   validate and reload again. Retain the previous pair for a bounded rollback
   window, then securely remove its private key and record the rotation event.

The mount is a directory, so file renames become visible inside the container;
a single-file bind mount can keep the old inode instead. The executable lab
smoke test, `python3 labs/lab11/scripts/rotate-test.py`, generates a new local pair,
installs it, validates Nginx, reloads it and checks the served serial while making
100 fresh HTTPS requests. It is a local test helper; the full production
prevalidation/monitoring procedure is the runbook above.

```text
old: serial=23BA3C43312CE954D39FFFBB7C9C54477BC7A65E
new on disk: serial=776A528598EB132777628EC24561C0218FD88119
new served: serial=776A528598EB132777628EC24561C0218FD88119
100 requests: 100 HTTP 200; 0 failures
```

Evidence: [rotation.json](../labs/lab11/results/rotation.json).
This observed run validates the procedure locally, not a guarantee against every
production failure scenario.

### Two ways around a per-address rate limit

A botnet or residential-proxy pool spreads credential attempts across many IPs,
keeping every bucket below threshold. A host with an IPv6 allocation can rotate
source addresses inside its prefix and obtain new per-address buckets without
owning many machines. Add a global login ceiling, carefully designed IPv6-prefix
aggregation and CDN bot detection at the edge, plus per-account progressive delays,
MFA and risk checks in the application; trust real-client-IP information only from
explicitly trusted upstream proxies.

## Bonus

The override adds CRS WAF to the same Compose project on `127.0.0.1:8081:8080`,
with `BACKEND=http://juice:3000`, `MODSEC_RULE_ENGINE=On`,
`BLOCKING_PARANOIA=1` and inbound threshold 5. It runs beside the plain Nginx proxy
for the required comparison. Neither path publishes Juice Shop directly.
This HTTP WAF path is a loopback-only lab comparison endpoint; production should
use HTTPS and chain the WAF with the hardened proxy so there is one entry point
with consistent headers and login/connection controls.

### Identical SQLi through both paths

```bash
curl -sk -o /dev/null -w '%{http_code}\n' \
  'https://localhost/rest/products/search?q=%27+OR+1%3D1--'
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:8081/rest/products/search?q=%27+OR+1%3D1--'
```

| Path | Status | Result |
|---|---|---|
| Plain proxy, HTTPS 443 | 500 | Request forwarded; Juice Shop errors on the SQL fragment. |
| CRS WAF, HTTP 8081 | 403 | Request blocked before reaching Juice Shop. |

An application 500 is not a proxy block: the WAF's recorded 403 and rule match
identify the added control. Evidence:
[waf-comparison.json](../labs/lab11/results/waf-comparison.json).

### Real CRS log evidence

The JSON audit event for that exact request records:

```text
942100: SQL Injection Attack Detected via libinjection
Matched Data: s&1c found within ARGS:q: ' OR 1=1--
949110: Inbound Anomaly Score Exceeded (Total Score: 5)
OWASP_CRS/4.30.0; response status 403
```

942100 detects SQL injection fingerprints using libinjection and contributes a
critical score of 5. 949110 performs the inbound blocking evaluation at the
configured threshold; it is the final denial rather than a separate SQLi detector.
The request and rule details extracted from the real log are committed in
[waf-rule.json](../labs/lab11/results/waf-rule.json); raw logs remain gitignored.
Reproduce with `docker compose -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml logs waf`.

### False-positive hunt — one found

The corpus includes home, application version, product listing, normal search,
apostrophe-containing search, spaces/ampersand, Unicode search and `whoami`.
Ordinary searches and pages return 200 through both paths. `O'Reilly` returns
500 through both paths: Juice Shop's SQL handling fails, and the WAF did not
block this input. A real false positive is **GET `/rest/user/whoami`**:
plain proxy **200**, WAF **403**; CRS **932260**, “Remote Command Execution:
Direct Unix Command Execution”, matches `REQUEST_FILENAME` because the
legitimate endpoint name contains `whoami`, followed by 949110 at score 5.

Evidence: [false-positive-hunt.json](../labs/lab11/results/false-positive-hunt.json)
and [waf-false-positive.json](../labs/lab11/results/waf-false-positive.json).
The lab intentionally records this blocking-mode incompatibility. Before a real
rollout, scope a rule-target exclusion to this exact legitimate route and
`REQUEST_FILENAME` for rule 932260, retaining argument inspection and adding
both benign and malicious regression cases; do not disable RCE rules globally.

### Production rollout

Start with `DetectionOnly` at paranoia level 1 and collect audit events across
representative staging and production-canary traffic, including authenticated
flows, state-changing methods and socket.io. Investigate legitimate matches and
add reviewed exclusions narrowly scoped to route, parameter and rule, with
regression coverage for attacks and ordinary users. Enable blocking on a canary
with a conservative anomaly threshold, then lower it toward the intended threshold
and expand traffic while monitoring false positives, error rates and latency.
Keep a fast rollback to detection mode and retest application/CRS upgrades before
expanding enforcement or raising paranoia.

## Independent cross-check and acceptance audit

After implementing and exercising our own configuration, I reviewed the lab11
files and report patches in public PRs
[#1874](https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1874),
[#1875](https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1875) and
[#1668](https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1668).
They are comparison material, not authoritative solutions or proof of our results.

- All three use `ssl_conf_command Ciphersuites`, a per-address connection zone,
  a parallel CRS proxy, and the 500-versus-403 SQLi observation. Our live outputs
  independently confirm these behaviors.
- #1875 identifies case/trailing-slash login bypasses and the whoami false positive.
  Our regex now covers both login variants and our final live suite asserts 429
  for them. We independently reproduced the whoami 200/403 result and extracted
  rule 932260 from our own CRS log.
- #1874 supplies rotation-under-traffic evidence; our own rotation test achieved
  100/100 successful requests and a verified new serial. #1668 is concise but does
  not include an actual timeout-firing command, so we retained our timed socket
  test and 408 log evidence rather than relying on its completeness.
- #1875 includes earlier labs in its diff; our branch includes only lab11 work.
  Its wider browser-driven WAF tuning is beyond this lab's required single
  false-positive example; we make no claim to have tested every application flow.

| Acceptance criterion | Evidence |
|---|---|
| Permanent redirect and rationale | 308, preserved path/query; Task 1 and redirect.json. |
| TLS 1.3 protocol and suite | tls13.txt. |
| Scanner excludes TLS 1.0/1.1 | protocols.txt. |
| Six always headers and CSP migration | headers.json, rate-limit.json; Task 1. |
| Login-only 429 and rate/burst | rate-limit.json and executable assertions. |
| Per-address connection limit | nginx.conf; 20 held requests then 429, connections.json. |
| Excluded TLS 1.3 cipher refused | rejected-cipher.txt, remote alert 40. |
| Timeouts explained, one observed | timeout table, timeout.json, executable command. |
| OCSP, ordered rotation with live verification | Task 2 and rotation.json. |
| Two concrete bypass techniques and mitigation | Task 2, distributed sources and IPv6 rotation. |
| Identical request through plain proxy/WAF | waf-comparison.json, 500 versus 403. |
| Real CRS rule and explanation | waf-rule.json, 942100 and 949110. |
| False positive and rollout | waf-false-positive.json, 932260; DetectionOnly-first plan. |

`nginx -t` succeeds for both proxy containers; Compose configuration validates.
[verification.txt](../labs/lab11/results/verification.txt) contains the final live
assertion summary. `tools/verify-lab.sh 11` was inspected/listed; its shell blocks
were verified by the equivalent commands above, with Compose-network scanning
for Docker Desktop. It was not claimed as an unmodified `--run` success, which
would regenerate the certificate and skip the deliberately failing cipher probe.

Cleanup after reviewing (includes the override so the WAF is removed too):

```bash
docker compose -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml down -v
```
