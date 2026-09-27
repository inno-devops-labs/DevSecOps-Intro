# Lab 11 — Edge Hardening with a Reverse Proxy

I put Nginx in front of Juice Shop and tested the controls over real connections:
HTTPS redirection, protocol and cipher restrictions, response headers, login
rate limiting, connection limiting, an upstream timeout, and certificate rotation.
I also ran an OWASP CRS WAF alongside the plain proxy and compared the same
request through both paths. The application has no published host port.

## Environment and reproducibility

| Item | Version or configuration |
|---|---|
| Run date | 27 September 2026 |
| Host | Windows, PowerShell, Docker Desktop with Linux containers |
| Docker / Compose | 29.2.1 / v5.1.0 |
| Application | Juice Shop v20.0.0 |
| Plain proxy | Nginx 1.30.5, stable-alpine image |
| WAF | ModSecurity 3.0.16, Nginx connector 1.0.4, OWASP CRS 4.29.0 |
| TLS client | OpenSSL 3.2.1 from Git for Windows |
| Protocol scanner | testssl.sh 3.2.4, image tag `3.2`, bundled legacy-capable OpenSSL |
| Published ports | `127.0.0.1:80`, `127.0.0.1:443`, WAF comparison at `127.0.0.1:8081` |
| Certificate | Local self-signed RSA-2048, 30 days, SANs `localhost` and `127.0.0.1` |

This branch starts from `main` and contains only these Lab 11 changes:

- [Nginx configuration](../labs/lab11/reverse-proxy/nginx.conf).
- [Base Compose file](../labs/lab11/docker-compose.yml), updated to bind the
  proxy locally and pin the application and proxy images by digest.
- [WAF Compose override](../labs/lab11/waf/docker-compose.override.yml), also
  pinned by digest.
- This report.

The image digests used for the run are:

```text
Juice Shop: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
Nginx:     sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94
WAF:       sha256:88c42590d8242eb48f53af309013642793152d4a5e4a16f8a74c2bcc9c840a1b
testssl:   sha256:e38206bd09f48e8b4022ee8480ad3be93bfecfc4e5b5e4c5f7aca5c4bec4da52
```

Certificates and private keys stay in the ignored `reverse-proxy/certs/`
directory. Raw outputs and verification scripts stay in the ignored
`labs/lab11/logs/` directory; no private signing material or bulk logs are
included in the PR. Commands below run from the repository root; `openssl`
refers to the Git for Windows binary, and `curl.exe` avoids the PowerShell alias.

```powershell
openssl req -x509 -nodes -newkey rsa:2048 -days 30 `
  -keyout labs/lab11/reverse-proxy/certs/localhost.key `
  -out labs/lab11/reverse-proxy/certs/localhost.crt `
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
docker compose -p lab11 -f labs/lab11/docker-compose.yml `
  -f labs/lab11/waf/docker-compose.override.yml up -d
docker exec lab11-nginx-1 nginx -t
```

Nginx reported `syntax is ok` and `test is successful`.
`https://localhost/rest/admin/application-version` returned
`{"version":"20.0.0"}`. The effective Compose configuration was checked, and
`docker inspect lab11-juice-1 --format '{{json .HostConfig.PortBindings}}'`
returned `{}`, confirming that Juice Shop itself has no published host port.

## Task 1

### Permanent HTTP-to-HTTPS redirect

```powershell
curl.exe -sI 'http://localhost/rest/admin/application-version?proof=redirect'
```

Observed status and destination:

```http
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/rest/admin/application-version?proof=redirect
```

I retained **308** because it preserves the method and request body when a client
follows the redirect, including a POST. The server-level return applies to every
HTTP path and preserves the path and query string. TLS is handled by Nginx,
which forwards to the internal `juice:3000` service.

### Protocols and negotiated cipher

```powershell
'' | openssl s_client -connect localhost:443 -servername localhost -tls1_3 -brief
docker run --rm --network lab11_default drwetter/testssl.sh:3.2 `
  --protocols --color 0 --warnings batch https://nginx:443
```

The TLS 1.3 connection succeeded, exit **0**:

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=localhost
Signature type: RSA-PSS
Verification error: self-signed certificate
```

The certificate warning is expected for this local certificate. These commands
demonstrate encryption and the offered configuration, not public-CA trust;
`curl -k` deliberately skips that trust check.

The scanner ran on the Compose network because Docker Desktop's host networking
is not needed to reach the proxy there. Its `nginx:443` target is the same Nginx
listener published as `localhost:443`. Actual protocol table:

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

This tests what the server offers using the scanner's own protocol probes;
it does not confuse a modern client's local refusal to use TLS 1.0/1.1 with
evidence that the server rejected them.

### Returned headers, including error responses

```powershell
curl.exe -skI https://localhost
```

The HTTPS **200** response contained all six required headers:

```http
Strict-Transport-Security: max-age=86400
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

Every directive uses `always`. I also checked that each header appeared exactly
once in actual **401** login responses, **429** rate/connection-limit responses,
and the **504** upstream-timeout response. Upstream copies are hidden where
necessary, including HSTS, so the proxy supplies one consistent value.
HSTS is only sent over HTTPS and uses a one-day trial value; this localhost
exercise does not claim preload registration or commit all subdomains to HTTPS.

The proxy overwrites `X-Real-IP` and `X-Forwarded-For` with `$remote_addr` and
sets `X-Forwarded-Proto` to `$scheme`. It is the entry point in this topology,
so it does not preserve a forwarding chain supplied by an untrusted client.
Docker Desktop presented these host-side requests as **172.18.0.1** in the
logs; both limits use that observed address, not a claim of visibility through
every possible upstream NAT or load balancer.

The candidate report-only CSP would block Juice Shop's inline cookie-consent
initialization, inline styles, and remote font loads if enforced unchanged;
the fetched HTML contains one inline executable script and two inline style
blocks, including a remote font reference. I would exercise the application's
real user journeys and collect browser violations into a protected reporting
endpoint, then replace necessary inline code with nonces/hashes and explicitly
authorize required sources. After reviewing those exceptions, I would test
enforcement in staging and a small canary before expanding it. The current
header is a policy trial, not enforced protection or a configured centralized
report collector.

## Task 2

### Login rate limiting and per-address connection limiting

The login-only configuration is:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

I sent 14 sequential POST requests with invalid test credentials:

```powershell
Set-Content -Encoding ascii -NoNewline labs/lab11/logs/login.json '{"email":"a@b.c","password":"x"}'
1..14 | ForEach-Object {
  curl.exe -sk -o NUL -w '%{http_code} ' -X POST https://localhost/rest/user/login `
    -H 'Content-Type: application/json' --data-binary '@labs/lab11/logs/login.json'
}
```

Observed sequence:

```text
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

The sustained rate is **10 requests/minute per observed client address**, with
**burst 5** and no queuing delay. An initially idle bucket allowed the first
request plus five excess requests to reach Juice Shop and return **401**; the
remaining eight were rejected with **429**. A subsequent sequence of 14 requests
to `/rest/admin/application-version` returned **200** every time, showing that
the login rate limit is not applied to the whole site.

The independent HTTPS connection limit is:

```nginx
limit_conn_zone $binary_remote_addr zone=per_client:10m;
limit_conn_status 429;
# Inside the HTTPS server:
limit_conn per_client 10;
```

I opened ten TLS connections, sent complete HTTP headers with an unfinished
request body on each, then requested the version endpoint on an eleventh
connection. That request returned **429**; after closing the held requests,
the same endpoint returned **200**. The error log confirms the connection
limit rather than the login rate limit caused the rejection:

```text
2026/09/27 09:05:38 [warn] 33#33: *95 limiting connections by zone "per_client", client: 172.18.0.1, server: _, request: "GET /rest/admin/application-version HTTP/1.1", host: "localhost"
```

This limits concurrent requests counted by Nginx, not every idle TCP socket;
HTTP/2 concurrent requests also need to be considered when sizing the limit.

### TLS 1.3 cipher restriction

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```

Only the two AES-GCM suites are enabled for **TLS 1.3**. The separate
`ssl_ciphers` list configures TLS 1.2 and retains its ECDHE AES-GCM and ChaCha20
suites; it is not used to select TLS 1.3 suites. This distinction follows the
[Nginx SSL module documentation](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_conf_command).

```powershell
'' | openssl s_client -connect localhost:443 -servername localhost -tls1_3 `
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -brief
```

This reached the server and exited **1**. Exact output:

```text
Connecting to 127.0.0.1
100000000A000000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:ssl/record/rec_layer_s3.c:865:SSL alert number 40
```

The server's TLS alert is the relevant evidence; this is not a local
`no cipher match` error caused by using the wrong OpenSSL option.

### Explicit timeouts and an observed failure

| Setting | Value | Purpose |
|---|---:|---|
| `proxy_connect_timeout` | **5s** | Bound the wait to establish an upstream connection. |
| `proxy_read_timeout` | **30s** | Stop waiting when the upstream sends no response data within the read interval. |
| `proxy_send_timeout` | **30s** | Stop an upstream that cannot accept request data within the write interval. |
| `client_header_timeout` | **10s** | Limit the time allowed to receive request headers. |
| `client_body_timeout` | **10s** | Limit idle gaps while receiving the request body. |
| `send_timeout` | **10s** | Limit idle gaps while sending the response to the client. |
| `keepalive_timeout` | **10s** | Release an idle persistent client connection. |

The proxy read and send values are inactivity intervals, not whole-transaction
deadlines, as specified by the
[Nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout).

To demonstrate a real read timeout, I paused the disposable application while
leaving Nginx running, requested its version, and resumed it in a `finally` block:

```powershell
docker pause lab11-juice-1
try {
  curl.exe -sk --max-time 40 -o NUL -w 'status=%{http_code} seconds=%{time_total}' `
    https://localhost/rest/admin/application-version
} finally {
  docker unpause lab11-juice-1
}
```

The measured result was **504 after 30.06 seconds**, and the next request after
unpausing returned **200**. All six security headers were present on the 504.
The matching log entry was:

```text
2026/09/27 09:06:10 [error] 33#33: *116 upstream timed out (110: Operation timed out) while reading response header from upstream, client: 172.18.0.1, server: _, request: "GET /rest/admin/application-version HTTP/1.1", upstream: "http://172.18.0.2:3000/rest/admin/application-version", host: "localhost"
```

### OCSP stapling

With a suitable CA-issued certificate, stapling lets the server provide a signed
revocation-status response, avoiding a separate client request to the CA's
responder. I leave `ssl_stapling off` here because this self-signed certificate
has no CA responder to supply a useful staple. For a real deployment I would
check the issuing CA's support and certificate chain before enabling and
monitoring it, following the
[Nginx stapling requirements](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_stapling).

### Certificate rotation runbook and live test

1. Obtain the replacement certificate and key in the mounted certificate
   directory under temporary names. Check SANs, validity dates, chain, and that
   `openssl x509 -pubkey` matches `openssl pkey -pubout`; keep the current pair
   available for rollback.
2. Start a continuous HTTPS probe against the version endpoint and record the
   certificate serial/fingerprint currently served. Keep the existing Nginx
   workers running throughout the replacement.
3. Replace both `localhost.crt` and `localhost.key` in the directory, completing
   the pair before any reload. Do not restart the container or trigger a file
   watcher between the two replacements; the running workers still use their
   certificate in memory.
4. Run `docker exec lab11-nginx-1 nginx -t`. If it fails, restore the previous
   pair and investigate while the old workers continue serving requests.
5. Run `docker exec lab11-nginx-1 nginx -s reload`. Nginx starts workers with
   the new configuration while old workers drain existing connections; continue
   monitoring responses and errors.
6. Open a fresh TLS connection and inspect its peer certificate, rather than
   only reading the file on disk. Compare its serial and SHA-256 fingerprint
   with the staged replacement, check the chain with a trusted client in a
   CA-backed deployment, and retain the old pair for the rollback window.

I executed this rotation with a newly generated local certificate and **120**
HTTP requests on fresh connections around the reload. All **120 returned 200**,
with **zero failed requests**. This is evidence for the local test, not a
guarantee that a reload can never fail under other conditions.

| Certificate | Served serial | SHA-256 fingerprint |
|---|---|---|
| Before | `4303586403431B2723B03714715115CA124400C0` | `9485de1396dd9e8cf9f75224a95ecb20eecfbbf52bbe010c88528e9beadf35c4` |
| After | `67E24847B642440F6152C50F72D7106294894890` | `8a6e5dc00363b0b050359b29bdecda620d047efdc177ffa1e65c687c4bce2f28` |

The newly served fingerprint matched the replacement file. Its validity runs
from **27 September 2026, 09:06:47 UTC** to **27 October 2026, 09:06:47 UTC**.

### Limits of a per-address rate limit

An attacker can distribute attempts across a botnet or rotating proxies so
each address stays under the threshold. A patient attacker can also stay below
10 requests per minute while spreading attempts across many accounts.
I would add account-aware velocity checks, progressive challenges or MFA, and
a global abuse budget alongside the IP limit, while considering shared-NAT
users so the protection does not become an easy account-lockout attack.
If another trusted proxy is introduced, I would explicitly configure which
upstream addresses may supply the real client IP rather than trusting arbitrary
`X-Forwarded-For` values.

## Bonus

### Compare plain proxy and blocking WAF

The [override](../labs/lab11/waf/docker-compose.override.yml) adds a WAF to the
same Compose project with `BACKEND=http://juice:3000`, `PORT=8080`, and host
port **8081**. It explicitly sets `MODSEC_RULE_ENGINE=On`, paranoia level **1**,
and inbound anomaly threshold **5**. These settings follow the
[CRS container configuration](https://github.com/coreruleset/modsecurity-crs-docker);
the generated `/etc/modsecurity.d/modsecurity.conf` contained `SecRuleEngine On`.

This HTTP listener is a loopback-only comparison path, not a proposed public
HTTP deployment. The WAF goes directly to the internal app so its behavior
can be distinguished from the plain proxy; it does not inherit the other
proxy's TLS, headers, or rate limit. A production path would put TLS termination,
the WAF, and application protection in one enforced route without a public
plain-proxy bypass.

I submitted exactly the same encoded request path through both entry points:

```powershell
curl.exe -sk -o NUL -w '%{http_code}' 'https://localhost/rest/products/search?q=%27+OR+1%3D1--'
curl.exe -s -o NUL -w '%{http_code}' 'http://localhost:8081/rest/products/search?q=%27+OR+1%3D1--'
```

| Path | Status | Interpretation |
|---|---:|---|
| Plain HTTPS proxy | **500** | Nginx forwarded the input; Juice Shop returned a SQL-related application error. This is not a proxy block or a claim of successful exploitation. |
| CRS WAF | **403** | The request was interrupted in phase 2 before being forwarded to the application. |

The decoded `q` value was **`' OR 1=1--`**. The WAF audit log for transaction
`179049993999.705243` recorded these unmodified message fields:

```json
[
  {
    "message": "SQL Injection Attack Detected via libinjection",
    "details": {
      "match": "detected SQLi using libinjection.",
      "reference": "v28,10",
      "ruleId": "942100",
      "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
      "lineNumber": "46",
      "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--",
      "severity": "2",
      "ver": "OWASP_CRS/4.29.0",
      "rev": "",
      "tags": [
        "application-multi",
        "language-multi",
        "platform-multi",
        "attack-sqli",
        "paranoia-level/1",
        "OWASP_CRS",
        "OWASP_CRS/ATTACK-SQLI",
        "capec/1000/152/248/66"
      ],
      "maturity": "0",
      "accuracy": "0"
    }
  },
  {
    "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
    "details": {
      "match": "Matched \"Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )",
      "reference": "",
      "ruleId": "949110",
      "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
      "lineNumber": "222",
      "data": "",
      "severity": "0",
      "ver": "OWASP_CRS/4.29.0",
      "rev": "",
      "tags": [
        "modsecurity",
        "anomaly-evaluation",
        "OWASP_CRS"
      ],
      "maturity": "0",
      "accuracy": "0"
    }
  }
]
```

**942100** is the SQL-injection detector using libinjection; it identified
the suspicious SQL structure in `ARGS:q`. **949110** is the blocking evaluation
rule that rejected the request once the inbound score reached **5**. Keeping
the detection rule separate from the score/blocking rule explains both why
the request was suspicious and why it received 403.

### False-positive hunt

I compared eight ordinary search strings, including punctuation and characters
that can be difficult for broad filters:

| Search text | Plain proxy | WAF |
|---|---:|---:|
| `apple` | 200 | 200 |
| `Apple Juice` | 200 | 200 |
| `O'Reilly` | 500 | 500 |
| `100% organic` | 200 | 200 |
| `Apple & Mango` | 200 | 200 |
| `C++` | 200 | 200 |
| `orange (fresh)` | 200 | 200 |
| `<3 juice` | 200 | 200 |

None received a WAF 403. `O'Reilly` caused **500 on both paths**; its WAF audit
entry had `is_interrupted=false` and no rule messages, so this was an application
handling error, not a false WAF block. The other seven returned 200 on both
paths. This small sample found no false positives; it does not establish
compatibility with every upload, account flow, or application feature.

For a real rollout, I would first run CRS in detection-only mode against
representative traffic and replay critical user journeys in staging.
I would investigate alerts and add narrowly scoped rule/parameter exclusions
for demonstrated false positives, rather than disabling the whole SQLi ruleset.
I would then enable blocking for a small canary with monitored error rates,
an accountable owner, and a quick rollback to detection-only.
Only after that evidence would I expand enforcement and keep regression tests
for both legitimate requests and known attack payloads.

## Final checks and cleanup

- Nginx syntax and the effective Compose configuration were valid.
- TLS enumeration, allowed and refused suite probes, and header checks passed.
- Both request and connection limits returned 429; ordinary traffic recovered.
- A real upstream timeout returned 504, followed by a successful recovery request.
- Certificate rotation completed with 120 successful requests and a new served fingerprint.
- CRS blocked the attack and did not block the eight benign-search controls.
- The application had no published port; only loopback proxy ports were exposed.

After capturing the evidence, I removed the lab services and network using both
Compose files so the bonus WAF was included:

```powershell
docker compose -p lab11 -f labs/lab11/docker-compose.yml `
  -f labs/lab11/waf/docker-compose.override.yml down -v
```
