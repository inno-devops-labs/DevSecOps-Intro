# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### 1.1 Stack Preparation and Startup

For this lab, OWASP Juice Shop was deployed behind an Nginx reverse proxy using Docker Compose.
The objective was to ensure that the application itself was **not directly exposed to the host**, and that all external traffic passed only through the reverse proxy.

Before starting the stack, a local self-signed TLS certificate with **Subject Alternative Name (SAN)** entries for `localhost`, `127.0.0.1`, and `::1` was generated.
This was required so that the HTTPS-enabled Nginx container could start successfully and serve TLS traffic on the local machine.

After certificate generation, the stack was started with:

```bash
docker compose up -d
docker compose ps
```

The stack started successfully and both services were running.

### 1.2 Container Exposure Verification

The `docker compose ps` output confirms that only the Nginx container publishes host ports, while the Juice Shop container remains internal to the Docker network.

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     5 seconds ago   Up 4 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     5 seconds ago   Up 4 seconds   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```

#### Analysis

* `lab11-juice-1` exposes only `3000/tcp` internally.
* There is **no published host binding** such as `0.0.0.0:3000->3000/tcp`.
* `lab11-nginx-1` is the only service accessible from the host, through:

  * `8080` for HTTP
  * `8443` for HTTPS

This means Juice Shop is reachable only through the Nginx reverse proxy, which satisfies the lab requirement.

### 1.3 HTTP to HTTPS Redirect Verification

To confirm that the reverse proxy handles insecure HTTP requests correctly, an HTTP request was sent to port `8080`:

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
```

Output:

```text
HTTP 308
```

This confirms that the HTTP endpoint does not serve the application directly and instead returns a **308 Permanent Redirect** to HTTPS.

The full response headers were also checked:

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Mon, 20 Apr 2026 18:28:02 GMT
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
```

#### Analysis

* The response includes a `Location` header pointing to `https://localhost:8443/`.
* This ensures that clients are redirected to the encrypted HTTPS endpoint.
* Security headers are also present on the redirect response because Nginx uses `add_header ... always;`, which is a good practice since protections remain visible even on redirects and error responses.

---

### 1.4 Why Reverse Proxies Improve Security

Using Nginx as a reverse proxy improves security for several reasons:

* It provides a **single controlled entry point** to the application.
* It can perform **TLS termination**, so HTTPS can be enforced even if the application itself does not manage certificates.
* It allows security controls such as:

  * HTTP → HTTPS redirects
  * security header injection
  * request filtering
  * rate limiting
  * centralized access logging
* It separates **application logic** from **transport and edge security configuration**.

This is especially valuable in DevSecOps practice because many security improvements can be implemented operationally **without modifying application code**.

---

### 1.5 Why Hiding Direct App Ports Reduces Attack Surface

Not exposing the Juice Shop container directly reduces the attack surface in several ways:

* attackers cannot connect to the backend service directly from the host;
* all traffic must pass through the hardened Nginx layer;
* proxy-level controls cannot be bypassed;
* the backend is isolated inside the Docker network;
* HTTPS, security headers, and future request controls are enforced consistently.

If the Juice Shop port were published directly, a client could potentially access the application without passing through the reverse proxy, which would weaken the security model of the deployment.

---


## Task 2 — Security Headers

### 2.1 HTTP Header Verification

The reverse proxy was checked over HTTP to confirm that the configured security headers are returned even on the redirect response.

Command used:

```bash
curl -sI http://localhost:8080/ | tee analysis/headers-http.txt
```

Output:

```text
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Mon, 20 Apr 2026 18:39:08 GMT
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
```

#### Analysis

The HTTP endpoint correctly returns a **308 Permanent Redirect** to HTTPS and still includes the configured security headers.
This is a good practice because the Nginx configuration uses `add_header ... always;`, which ensures that protections are visible even on redirects and non-200 responses.

At the same time, the HTTP response does **not** include the `Strict-Transport-Security` header, which is the correct behavior.
HSTS should only be sent over HTTPS, otherwise browsers may ignore it or the configuration may be considered incorrect.

---

### 2.2 HTTPS Header Verification

The proxy was then checked over HTTPS to verify that the same headers are present on the secured endpoint and that HSTS is enabled.

Command used:

```bash
curl -skI https://localhost:8443/ | tee analysis/headers-https.txt
```

Output:

```text
HTTP/2 200 
server: nginx
date: Mon, 20 Apr 2026 18:39:22 GMT
content-type: text/html; charset=UTF-8
content-length: 75002
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Mon, 20 Apr 2026 18:27:51 GMT
etag: W/"124fa-19dac261b3e"
vary: Accept-Encoding
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

#### Relevant security headers observed over HTTPS

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

#### Analysis

The HTTPS response confirms that all required proxy-level security headers are active.
Unlike the HTTP response, the HTTPS response also includes the `Strict-Transport-Security` header:

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

This shows that HSTS is configured correctly only on the TLS-protected endpoint.

---

### 2.3 HSTS Verification

To confirm that HSTS appears only on HTTPS, the following checks were performed:

```bash
grep -i "strict-transport-security" analysis/headers-http.txt
grep -i "strict-transport-security" analysis/headers-https.txt
```

Results:

* `analysis/headers-http.txt` returned **no output**
* `analysis/headers-https.txt` returned:

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

#### Analysis

This behavior is correct and aligned with best practice:

* **HTTP:** no HSTS
* **HTTPS:** HSTS enabled

This ensures browsers learn the HTTPS-only policy only from a secure connection.

---

### 2.4 Security Header Purpose and Protection

#### a. `X-Frame-Options: DENY`

This header prevents the application from being embedded inside a `frame` or `iframe`.
Its main purpose is to protect against **clickjacking**, where an attacker tricks a user into interacting with hidden or overlaid content from another site.

#### b. `X-Content-Type-Options: nosniff`

This header tells browsers not to guess or “sniff” the MIME type of a response.
It helps prevent **content-type confusion attacks**, where a browser may interpret a file as executable script even when the declared content type says otherwise.

#### c. `Strict-Transport-Security (HSTS)`

This header instructs browsers to use **HTTPS only** for the site for the configured period (`max-age=31536000`).
It helps protect against **SSL stripping** and protocol downgrade attacks by preventing the browser from falling back to insecure HTTP after the first trusted HTTPS visit.

#### d. `Referrer-Policy: strict-origin-when-cross-origin`

This header controls how much referrer information is sent when the browser follows links or makes requests.
It reduces **information leakage** by avoiding full URL disclosure to cross-origin destinations while still preserving useful same-origin behavior.

#### e. `Permissions-Policy: camera=(), geolocation=(), microphone=()`

This header disables access to selected browser features such as camera, geolocation, and microphone.
It reduces unnecessary exposure to **sensitive browser capabilities** and limits abuse if malicious or compromised content is rendered in the page.

#### f. `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`

These headers improve cross-origin isolation:

* **COOP** (`Cross-Origin-Opener-Policy`) isolates the browsing context from cross-origin pages and reduces unsafe interactions between windows/tabs.
* **CORP** (`Cross-Origin-Resource-Policy`) restricts loading of resources by other origins unless explicitly allowed.

Together, they help reduce risks related to **cross-origin data leaks**, **window reference abuse**, and some classes of browser side-channel attacks.

#### g. `Content-Security-Policy-Report-Only`

This header defines a Content Security Policy in **monitoring mode** rather than enforcement mode.
It helps identify unsafe script, style, or resource loading patterns without immediately breaking application functionality.

This is especially important for Juice Shop because it is a JavaScript-heavy application, and a strict enforced CSP could disrupt normal behavior.
Using **Report-Only** is a practical first hardening step that provides visibility into policy violations while preserving usability.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### 3.1 TLS Scan with testssl.sh

The HTTPS endpoint was scanned using `testssl.sh`.

Because the environment was macOS with Docker Desktop, the scan targeted `host.docker.internal` instead of using host networking.

Command used:

```bash
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 \
  | tee analysis/testssl.txt
```

#### TLS protocol support

The scan confirmed that only modern TLS versions are enabled:

* **SSLv2**: not offered
* **SSLv3**: not offered
* **TLS 1.0**: not offered
* **TLS 1.1**: not offered
* **TLS 1.2**: offered
* **TLS 1.3**: offered

Relevant scan output:

```text
SSLv2      not offered (OK)
SSLv3      not offered (OK)
TLS 1      not offered
TLS 1.1    not offered
TLS 1.2    offered (OK)
TLS 1.3    offered (OK): final
ALPN/HTTP2 h2, http/1.1 (offered)
```

#### Supported cipher suites

The scan showed that the server supports only modern AEAD cipher suites with forward secrecy.

**TLS 1.2**

* `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
* `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`

**TLS 1.3**

* `TLS_AES_256_GCM_SHA384`
* `TLS_CHACHA20_POLY1305_SHA256`
* `TLS_AES_128_GCM_SHA256`

Relevant scan output:

```text
TLSv1.2 (server order)
xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 256   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 256   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

TLSv1.3 (server order)
x1302   TLS_AES_256_GCM_SHA384            ECDH 253   AESGCM      256      TLS_AES_256_GCM_SHA384
x1303   TLS_CHACHA20_POLY1305_SHA256      ECDH 253   ChaCha20    256      TLS_CHACHA20_POLY1305_SHA256
x1301   TLS_AES_128_GCM_SHA256            ECDH 253   AESGCM      128      TLS_AES_128_GCM_SHA256
```

#### Why TLS 1.2+ is required

Using only **TLS 1.2 and TLS 1.3** is important because older protocols such as SSLv3, TLS 1.0, and TLS 1.1 are obsolete and no longer considered secure for modern deployments. They are associated with outdated cryptographic behavior and broader compatibility with weak cipher suites.

**TLS 1.2** is the minimum modern baseline for secure deployments, while **TLS 1.3** is preferred because it simplifies the handshake, removes legacy insecure options, and improves both security and performance.

#### Warnings and notable findings from testssl

The scan did **not** report major classic TLS vulnerabilities:

* Heartbleed: not vulnerable
* CCS: not vulnerable
* CRIME: not vulnerable
* BREACH: not vulnerable
* POODLE: not vulnerable
* SWEET32: not vulnerable
* FREAK: not vulnerable
* DROWN: not vulnerable
* LOGJAM: not vulnerable
* BEAST: not vulnerable
* LUCKY13: not vulnerable

Relevant scan output:

```text
Heartbleed (CVE-2014-0160)                not vulnerable (OK)
CCS (CVE-2014-0224)                       not vulnerable (OK)
CRIME, TLS (CVE-2012-4929)                not vulnerable (OK)
BREACH (CVE-2013-3587)                    no gzip/deflate/compress/br HTTP compression (OK)
POODLE, SSL (CVE-2014-3566)               not vulnerable (OK), no SSLv3 support
SWEET32 (CVE-2016-2183, CVE-2016-6329)    not vulnerable (OK)
FREAK (CVE-2015-0204)                     not vulnerable (OK)
DROWN (CVE-2016-0800, CVE-2016-0703)      not vulnerable on this host and port (OK)
LOGJAM (CVE-2015-4000)                    not vulnerable (OK)
BEAST (CVE-2011-3389)                     not vulnerable (OK), no SSL3 or TLS1
LUCKY13 (CVE-2013-0169)                   not vulnerable (OK)
```

The main negative findings are expected for a **localhost self-signed development certificate**:

* chain of trust is **not trusted**
* certificate is **self-signed**
* hostname trust check is affected because the scan targets `host.docker.internal` while the certificate CN/SAN is for `localhost`
* no CRL/OCSP URI is provided
* OCSP stapling is not offered
* no CAA / CT information is present

Relevant scan output:

```text
Trust (hostname)             certificate does not match supplied URI (same w/o SNI)
Chain of trust               NOT ok (self signed)
OCSP URI                     --
                             NOT ok -- neither CRL nor OCSP URI provided
OCSP stapling                not offered
DNS CAA RR (experimental)    not offered
Certificate Transparency     --
```

These findings are acceptable for a local lab environment. To eliminate them in a more realistic deployment, one of the following would be needed:

* trust a local CA such as **mkcert**, or
* use a real domain and a publicly trusted CA such as **Let’s Encrypt**

In that case, OCSP stapling could also be enabled in Nginx.

#### Overall TLS assessment

The TLS configuration is strong for a local development environment:

* only TLS 1.2 and TLS 1.3 are enabled
* old protocols are disabled
* only modern AEAD cipher suites are supported
* forward secrecy is enabled
* no major classic TLS vulnerabilities were detected

The low grade in `testssl.sh` is caused by certificate trust issues typical for self-signed localhost certificates, not by weak protocol or cipher configuration.

---

### 3.2 HSTS Verification

The HSTS header was verified to appear only on HTTPS responses and not on HTTP responses.

Commands used:

```bash
grep -i "strict-transport-security" analysis/headers-http.txt
grep -i "strict-transport-security" analysis/headers-https.txt
```

Result:

* `analysis/headers-http.txt` returned **no output**
* `analysis/headers-https.txt` returned:

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

#### Analysis

This is the correct behavior:

* **HTTP** responses do not include HSTS
* **HTTPS** responses do include HSTS

This ensures the browser learns the HTTPS-only policy only over a secure channel.

---

### 3.3 Rate Limiting Validation on `/rest/user/login`

The login endpoint is protected in Nginx with request limiting:

* `rate=10r/m`
* `burst=5`
* `limit_req_status 429`

Command used:

```bash
for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done | tee analysis/rate-limit-test.txt
```

Output:

```text
401
401
401
401
401
401
429
429
429
429
429
429
```

Summary:

```text
6 401
6 429
```

#### Analysis

Out of 12 rapid login attempts:

* **6 requests** were processed by the application and returned `401 Unauthorized`
* **6 requests** were blocked by Nginx with `429 Too Many Requests`

The `401` responses are expected because intentionally invalid credentials were used. The important result is that once the request rate exceeded the configured threshold, Nginx began returning `429`, confirming that rate limiting is active and working correctly.

---

### 3.4 Rate Limit Configuration Analysis

The login endpoint is protected by:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

#### What `rate=10r/m` means

The configuration allows approximately **10 requests per minute per client IP** as the sustained rate.

#### What `burst=5` means

An additional **burst of 5 requests** is allowed above the sustained rate before requests are rejected.

#### What `nodelay` means

Burst requests are processed immediately rather than being queued and delayed.

#### Security/usability trade-off

This is a reasonable balance between security and usability:

* it reduces the effectiveness of brute-force login attempts;
* it limits abusive rapid request bursts;
* it still tolerates short legitimate bursts from normal users or browsers.

If the rate were much lower, real users could be blocked too aggressively. If it were much higher, brute-force protection would be weaker.

---

### 3.5 Timeout Configuration Analysis

Relevant timeout directives in `nginx.conf`:

```nginx
client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
```

#### `client_body_timeout 10s`

Limits how long Nginx waits for the client to send the request body. This helps reduce the impact of **slow POST / slow upload** attacks.

**Trade-off:** if set too low, legitimate slow clients or larger uploads may be terminated prematurely.

#### `client_header_timeout 10s`

Limits how long Nginx waits for the client to send request headers. This helps mitigate **slowloris-style attacks**, where an attacker keeps connections open by sending headers very slowly.

**Trade-off:** if set too aggressively, clients on slow networks may be disconnected.

#### `proxy_read_timeout 30s`

Limits how long Nginx waits for a response from the upstream application. This prevents the proxy from holding resources indefinitely if the backend becomes slow or stuck.

**Trade-off:** if set too low, legitimate slow backend operations may be interrupted.

#### `proxy_send_timeout 30s`

Limits how long Nginx waits while sending the request to the upstream server. This protects against hangs between the reverse proxy and the backend.

**Trade-off:** if set too low, transient backend slowness may cause avoidable failures.

#### Overall timeout assessment

These timeout values are short enough to reduce the impact of slow-connection abuse, but not so short that they are likely to break normal Juice Shop usage in a lab environment.

---

### 3.6 Access Log Evidence

Relevant Nginx access log lines showing rate-limit enforcement:

```text
192.168.65.1 - - [20/Apr/2026:18:54:44 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:54:44 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:54:44 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:54:44 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:54:44 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:54:44 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:58:25 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:58:25 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:58:25 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:58:25 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:58:25 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:18:58:25 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

These entries confirm on the server side that requests to `/rest/user/login` were rejected with HTTP `429 Too Many Requests` after the configured threshold was exceeded.

