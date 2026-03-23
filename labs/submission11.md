# Lab 11 — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

## Task 1 — Reverse Proxy Compose Setup

### 1.1 Reverse Proxy and Security Benefits

Running Juice Shop behind an Nginx reverse proxy provides several security advantages:

- **TLS termination at a single point:**  
  Nginx handles HTTPS for all incoming traffic, so certificates and TLS settings are managed in one place instead of inside the application container. This simplifies rotation, hardening, and monitoring of TLS.

- **Security headers injection at the edge:**  
  The proxy can add security headers (X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy, COOP/CORP, CSP-Report-Only) to every response without changing application code. This reduces the risk of XSS, clickjacking, MIME-type confusion, and cross-origin data leaks.

- **Request filtering and central logging:**  
  Nginx acts as a single choke point where rate limiting, IP-based filtering, basic WAF rules, and detailed access logs can be applied. This helps detect and block brute-force or DoS attempts before they reach the app.

- **Single access point:**  
  All external traffic goes through the reverse proxy, which simplifies network policies, firewall rules, and monitoring. Operations teams can enforce consistent security controls for all clients.

### 1.2 Reduced Attack Surface (No Direct App Exposure)

Hiding the Juice Shop container behind the reverse proxy means the application itself does **not** expose a host port:

- The **app container** (`juice`) is only reachable on the internal Docker network.
- The **only** exposed ports on the host are the Nginx ports (`8080` for HTTP and `8443` for HTTPS).
- Attackers cannot directly scan or attack the Node.js/Express server from the outside; they must go through Nginx, where TLS, headers, and rate limits are enforced.

This reduces attack surface by:

- Eliminating direct access to the app port (`3000`) from the host.
- Preventing accidental exposure of additional app ports.
- Forcing all traffic through a hardened, controlled entry point.

### 1.3 Docker compose ps evidence

The stack was started from `labs/lab11`:

```bash
docker compose ps
```

Output (truncated to relevant columns):

```bash
Polina@MagicBookX16 MINGW64 /c/devsec/DevSecOps-Intro/labs/lab11 (feature/lab11)
$ docker compose ps
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     2 minutes ago   Up 2 minutes   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     2 minutes ago   Up 2 minutes   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp

```

This shows that:

- The `juice` service has **no published host ports** (only `expose: 3000` inside the Docker network).
- The `nginx` service is the **only** component exposing ports to the host (`8080` and `8443`), acting as the secure reverse proxy in front of Juice Shop.

Additionally, the HTTP redirect behavior was verified:

```bash
Polina@MagicBookX16 MINGW64 /c/devsec/DevSecOps-Intro/labs/lab11 (feature/lab11)
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```
This confirms that HTTP on `8080` is correctly redirected to HTTPS on `8443` by Nginx.

## Task 2 — Security Headers

### 2.1 Captured HTTPS Response Headers

Headers were captured with:

```bash
curl -skI https://localhost:8443/ > labs/lab11/analysis/headers-https.txt
```

Relevant security headers from `labs/lab11/analysis/headers-https.txt`:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### 2.2 Header Purpose and Protection

- **X-Frame-Options**  
  Protects against clickjacking. With `DENY`, the site cannot be framed by any other page, so attackers cannot overlay a hidden frame over a trusted UI to trick users into clicking sensitive actions.

- **X-Content-Type-Options**  
  Protects against MIME-sniffing. `nosniff` tells the browser to respect the declared `Content-Type` and not guess file types, reducing the chance that uploaded or served content is interpreted as executable script.

- **Strict-Transport-Security (HSTS)**  
  Enforces HTTPS for this host in the browser for $max\_age=31536000$ seconds (1 year).  
  `includeSubDomains` extends this to all subdomains; `preload` signals intent to be added to browser preload lists. This mitigates SSL stripping and protocol downgrade attacks once the browser has seen HTTPS at least once.

- **Referrer-Policy**  
  `strict-origin-when-cross-origin` limits how much referrer data is sent to other sites: full URL for same-origin requests, only the origin for cross-origin, and no referrer for downgraded HTTP. This reduces leakage of sensitive paths, query parameters, and tokens in the `Referer` header.

- **Permissions-Policy**  
  `camera=(), geolocation=(), microphone=()` disables access to these powerful browser APIs for all origins. Even if the app is compromised (e.g., XSS), injected scripts cannot use camera, geo, or microphone through standard browser APIs.

- **COOP/CORP (Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy)**  
  - `Cross-Origin-Opener-Policy: same-origin` isolates the browsing context from cross-origin windows and tabs, reducing side‑channel data leaks and some Spectre-like attacks between documents.  
  - `Cross-Origin-Resource-Policy: same-origin` prevents other origins from embedding this site’s resources (e.g., via `<img>` or `<script>`) unless they are same-origin, reducing the risk of cross-origin data exfiltration.

- **Content-Security-Policy-Report-Only**  
  CSP in Report‑Only mode does not block content but logs violations. The policy here:  
  - `default-src 'self'` → most resources must come from the same origin.  
  - `img-src 'self' data:` → images allowed from self or data URIs.  
  - `script-src 'self' 'unsafe-inline' 'unsafe-eval'` → allows Juice Shop’s existing inline/eval-heavy JS while still reporting violations.  
  - `style-src 'self' 'unsafe-inline'` → allows inline styles.  
 Applied at the proxy, this lets operations iterate towards a stricter CSP without modifying application code or breaking the app during this lab.

 ## Task 3 — TLS, HSTS, Rate Limiting & Timeouts

### 3.1 TLS / HSTS Summary (testssl.sh)

TLS configuration was scanned with:

```bash
docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 \
  | tee labs/lab11/analysis/testssl.txt
```

Key results from `labs/lab11/analysis/testssl.txt`:

- **TLS protocol support:**
  - Enabled: TLS 1.2, TLS 1.3  
    (`TLS 1.2 offered (OK)`, `TLS 1.3 offered (OK)`)
  - Not offered: SSLv2, SSLv3, TLS 1.0, TLS 1.1

- **Cipher suites supported (examples):**
  - TLS 1.3:
    - `TLS_AES_256_GCM_SHA384`
    - `TLS_CHACHA20_POLY1305_SHA256`
    - `TLS_AES_128_GCM_SHA256`
  - TLS 1.2:
    - `ECDHE-RSA-AES256-GCM-SHA384`
    - `ECDHE-RSA-AES128-GCM-SHA256`
  - Weak/legacy cipher categories (NULL, EXPORT, RC4, 3DES, obsolete CBC) are all reported as **“not offered (OK)”**, and forward secrecy is enabled: `FS is offered (OK)` with modern groups and curves (`X25519`, `prime256v1`, etc.).

- **Why TLSv1.2+ (prefer TLSv1.3):**
  - SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are deprecated and have known weaknesses; they are disabled on the proxy.
  - TLS 1.2 with AEAD ciphers (AES‑GCM, ChaCha20‑Poly1305) is the current minimum baseline for secure HTTPS.
  - TLS 1.3 further simplifies the protocol, removes many legacy options, and improves performance and forward secrecy, so the proxy prefers TLS 1.3 while still supporting TLS 1.2 for compatibility.

- **Warnings / “NOT ok” items (expected for localhost dev cert):**
  - `Chain of trust: NOT ok (self signed)` — the certificate is self‑signed rather than issued by a public CA.
  - `certificate does not match supplied URI` — the cert CN/SAN is `localhost` while testssl is run against `host.docker.internal`.
  - No CRL/OCSP/CAA/CT information and OCSP stapling not offered.  
    These are acceptable for a local lab with a self‑signed certificate. In a production setup you would:
    - Use a real domain and a public CA (e.g., Let’s Encrypt) or a trusted internal CA (e.g., mkcert).
    - Ensure the hostname matches CN/SAN.
    - Enable OCSP stapling and proper revocation/CAA configuration as hinted in `labs/lab11/reverse-proxy/nginx.conf`.

- **HSTS verification:**
  - HTTP (`http://localhost:8080/`) returns `HTTP 308 Permanent Redirect` and does **not** send `Strict-Transport-Security`, which is correct because HSTS must only be sent over HTTPS.
  - HTTPS (`https://localhost:8443/`) includes:  
    `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`  
    (visible in `labs/lab11/analysis/headers-https.txt` and in the `Strict Transport Security 365 days` section of `testssl.txt`).  
    This ensures that once a browser has seen HTTPS on this host, it will automatically enforce HTTPS for one year, mitigating SSL‑stripping and protocol downgrade attacks.

### 3.2 Rate Limiting & Timeouts

Rate limiting for the login endpoint is configured in `labs/lab11/reverse-proxy/nginx.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_status 429;

location = /rest/user/login {
  limit_req zone=login burst=5 nodelay;
  limit_req_log_level warn;
  proxy_pass http://juice;
}
```

#### Rate‑limit test results

Requests were sent from PowerShell to trigger rate limiting:

Output from `labs/lab11/analysis/rate-limit-test.txt`:

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

- **Summary:**  
  - 6 requests returned `401 Unauthorized` (invalid credentials, backend behaving normally).  
  - The next 6 requests returned `429 Too Many Requests` once the configured `rate` and `burst` thresholds were exceeded, confirming that Nginx rate limiting is active on `/rest/user/login`.

Relevant lines from `labs/lab11/logs/access.log`:

```text
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 401 2373 "-" "curl/8.18.0" rt=0.016 uct=0.001 urt=0.016
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 401 2373 "-" "curl/8.18.0" rt=0.003 uct=0.001 urt=0.003
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 401 2373 "-" "curl/8.18.0" rt=0.002 uct=0.001 urt=0.002
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 401 2373 "-" "curl/8.18.0" rt=0.003 uct=0.000 urt=0.002
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 401 2373 "-" "curl/8.18.0" rt=0.002 uct=0.000 urt=0.002
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 401 2373 "-" "curl/8.18.0" rt=0.002 uct=0.000 urt=0.001
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
172.18.0.1 - - [23/Mar/2026:18:41:33 +0000] "POST /rest/user/login HTTP/1.1" 429 162 "-" "curl/8.18.0" rt=0.000 uct=- urt=-
```

These entries show the same client IP first receiving normal 401 responses, then being throttled with 429 once the rate limit is hit.

#### Rate limit configuration rationale

- `rate=10r/m` — approximately one request every 6 seconds per IP. This is sufficient for normal user login behavior but significantly slows down brute‑force tools trying hundreds or thousands of guesses.
- `burst=5` — allows up to 5 extra requests above the base rate without immediate blocking. This covers short bursts of user errors (e.g., quickly mistyping a password several times) before returning 429s.
- Together, these values strike a balance between **security** (throttling abusive clients) and **usability** (not punishing a human who mistypes a password a few times).

#### Timeout settings and trade‑offs

The proxy and client timeouts in `labs/lab11/reverse-proxy/nginx.conf` are:

```nginx
client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
```
- **client_body_timeout (10s)**  
  Maximum time Nginx waits for the request body from the client. If the client sends the body too slowly or stops sending data, the connection is closed. This limits slow POST / slowloris-style attacks that try to occupy connections by trickling data.

- **client_header_timeout (10s)**  
  Maximum time Nginx waits for the complete HTTP request headers. Very slow or partial header delivery causes the connection to be dropped, reducing the impact of slow-client DoS attempts during the header phase.

- **proxy_read_timeout (30s)**  
  Maximum time Nginx waits for a response from the upstream (Juice Shop) after the request has been sent. If the backend hangs or is very slow, Nginx will time out instead of letting connections pile up indefinitely.  
  Trade-off: setting this too low may break legitimately long‑running requests; setting it too high allows more time for hung backends to tie up proxy resources.

- **proxy_send_timeout (30s)**  
  Maximum time Nginx waits while sending the request to the upstream. If the upstream stops reading (e.g., overloaded app or network issue), Nginx will eventually give up instead of blocking indefinitely.  
  Trade-off: a lower timeout fails stuck requests faster, protecting the proxy and backend, but may terminate traffic on very slow or temporarily overloaded backends.

Combined with TLS 1.2/1.3, HSTS, security headers, and login rate limiting, these timeout settings make the Juice Shop deployment more resilient against brute‑force, slow‑client, and protocol‑level attacks without changing application code.