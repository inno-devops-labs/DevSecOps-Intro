# Lab 11 Submission — Reverse Proxy Hardening: Nginx Security Headers, TLS, and Rate Limiting

**Student:** Ilsaf Abdulkhakov  
**Date:** April 20, 2026  
**Lab:** Lab 11 — Reverse Proxy Hardening

---

## Task 1 — Reverse Proxy Compose Setup (2 pts)

### Why Reverse Proxies Are Valuable for Security

Reverse proxies like Nginx provide critical security benefits for web applications:

1. **TLS Termination**: The proxy handles SSL/TLS encryption/decryption, offloading this computationally expensive task from the application server and providing a single point for certificate management.

2. **Security Headers Injection**: Headers can be added/modified at the proxy layer without modifying application code, ensuring consistent security policies across all responses.

3. **Request Filtering**: The proxy can filter malicious requests, implement rate limiting, and block common attacks before they reach the application.

4. **Single Access Point**: By acting as a gateway, the reverse proxy provides a centralized location for security controls, logging, and monitoring.

5. **Defense in Depth**: Even if the application has vulnerabilities, the proxy layer provides an additional security boundary.

### Why Hiding Direct App Ports Reduces Attack Surface

By not exposing application ports directly to the host:

1. **Reduced Exposure**: Attackers cannot bypass proxy security controls by directly accessing the application
2. **Network Isolation**: The application runs in a private Docker network, only accessible via the proxy
3. **Centralized Security**: All security policies are enforced at a single choke point
4. **Simplified Firewall Rules**: Only the proxy ports need to be exposed to external networks

### Docker Compose Container Status

```
NAME            IMAGE                           COMMAND                  SERVICE   CREATED         STATUS         PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     7 minutes ago   Up 7 minutes   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     7 minutes ago   Up 7 minutes   0.0.0.0:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp
```

**Analysis**: 
- The Juice Shop container (`lab11-juice-1`) shows port `3000/tcp` but **no host port mapping** — it's only accessible within the Docker network
- The Nginx container (`lab11-nginx-1`) has host ports `8080` and `8443` mapped, serving as the only entry point
- This configuration ensures all traffic must pass through Nginx, where security controls are enforced

---

## Task 2 — Security Headers (3 pts)

### HTTP Redirect Verification

Testing HTTP access shows an immediate redirect to HTTPS:

```bash
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```

The `308 Permanent Redirect` status indicates a permanent redirect that preserves the HTTP method, redirecting users to the secure HTTPS endpoint.

### Security Headers from HTTPS Response

```
HTTP/2 200 
server: nginx
date: Mon, 20 Apr 2026 18:58:57 GMT
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Security Header Analysis

#### X-Frame-Options: DENY
**Protection**: Prevents clickjacking attacks by disallowing the page from being embedded in any `<frame>`, `<iframe>`, or `<object>` tags, even on the same origin. This ensures users cannot be tricked into clicking on concealed elements on a page embedded within a malicious site.

#### X-Content-Type-Options: nosniff
**Protection**: Prevents MIME-type sniffing attacks by forcing browsers to respect the declared `Content-Type` header. Without this, browsers might interpret files differently than intended (e.g., treating a text file as JavaScript), which could lead to XSS attacks.

#### Strict-Transport-Security (HSTS): max-age=31536000; includeSubDomains; preload
**Protection**: Forces browsers to only connect via HTTPS for the next year (31536000 seconds) for this domain and all subdomains. The `preload` directive allows the domain to be included in browser HSTS preload lists, protecting even the first visit. This prevents SSL stripping attacks and ensures encrypted communications.

**Important Note**: HSTS only appears on HTTPS responses, not HTTP responses, as verified in the headers. This is correct behavior since browsers only process HSTS headers over secure connections.

#### Referrer-Policy: strict-origin-when-cross-origin
**Protection**: Controls what referrer information is sent with requests. This policy sends the full URL when navigating within the same origin, but only the origin (protocol + domain) when navigating to external sites. This balances analytics needs with privacy, preventing sensitive information in URLs from leaking to third parties.

#### Permissions-Policy: camera=(), geolocation=(), microphone=()
**Protection**: Blocks access to sensitive browser APIs (camera, geolocation, microphone) by default. This reduces the attack surface by preventing malicious scripts from accessing device sensors without explicit permission, mitigating surveillance and privacy risks.

#### Cross-Origin-Opener-Policy (COOP): same-origin
**Protection**: Isolates the browsing context from cross-origin windows, preventing potential cross-origin attacks via `window.opener`. This ensures that popups or windows opened by the page cannot be manipulated by different-origin pages, protecting against certain timing and XS-Leak attacks.

#### Cross-Origin-Resource-Policy (CORP): same-origin
**Protection**: Prevents other origins from loading this resource, even with CORS enabled. This is a defense against Spectre-like attacks and protects sensitive resources from being embedded or loaded by malicious sites.

#### Content-Security-Policy-Report-Only
**Protection**: CSP is a powerful header that restricts where resources (scripts, styles, images, etc.) can be loaded from. Report-Only mode logs violations without enforcing them, allowing testing without breaking functionality. The current policy:
- `default-src 'self'`: Only allow resources from the same origin by default
- `img-src 'self' data:`: Allow images from same origin and data URIs
- `script-src 'self' 'unsafe-inline' 'unsafe-eval'`: Allow scripts from same origin, inline scripts, and eval (needed for Juice Shop's dynamic JavaScript)
- `style-src 'self' 'unsafe-inline'`: Allow styles from same origin and inline styles

This header protects against XSS attacks by controlling resource loading, though `unsafe-inline` and `unsafe-eval` are necessary for Juice Shop's functionality and weaken the protection. In production, these directives should be removed and replaced with nonces or hashes.

---

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts (5 pts)

### TLS Protocol Support Summary

From the testssl.sh scan:

**Supported Protocols:**
- ✅ **TLS 1.2**: Offered (OK)
- ✅ **TLS 1.3**: Offered (OK) - final version
- ❌ **SSLv2**: Not offered (OK)
- ❌ **SSLv3**: Not offered (OK)
- ❌ **TLS 1.0**: Not offered
- ❌ **TLS 1.1**: Not offered

**Why TLSv1.2+ is Required:**

1. **Security Vulnerabilities**: Older protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) have known cryptographic weaknesses:
   - SSLv2/v3: Multiple critical vulnerabilities (POODLE, DROWN)
   - TLS 1.0/1.1: Vulnerable to BEAST attacks, lack modern cipher suites

2. **Compliance**: PCI DSS 3.2+ requires TLS 1.2 or higher for payment card processing

3. **Modern Cryptography**: TLS 1.2+ supports:
   - AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
   - Perfect Forward Secrecy (PFS)
   - Better key exchange mechanisms

4. **TLS 1.3 Advantages**: 
   - Improved handshake performance (1-RTT)
   - Removed legacy cipher suites
   - Enhanced privacy (encrypted handshake)
   - Post-quantum key exchange support (X25519MLKEM768)

### Cipher Suites Supported

**TLS 1.2 (server order):**
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (256-bit)
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (128-bit)

**TLS 1.3 (server order):**
- `TLS_AES_256_GCM_SHA384` (256-bit) - Priority
- `TLS_CHACHA20_POLY1305_SHA256` (256-bit)
- `TLS_AES_128_GCM_SHA256` (128-bit)

**Analysis:**
- All cipher suites use AEAD (Authenticated Encryption with Associated Data)
- All provide forward secrecy via ECDHE key exchange
- No weak ciphers (NULL, RC4, DES, 3DES, MD5) are offered
- Server cipher order is enforced (prevents downgrade attacks)
- Modern elliptic curves supported: X25519, P-256, P-384, P-521

### testssl.sh Warnings and Vulnerabilities

**✅ Vulnerabilities - All Clear:**
- Heartbleed: Not vulnerable
- CCS: Not vulnerable
- POODLE: Not vulnerable (no SSLv3)
- BEAST: Not vulnerable (no TLS 1.0)
- CRIME: Not vulnerable
- BREACH: Not vulnerable (no compression)
- FREAK: Not vulnerable
- DROWN: Not vulnerable
- LOGJAM: Not vulnerable
- ROBOT: Not vulnerable
- RC4: Not detected

**⚠️ Expected Warnings (Self-Signed Certificate on localhost):**

1. **Chain of Trust: NOT ok (self signed)**
   - Expected for development with self-signed certificate
   - Resolution for production: Use Let's Encrypt or organizational CA

2. **OCSP/CRL: NOT ok - neither CRL nor OCSP URI provided**
   - Expected for self-signed certificates
   - Resolution: Use real CA certificates with OCSP stapling enabled

3. **Certificate does not match supplied URI**
   - Minor issue due to connecting via Docker network (host.docker.internal)
   - Not a concern for localhost development

4. **OCSP stapling: not offered**
   - Expected without a real CA
   - Resolution: Uncomment OCSP stapling lines in nginx.conf with trusted certificates

**Note**: These warnings are acceptable for localhost development but must be addressed in production by:
- Using a trusted CA (Let's Encrypt for public, internal CA for private)
- Enabling OCSP stapling
- Proper certificate management and rotation

### HSTS Header Verification

HSTS header is **only present on HTTPS responses** (correctly implemented):

**HTTPS Response:**
```
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

**HTTP Response:**
- No HSTS header present (correct, as browsers ignore HSTS over HTTP)

This is the correct implementation because HSTS headers sent over HTTP are ignored by browsers to prevent MITM attacks from setting HSTS policies.

### Rate Limiting Test Results

**Test Command Output:**
```bash
$ for i in $(seq 1 12); do curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"test@test","password":"test"}'; done

401  # Request 1 - allowed, invalid credentials
401  # Request 2 - allowed
401  # Request 3 - allowed
401  # Request 4 - allowed
401  # Request 5 - allowed
401  # Request 6 - allowed (burst complete)
429  # Request 7 - rate limited!
429  # Request 8 - rate limited
429  # Request 9 - rate limited
429  # Request 10 - rate limited
429  # Request 11 - rate limited
429  # Request 12 - rate limited
```

**Analysis:**
- First 6 requests: `401 Unauthorized` (passed through to app, authentication failed as expected)
- Requests 7-12: `429 Too Many Requests` (rate limiting enforced)

### Nginx Access Log - 429 Responses

```
192.168.65.1 - - [20/Apr/2026:19:05:33 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:19:05:33 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:19:05:33 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:19:05:33 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:19:05:33 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
192.168.65.1 - - [20/Apr/2026:19:05:33 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

The logs confirm rate limiting is working, with response time `rt=0.000` showing the proxy immediately rejected excess requests without forwarding to the backend.

### Rate Limit Configuration Analysis

**Configuration from nginx.conf:**
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req zone=login burst=5 nodelay;
```

**Parameters Explained:**

1. **`rate=10r/m`**: 10 requests per minute per IP address
   - Averages to 1 request every 6 seconds
   - Refill rate prevents sustained brute-force attempts

2. **`burst=5`**: Allows up to 5 excess requests beyond the rate
   - Total capacity: 6 requests initially (1 base + 5 burst)
   - Absorbs legitimate traffic spikes (e.g., double-click, page refresh)

3. **`nodelay`**: Process burst requests immediately rather than queueing
   - Better user experience for legitimate users
   - Faster rejection of attackers

**Why These Values Balance Security vs. Usability:**

**Security Benefits:**
- **Brute Force Prevention**: 10 req/min makes password guessing impractical (only 600 attempts/hour from one IP)
- **Credential Stuffing Defense**: Prevents automated attacks using stolen credential lists
- **DoS Mitigation**: Limits resource consumption from login endpoint abuse

**Usability Considerations:**
- **Legitimate Users**: Most users won't attempt 6+ logins in rapid succession
- **Burst Handling**: The burst of 5 allows for typos or multiple quick attempts without hitting limits
- **Recovery**: After 1 minute, the limit resets, so locked-out users aren't permanently blocked

**Trade-offs:**
- Could be more restrictive (e.g., 5r/m) but may frustrate legitimate users with password managers or typos
- Could be less restrictive (e.g., 30r/m) but would allow more brute-force attempts
- 10r/m is a reasonable middle ground for most applications

### Timeout Settings Analysis

**From nginx.conf:**
```nginx
client_body_timeout 10s;
client_header_timeout 10s;
proxy_read_timeout 30s;
proxy_send_timeout 30s;
proxy_connect_timeout 5s;
keepalive_timeout 10s;
send_timeout 10s;
```

**Timeout Explanations and Trade-offs:**

1. **`client_body_timeout 10s`**
   - Maximum time between successive read operations from the client body
   - **Protects against**: Slowloris attacks (slow POST body)
   - **Trade-off**: May timeout legitimate users on slow connections uploading files
   - **Rationale**: 10s is sufficient for headers but may need increase for file uploads

2. **`client_header_timeout 10s`**
   - Maximum time to receive complete request headers
   - **Protects against**: Slowloris attacks (slow headers)
   - **Trade-off**: Minimal impact on legitimate users (headers are small)
   - **Rationale**: Headers should arrive quickly; 10s is generous

3. **`proxy_read_timeout 30s`**
   - Maximum time waiting for response from upstream (Juice Shop)
   - **Protects against**: Hung backend connections consuming proxy resources
   - **Trade-off**: May timeout long-running API operations
   - **Rationale**: 30s is reasonable for most web requests; complex operations may need longer

4. **`proxy_send_timeout 30s`**
   - Maximum time for transmitting request to upstream
   - **Protects against**: Slow backend accepting requests
   - **Trade-off**: Rarely an issue unless backend is severely overloaded
   - **Rationale**: Matches proxy_read_timeout for symmetry

5. **`proxy_connect_timeout 5s`**
   - Maximum time for establishing connection to upstream
   - **Protects against**: Unresponsive backends
   - **Trade-off**: Faster fail-over in case of backend issues
   - **Rationale**: Should connect quickly; 5s allows for network latency

6. **`keepalive_timeout 10s`**
   - How long to keep idle connections open
   - **Protects against**: Connection exhaustion
   - **Trade-off**: Lower value may increase connection overhead; higher value holds resources
   - **Rationale**: 10s balances connection reuse with resource conservation

7. **`send_timeout 10s`**
   - Maximum time between packets sent to client
   - **Protects against**: Slow clients consuming resources
   - **Trade-off**: May disconnect slow clients
   - **Rationale**: Sufficient for most client connections

**Overall Timeout Strategy:**
- Aggressive timeouts prioritize server availability over accommodating slow clients/backends
- Prevents resource exhaustion from slow or malicious connections
- May need adjustment for specific use cases (file uploads, long-polling, streaming)

---

## Summary

### Task Completion Checklist

- ✅ **Task 1**: Nginx reverse proxy running with Juice Shop internal-only
- ✅ **Task 2**: Security headers verified on both HTTP and HTTPS; HSTS only on HTTPS
- ✅ **Task 3**: TLS configured and scanned; HSTS verified; rate limiting working; timeouts analyzed

### Key Achievements

1. **Zero Direct Application Exposure**: Juice Shop is completely isolated, accessible only through Nginx
2. **Strong TLS Configuration**: TLS 1.2/1.3 only, modern cipher suites, no known vulnerabilities
3. **Comprehensive Security Headers**: 8 security headers implemented protecting against clickjacking, XSS, MIME sniffing, and cross-origin attacks
4. **Effective Rate Limiting**: Login endpoint protected with 10 req/min limit and burst capacity
5. **Defense in Depth**: Multiple timeout configurations protect against various DoS attack vectors

### Files Generated

All analysis outputs stored in `labs/lab11/analysis/`:
- `headers-http.txt` - HTTP redirect response headers
- `headers-https.txt` - HTTPS response headers with HSTS
- `testssl.txt` - Complete TLS security scan
- `rate-limit-test.txt` - Rate limiting test results
- `rate-limit-logs.txt` - Nginx access log showing 429 responses
- `docker-compose-ps.txt` - Container status verification

---

**End of Submission**
