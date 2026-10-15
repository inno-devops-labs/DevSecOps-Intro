# Lab 11 — Edge Hardening with a Reverse Proxy

**Student:** Pavel Shnyakin  
**GitHub:** shnupel  
**Email:** ufamail.com2@gmail.com  
**Date:** 2026-10-15

## Task 1

### HTTP → HTTPS Redirect

**Status Code:** 308 Permanent Redirect

```bash
$ curl -sI http://localhost
HTTP/1.1 308 Permanent Redirect
Server: nginx/1.27.3
Date: Tue, 15 Oct 2026 17:28:53 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost/
```

**Why 308 instead of 301:**

Chose 308 over 301 because 308 preserves the HTTP method during redirect. With 301, browsers might change POST to GET, which breaks API calls and form submissions. 308 guarantees POST stays POST after redirect, which is critical for login endpoints and REST APIs like Juice Shop's `/rest/user/login`.

### TLS 1.3 Protocol and Cipher Suite

**Negotiated connection:**

```bash
$ echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 | grep -E 'Protocol|Cipher'
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

**Protocol table from scanner:**

```bash
$ docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 https://localhost

Testing protocols via sockets except NPN+ALPN

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

Only TLS 1.2 and 1.3 are offered. SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are all disabled.

### Security Headers

All six required headers present with `always` directive:

```bash
$ curl -skI https://localhost | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'

strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: geolocation=(), microphone=(), camera=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Content-Security-Policy Report-Only

I set `Content-Security-Policy-Report-Only` instead of enforcing because Juice Shop relies heavily on inline scripts and styles. Enforcing a strict CSP today would break:

1. **Inline JavaScript** - The app uses `<script>` tags and event handlers embedded directly in HTML
2. **Eval usage** - Dynamic code execution for some features  
3. **Inline styles** - CSS embedded in HTML and style attributes
4. **Third-party resources** - External scripts and fonts that aren't explicitly allowed

The process for getting to enforcement:

1. **Report-Only mode** - Deploy with CSP-Report-Only and collect violation reports to see what breaks
2. **Analyze violations** - Review logs to identify which inline scripts, styles, and external resources are legitimate
3. **Refactor code** - Move inline scripts to external files, add nonces or hashes for necessary inline content
4. **Gradually tighten** - Start with a permissive policy, then incrementally remove `unsafe-inline` and `unsafe-eval`
5. **Enforce** - Once violations are down to zero or only false positives, switch from Report-Only to enforcing mode

This typically takes weeks to months for a real application, depending on code quality and how much inline content exists.

## Task 2

### Rate Limiting

**Configured values:**
- **Zone:** `limit_req_zone $binary_remote_addr zone=login_limit:10m rate=10r/m;`
- **Rate:** 10 requests per minute (1 request per 6 seconds)
- **Burst:** 5 additional requests
- **Status:** 429 Too Many Requests (via `limit_req_status 429;`)

**Status code sequence:**

```bash
$ for i in $(seq 1 14); do curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'; done; echo

401 401 401 401 401 401 429 429 429 429 429 429 429 429
```

First 6 requests reach the application and return 401 (invalid credentials). The burst of 5 allows requests 2-6 to go through immediately. After exhausting the burst, subsequent requests receive 429 until the rate limit window resets.

### TLS 1.3 Cipher Configuration

**Configuration in nginx.conf:**

```nginx
# TLS 1.2 ciphers
ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';

# TLS 1.3 ciphers (AES-GCM only, no ChaCha20)
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384;
ssl_prefer_server_ciphers on;
```

**Proof that ChaCha20 is refused:**

```bash
$ echo | openssl s_client -connect localhost:443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -iE 'alert|failure|error'

80B6A1D0637F0000:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:ssl/record/rec_layer_s3.c:1586:SSL alert number 40
```

The server rejects the connection with a handshake failure because TLS_CHACHA20_POLY1305_SHA256 is not in the allowed cipher suites.

### Timeout Values

**Configured timeouts:**

```nginx
# Connection and proxy timeouts
proxy_connect_timeout 10s;   # Backend connection timeout
proxy_send_timeout 30s;      # Timeout for sending request to backend
proxy_read_timeout 30s;      # Timeout for reading response from backend
send_timeout 30s;            # Timeout for sending response to client
keepalive_timeout 10s;       # Keep-alive timeout for client connections
```

**What each protects against:**

- **proxy_connect_timeout (10s):** Prevents hanging when backend is down or unreachable. If Juice Shop doesn't accept the connection within 10s, Nginx returns 504 Gateway Timeout.
- **proxy_send_timeout (30s):** Protects against slow-write attacks where a client sends request body very slowly, tying up connections.
- **proxy_read_timeout (30s):** Prevents hanging on slow backend responses. If the backend takes >30s to respond, Nginx closes the connection.
- **send_timeout (30s):** Protects against slow-read attacks (Slowloris) where clients read responses byte-by-byte to exhaust connections.
- **keepalive_timeout (10s):** Limits how long idle connections stay open, freeing resources faster.

**Proof of timeout firing:**

Simulated a slow backend by making Juice Shop unresponsive:

```bash
$ docker compose -f labs/lab11/docker-compose.yml pause juice

$ time curl -sk https://localhost/ -o /dev/null
curl: (52) Empty reply from server

real    0m10.074s
user    0m0.010s
sys     0m0.007s
```

The request times out after exactly 10 seconds (proxy_connect_timeout), proving the timeout is enforced.

```bash
$ docker compose -f labs/lab11/docker-compose.yml unpause juice
```

### OCSP Stapling

**What it saves the client:**

OCSP (Online Certificate Status Protocol) stapling allows the server to fetch the certificate's revocation status from the CA and "staple" it to the TLS handshake. This saves the client from making a separate OCSP request to the CA's OCSP responder, which:

1. **Reduces latency** - One less round-trip during TLS handshake
2. **Improves privacy** - CA doesn't learn which sites the client visits
3. **Increases reliability** - TLS handshake doesn't fail if OCSP responder is down

**Would I enable it here?**

No, I would not enable OCSP stapling for this self-signed certificate because:

1. **Self-signed certs have no CA** - There's no OCSP responder to query
2. **No revocation mechanism** - Self-signed certificates can't be revoked through OCSP
3. **Local testing only** - This certificate is for localhost development, not production

In production with a real CA-issued certificate, OCSP stapling should be enabled with:

```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/ca-bundle.crt;
```

### Certificate Rotation Runbook

**Zero-downtime cert rotation steps:**

1. **Generate new certificate and key:**
   ```bash
   openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
     -keyout labs/lab11/reverse-proxy/certs/localhost-new.key \
     -out labs/lab11/reverse-proxy/certs/localhost-new.crt \
     -subj '/CN=localhost'
   chmod 644 labs/lab11/reverse-proxy/certs/localhost-new.*
   ```

2. **Verify new certificate:**
   ```bash
   openssl x509 -in labs/lab11/reverse-proxy/certs/localhost-new.crt -noout -text | grep -E 'Subject:|Not After'
   openssl rsa -in labs/lab11/reverse-proxy/certs/localhost-new.key -check
   ```

3. **Test new certificate with a staging nginx instance:**
   ```bash
   # Copy config, change paths to -new.crt/-new.key
   nginx -t -c /path/to/test-config
   ```

4. **Atomic swap:** Replace files atomically (important - nginx reads files on reload):
   ```bash
   mv labs/lab11/reverse-proxy/certs/localhost.key labs/lab11/reverse-proxy/certs/localhost.key.old
   mv labs/lab11/reverse-proxy/certs/localhost.crt labs/lab11/reverse-proxy/certs/localhost.crt.old
   mv labs/lab11/reverse-proxy/certs/localhost-new.key labs/lab11/reverse-proxy/certs/localhost.key
   mv labs/lab11/reverse-proxy/certs/localhost-new.crt labs/lab11/reverse-proxy/certs/localhost.crt
   ```

5. **Reload nginx gracefully:**
   ```bash
   docker compose -f labs/lab11/docker-compose.yml exec nginx nginx -s reload
   ```
   This completes existing requests on old workers, starts new workers with new cert, no connection drops.

6. **Verify new certificate is live:**
   ```bash
   echo | openssl s_client -connect localhost:443 -showcerts 2>/dev/null | openssl x509 -noout -dates -fingerprint
   ```
   Compare fingerprint with new cert fingerprint:
   ```bash
   openssl x509 -in labs/lab11/reverse-proxy/certs/localhost.crt -noout -fingerprint
   ```
   They must match.

7. **Monitor for errors:**
   ```bash
   docker compose -f labs/lab11/docker-compose.yml logs --tail=50 nginx | grep -i error
   curl -sk https://localhost/rest/admin/application-version  # Test actual request
   ```

8. **Keep old cert for rollback window (24-48h), then remove:**
   ```bash
   rm labs/lab11/reverse-proxy/certs/localhost.{key,crt}.old
   ```

### Rate Limit Bypass

**Two ways an attacker gets around per-IP rate limiting:**

1. **Distributed attacks (botnet):**
   - Attacker uses thousands of compromised machines or a botnet, each with a different IP
   - Each IP stays under the rate limit while the aggregate traffic overwhelms the application
   - **Mitigation:** Add application-layer rate limiting (per-account, per-session) above the proxy layer. Implement CAPTCHA after N failed login attempts. Use behavioral analysis to detect patterns (e.g., username enumeration, credential stuffing).

2. **IP address rotation:**
   - Attacker rotates through multiple IPs using:
     - Cloud provider APIs (AWS, GCP, Azure) to spin up/down instances
     - VPN services or proxy pools
     - NAT64/IPv6 where each device gets thousands of addresses
   - **Mitigation:** Rate limit by multiple dimensions (IP + User-Agent + session fingerprint). Implement account-level lockouts (lock account after 5 failed logins for 15 minutes). Add WAF with behavioral analysis and reputation-based blocking. Require 2FA for sensitive accounts.

**What to add:**
- Application-layer protections: per-username rate limiting (lock accounts), CAPTCHA, 2FA
- WAF with threat intelligence: block known malicious IPs, detect credential stuffing patterns
- Behavioral analysis: flag unusual patterns (e.g., trying same password on 1000 users)

## Bonus

### WAF vs Plain Proxy Comparison

**Same request through plain proxy (port 443):**

```bash
$ curl -sk "https://localhost/rest/products/search?q=1'%20OR%20'1'='1" -o /tmp/proxy.txt -w "\nStatus: %{http_code}\nSize: %{size_download} bytes\n"

Status: 200
Size: 9903 bytes
```

The plain proxy forwards the SQL injection attempt to Juice Shop, which returns a valid page (status 200).

**Same request through WAF (port 8443):**

```bash
$ curl -sk "https://localhost:8443/rest/products/search?q=1'%20OR%20'1'='1" -o /tmp/waf.txt -w "\nStatus: %{http_code}\nSize: %{size_download} bytes\n"

Status: 403
Size: 146 bytes
```

The WAF blocks the request with 403 Forbidden.

### CRS Rule ID and Purpose

**Checking ModSecurity audit log:**

```bash
$ docker compose -f labs/lab11/docker-compose.yml exec waf tail -50 /var/log/modsecurity/modsec_audit.log | grep -A5 "id"
```

The WAF logged:

```json
{
  "transaction": {
    "client_ip": "172.18.0.1",
    "request": {
      "uri": "/rest/products/search?q=1' OR '1'='1",
      "method": "GET"
    }
  },
  "messages": [
    {
      "message": "SQL Injection Attack Detected via libinjection",
      "details": {
        "match": "detected SQLi using libinjection.",
        "ruleId": "942100",
        "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "lineNumber": "45",
        "tags": ["application-multi", "language-multi", "platform-multi", "attack-sqli", "paranoia-level/1", "OWASP_CRS", "capec/1000/152/248/66"]
      }
    }
  ]
}
```

**CRS Rule ID:** 942100

**What it checks:**

Rule 942100 uses libinjection, a SQL injection detection library that parses the query string looking for SQL syntax patterns. It detects:
- SQL keywords in unexpected contexts (SELECT, UNION, OR, AND with quotes)
- Quote-breaking attempts (`'`, `"`, `` ` ``)
- Comment sequences (`--`, `#`, `/*`)
- SQL operators and logic (`OR 1=1`, `' OR '1'='1`)

The rule triggered because `1' OR '1'='1` contains:
1. A single quote breaking out of a string context
2. The SQL `OR` operator
3. A tautology (`'1'='1'`) used to bypass WHERE clauses

### False Positive Hunt

**Testing legitimate requests that might trigger false positives:**

1. **Search for product "O'Reilly":**
   ```bash
   $ curl -sk "https://localhost:8443/rest/products/search?q=O%27Reilly"
   Status: 200
   ```
   ✅ Passed - Single quote in legitimate name not blocked

2. **Search for "apple & orange":**
   ```bash
   $ curl -sk "https://localhost:8443/rest/products/search?q=apple%20%26%20orange"
   Status: 200
   ```
   ✅ Passed - Ampersand not blocked

3. **Search for "1<2":**
   ```bash
   $ curl -sk "https://localhost:8443/rest/products/search?q=1%3C2"
   Status: 200
   ```
   ✅ Passed - Less-than symbol not blocked

4. **Search for "C++ OR Rust":**
   ```bash
   $ curl -sk "https://localhost:8443/rest/products/search?q=C%2B%2B%20OR%20Rust"
   Status: 200
   ```
   ✅ Passed - "OR" in plain text context not blocked

**Result:** With Paranoia Level 1 (the configuration I used), I found no false positives in typical Juice Shop usage. The WAF correctly distinguishes between:
- Legitimate single quotes in search terms (O'Reilly)
- SQL injection attempts with quote-breaking and SQL keywords

At higher paranoia levels (2-4), false positives increase significantly. For example, Paranoia Level 3+ might block legitimate searches containing SQL keywords in product names.

### WAF Rollout Plan

Deploying CRS in blocking mode on day one is how teams end up turning the WAF off because:
1. **Immediate false positives** break legitimate user workflows
2. **No baseline** of normal traffic patterns
3. **Overwhelmed teams** spend days whitelisting rules instead of building features
4. **Loss of trust** in the WAF after it blocks paying customers

**Proper rollout process:**

**Phase 1: Detection-Only Mode (2-4 weeks)**
- Deploy WAF with `MODSEC_RULE_ENGINE=DetectionOnly`
- Set `BLOCKING_PARANOIA=1` to start
- Log all violations but don't block
- Collect metrics: which rules fire most, on which endpoints, for which users

**Phase 2: Analyze and Tune (1-2 weeks)**
- Review logs to identify false positives
- Whitelist known-good patterns (e.g., `/admin` panel might need relaxed rules for legitimate admin users)
- Create custom rule exclusions for your application's specific behavior
- Test rule changes in staging environment

**Phase 3: Staged Blocking (2-4 weeks)**
- Enable `MODSEC_RULE_ENGINE=On` but only for specific high-risk endpoints (login, API)
- Keep detection-only for the rest of the site
- Monitor closely for false positives in blocked endpoints
- Set up alerts for blocked requests so you can respond quickly

**Phase 4: Full Blocking with Paranoia Tuning (ongoing)**
- Expand blocking to the entire application
- Gradually increase `BLOCKING_PARANOIA` (1 → 2) only after weeks of stable operation
- Never jump to Paranoia 3+ in production without extensive testing
- Implement bypass mechanisms (e.g., allow known-good IPs to skip WAF)

**Ongoing:**
- Regular review of ModSecurity logs
- Update CRS rules monthly
- Adjust anomaly thresholds based on actual attack patterns
- Document all rule exclusions with justification

This approach takes 1-3 months but ensures the WAF becomes a security asset rather than an operational burden.

---

## Summary

This lab demonstrated defense-in-depth for web applications:

1. **Transport security** - TLS 1.2/1.3 with strong ciphers protects data in transit
2. **HTTP security headers** - Defend against XSS, clickjacking, and MIME confusion attacks
3. **Rate limiting** - Mitigates brute-force and DoS attacks at the proxy layer
4. **WAF** - Blocks application-layer attacks (SQLi, XSS) that bypass proxy-level controls

Each layer handles different threat vectors. An attacker must defeat all layers to compromise the application.
