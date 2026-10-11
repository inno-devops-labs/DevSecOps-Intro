# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (paste the SSL + header sections only — not the whole file)
```nginx
# HTTP server block for traffic redirection
server {
    listen 8080;
    listen [::]:8080;
    server_name localhost;
    return 308 https://$host:8443$request_uri;
}

# HTTPS server block configuring TLS 1.3 and Security Headers
server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name localhost;

    # TLS 1.3 Enforcement
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # SSL Certificate Paths
    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    # 6 Mandatory Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;

    # [Proxy configuration block omitted]
}
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx/1.30.4
Date: Fri, 17 Jul 2026 14:19:19 GMT
Content-Type: text/html
Content-Length: 171
Connection: keep-alive
Location: https://localhost:8443/
```

### B. TLS 1.3 proof
```
Can't use SSL_get_servername
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN = juice.local
Hash used: SHA256
```

### C. Security headers proof (all 6 present)
```
HTTP/2 200 
server: nginx/1.30.4
date: Fri, 17 Jul 2026 14:19:49 GMT
content-type: text/html; charset=UTF-8
content-length: 9903
access-control-allow-origin: *
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 17 Jul 2026 14:14:51 GMT
etag: W/"26af-19f706e1a77"
vary: Accept-Encoding
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)
- HSTS: Prevents man-in-the-middle attacks and protocol downgrades by forcing browsers to connect to the server exclusively via secure HTTPS connections.

- X-Content-Type-Options: nosniff: Defends against MIME-sniffing vulnerabilities by ensuring that browsers strictly adhere to the Content-Type header declared by the server.

- X-Frame-Options: DENY: Prevents Clickjacking attacks by forbidding browsers from rendering the application inside frames, iframes, or objects.

- Referrer-Policy: Minimizes the risk of sensitive information leakage across origins by regulating how much referral data is passed in the HTTP Referer header.

- Permissions-Policy: Secures user privacy and blocks unauthorized access by restricting the browser's capability to utilize hardware APIs like the camera, microphone, or geolocation.

- Content-Security-Policy: Significantly mitigates Cross-Site Scripting (XSS) and data injection vulnerabilities by specifying authorized domains and contexts from which resources can be loaded or executed.

## Task 2: Production Posture

### Rate limit proof
| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced
```text
Can't use SSL_get_servername
depth=0 CN = juice.local
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = juice.local
verify return:1
4057023FB9720000:error:0A000126:SSL routines:ssl3_read_n:unexpected eof while reading:../ssl/record/rec_layer_s3.c:316:
```

### Cipher hardening
```
Server Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)
1. **Detect expiry**: Monitor certificate expiration automatically using automated tools (such as Prometheus ssl_exporter or a deployment cron job checking openssl x509 -enddate) configured to trigger high-severity alerts 30 days prior to expiration.

2. **Order new cert**: Generate a new private key along with a Certificate Signing Request (CSR) specifying required Subject Alternative Names (SANs), and submit it to the Certificate Authority (CA) via the ACME protocol or an internal corporate PKI.

3. **Validate**: Satisfy the CA's automated domain control validation challenges (such as responding to DNS-01 or HTTP-01 verification tokens) to clear the request and download the newly issued cryptographic certificate chain.

4. **Atomic swap**: Upload the newly obtained certificate and private key files into a secure staging directory on the proxy machine, then use an atomic filesystem move (mv) or modify production symlinks to instantly swap the active file targets.

5. **Verify**: Run a configuration syntax and certificate validity check using nginx -t to guarantee the new files are uncorrupted and match the key configuration, then gracefully apply the changes by running nginx -s reload.

6. **Rollback plan**: Retain the previously functional certificate and private key files within an isolated backup folder; if post-deployment checks fail or handshakes break, immediately restore the old files and execute another graceful nginx -s reload.

7. **Audit**: Log the successful certificate rotation event to the centralized SIEM/logging pipeline, update enterprise asset tracking registries with the new expiration metrics, and verify that all monitoring alerts have cleared.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)
- Why is OCSP stapling useful for production but not for a self-signed lab cert?

- OCSP stapling allows the Nginx web server to periodically query the Certificate Authority's (CA) revocation records on its own and "staple" a time-stamped, cryptographically signed proof of validity directly into the initial TLS handshake. This vastly improves performance and client privacy by removing the requirement for every individual user browser to establish a separate, high-latency connection to the CA's external infrastructure just to verify the certificate's status. While critical for production environments, OCSP stapling provides no operational benefit for a self-signed lab certificate because self-signed setups lack a trusted root authority and an independent, external OCSP responder architecture to poll.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- **WAF used:** ModSecurity v3 via the official prepackaged `owasp/modsecurity-crs:nginx-alpine` image. This setup was chosen per the lab's guidance to leverage the rich OWASP Core Rule Set (CRS) documentation and avoid the complexity of manual connector compilation.
- **OWASP CRS version:** 3.3.10 (as verified by the container's deployment logs and audit log signatures).
- **Paranoia level:** 1 (`PARANOIA=1`), enforcing default anomaly thresholds (inbound score cutoff: 5, outbound score cutoff: 4).
- **Rule engine configuration:** `SecRuleEngine On` (active blocking mode).

> **Engineering & Deployment Notes:**
> 1. **Routing Adjustments:** The lab sheet's reference endpoint (`https://localhost-waf`) and native log path (`/var/log/modsec/audit.log`) do not apply to this container architecture. The sidecar was configured to expose port `8080`, acting as a reverse proxy that terminates incoming plain HTTP traffic before establishing an internal proxy link to the backend.
> 2. **mTLS Directives:** When configuring proxy paths, variables like `PROXY_SSL_CERT` and `PROXY_SSL_CERT_KEY` must point to valid, parseable files even if validation is explicitly disabled (`PROXY_SSL_VERIFY=off`). Otherwise, the Nginx engine fails to parse the configuration with an `unknown "proxy_ssl_cert" variable` error.
> 3. **Log Write Permissions:** The image restricts write access to the `/var/log/modsecurity/` parent directory to `root:root`. The actual worker runs under the `nginx` account (UID 101) and can only write inside the designated `/var/log/modsecurity/audit/` subdirectory. Setting `MODSEC_AUDIT_LOG` outside of this directory silently suppresses log output without spitting out errors to stdout.

### Attack payload sent
`GET /rest/products/search?q=' OR 1=1--` (URL-encoded as `?q=%27%20OR%201%3D1--`)

### Before WAF (Nginx alone, port 443)
```text
no-waf: HTTP 500
```
*Observation: Without the WAF sidecar, Nginx proxies the malicious payload straight to the backend. The 500 Internal Server Error is explicitly generated by the Juice Shop SQL database engine choking on the unparameterized, raw SQL tautology. This confirms the baseline posture is fully vulnerable and open to application-layer exploitation.*

### After WAF
```
with-waf: HTTP 403
```

*Observation: The request is intercepted at the proxy layer before hitting the application code. ModSecurity processes the signature, drops the transaction, and returns a clean, standard HTTP 403 Forbidden status code.*

### Audit log excerpt (the rule that fired)
```
{
  "transaction": {
    "client_ip": "172.19.0.1",
    "request": {
      "method": "GET",
      "uri": "/rest/products/search?q=%27%20OR%201=1--"
    },
    "response": {
      "http_code": 403
    },
    "messages": [
      {
        "message": "SQL Injection Attack Detected via libinjection",
        "details": {
          "match": "detected SQLi using libinjection.",
          "ruleId": "942100",
          "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
          "data": "Matched Data: s&1c found within ARGS:q: ' OR 1=1--"
        }
      },
      {
        "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
        "details": {
          "match": "Matched \"Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' )",
          "ruleId": "949110",
          "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"
        }
      }
    ]
  }
}
```
Rule ID: **<e.g. 942100>** — OWASP CRS rule name: **<e.g. SQL Injection Attack: Common Injection Testing>**

### Tradeoff analysis (3 sentences)
What does the WAF buy you that Lecture 5's SAST + DAST + the L7 Conftest gate didn't already?
What does it COST you? (FP risk at higher paranoia levels; ops overhead; cert/config sprawl.)
When would you NOT deploy a WAF in front of a service?
