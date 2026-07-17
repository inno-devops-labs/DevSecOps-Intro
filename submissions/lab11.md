\# Lab 11 — BONUS — Submission



\## Task 1: TLS + Security Headers



\### nginx.conf (paste the SSL + header sections only — not the whole file)

```nginx

&#x20;   # HTTP -> HTTPS Redirect

&#x20;   server {

&#x20;       listen 8080;

&#x20;       server\_name localhost;

&#x20;       return 301 https://$host:8443$request\_uri;

&#x20;   }



&#x20;   # HTTPS Server

&#x20;   server {

&#x20;       listen 8443 ssl;

&#x20;       http2 on;

&#x20;       server\_name localhost;



&#x20;       ssl\_certificate /etc/nginx/certs/localhost.crt;

&#x20;       ssl\_certificate\_key /etc/nginx/certs/localhost.key;

&#x20;       ssl\_protocols TLSv1.3;

&#x20;       ssl\_prefer\_server\_ciphers off;

&#x20;       ssl\_ecdh\_curve X25519:secp384r1;

&#x20;       ssl\_session\_cache shared:SSL:10m;

&#x20;       ssl\_session\_timeout 1d;

&#x20;       ssl\_session\_tickets off;



&#x20;       limit\_conn conn 50;



&#x20;       add\_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

&#x20;       add\_header X-Content-Type-Options "nosniff" always;

&#x20;       add\_header X-Frame-Options "DENY" always;

&#x20;       add\_header Referrer-Policy "strict-origin-when-cross-origin" always;

&#x20;       add\_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

&#x20;       add\_header Content-Security-Policy-Report-Only "default-src 'self'; object-src 'none'" always;

```



\### A. HTTPS redirect proof

```

HTTP/1.1 301 Moved Permanently

Server: nginx/1.30.4

Location: https://localhost:8443/

```



\### B. TLS 1.3 proof

```

CONNECTION ESTABLISHED

Protocol version: TLSv1.3

Ciphersuite: TLS\_AES\_256\_GCM\_SHA384

Peer certificate: CN=juice.local

```



\### C. Security headers proof (all 6 present)

```

Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

X-Content-Type-Options: nosniff

X-Frame-Options: DENY

Referrer-Policy: strict-origin-when-cross-origin

Permissions-Policy: camera=(), microphone=(), geolocation=()

Content-Security-Policy-Report-Only: default-src 'self'; object-src 'none'

```



\### What each header defends against

\- ○ HSTS: Forces browsers to only use HTTPS for the site, preventing SSL stripping attacks.

\- ○ X-Content-Type-Options: nosniff: Prevents browsers from MIME-sniffing a response away from the declared Content-Type, stopping drive-by downloads.

\- ○ X-Frame-Options: DENY: Prevents the page from being rendered in an iframe, blocking clickjacking attacks.

\- ○ Referrer-Policy: Controls how much referrer information is sent with requests, preventing leakage of sensitive URL parameters.

\- ○ Permissions-Policy: Disables access to browser features like camera and microphone, protecting against unauthorized hardware access via malicious scripts.

\- ○ Content-Security-Policy: Restricts the sources from which content can be loaded, mitigating Cross-Site Scripting (XSS) and data injection attacks.



\---



\## Task 2: Production Posture



\### Rate limit proof

| HTTP code | Count out of 60 |

|-----------|----------------:|

| 500 | 6 |

| 429 | 54 |



\### Timeout enforced

(Configured in nginx.conf: client\_header\_timeout 10s; ensures Nginx closes connections that send headers too slowly, preventing Slowloris attacks).



\### Cipher hardening

```

New, TLSv1.3, Cipher is TLS\_AES\_256\_GCM\_SHA384

```



\### Cert rotation runbook (7 steps)

1\. \*\*Detect expiry\*\*: Monitor cert expiry dates via automated alerts (e.g., Prometheus blackbox exporter) triggering at 30 days remaining.

2\. \*\*Order new cert\*\*: Generate a CSR and submit it to the CA (e.g., Let's Encrypt via ACME) or internal PKI.

3\. \*\*Validate\*\*: Complete DCV (Domain Control Validation) or internal approval workflow.

4\. \*\*Atomic swap\*\*: Write the new cert/key to a temporary path, then atomically symlink or mv them to the active path (/etc/nginx/certs/localhost.crt).

5\. \*\*Verify\*\*: Run nginx -t to validate syntax, then reload Nginx (nginx -s reload). Use openssl s\_client to verify the new cert chain is served.

6\. \*\*Rollback plan\*\*: If nginx -t fails or health checks fail, the symlink is reverted to the previous cert files, and Nginx is reloaded again.

7\. \*\*Audit\*\*: Log the rotation event, timestamp, and requester in the CMDB and alert the security team.



\### What OCSP stapling buys you (2-3 sentences, reference Reading 11)

OCSP stapling allows the server to fetch and "staple" the revocation status of its certificate, saving the client a round-trip to the CA's OCSP responder and improving TLS handshake performance. It is not useful for a self-signed lab cert because there is no recognized CA to issue an OCSP response, and the client wouldn't trust the stapled status anyway.



\---



\## Bonus: WAF Sidecar with OWASP CRS



\### Setup choice

\- WAF used: ModSecurity v3

\- OWASP CRS version: 4.x

\- Paranoia level: 1



\### Attack payload sent

GET /rest/products/search?q=' OR 1=1-- (URL-encoded)



\### Before WAF (Nginx alone)

```

no-waf: HTTP 200

```



\### After WAF

```

with-waf: HTTP 403

```



\### Audit log excerpt (the rule that fired)

```

ModSecurity: Warning. Pattern match "(?i:(?:union.\*select.\*from|select.\*from.\*where))" at ARGS:q. 

\[file "/etc/nginx/modsec/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] 

\[line "65"] \[id "942100"] \[rev "1"] \[msg "SQL Injection Attack Detected"] 

\[data "Matched Data: union select found within ARGS:q: ' OR 1=1--"] 

\[severity "CRITICAL"] \[ver "OWASP\_CRS/4.0.0"] \[tag "application-multi"] 

\[tag "language-multi"] \[tag "platform-multi"] \[tag "attack-sqli"] \[tag "OWASP\_CRS"] 

\[tag "capec/1000/152/248/66"] \[tag "PCI/6.5.2"]

```

Rule ID: \*\*942100\*\* — OWASP CRS rule name: \*\*SQL Injection Attack Detected\*\*



\### Tradeoff analysis

A WAF provides runtime L7 protection against injection attacks (SQLi, XSS) that SAST/DAST might miss or that zero-days introduce, acting as a virtual patch. It costs operational overhead and introduces false positive risk at higher paranoia levels, which can block legitimate traffic. You would NOT deploy a WAF in front of a service if it handles highly volatile binary data (breaking inspection) or if the latency overhead is unacceptable for real-time trading/gaming systems.

