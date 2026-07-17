\# Lab 11 — BONUS — Submission



\## Task 1: TLS + Security Headers



\### nginx.conf (SSL + header sections)



```nginx

\# HTTP server (redirect to HTTPS)

server {

&#x20; listen 8080;

&#x20; listen \[::]:8080;

&#x20; server\_name \_;



&#x20; # Core headers (also on redirects)

&#x20; add\_header X-Frame-Options "DENY" always;

&#x20; add\_header X-Content-Type-Options "nosniff" always;

&#x20; add\_header Referrer-Policy "strict-origin-when-cross-origin" always;

&#x20; add\_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;

&#x20; add\_header Cross-Origin-Opener-Policy "same-origin" always;

&#x20; add\_header Cross-Origin-Resource-Policy "same-origin" always;

&#x20; add\_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;



&#x20; return 308 https://$host:8443$request\_uri;

}



\# HTTPS server

server {

&#x20; listen 8443 ssl;

&#x20; listen \[::]:8443 ssl;

&#x20; http2 on;

&#x20; server\_name \_;



&#x20; ssl\_certificate     /etc/nginx/certs/localhost.crt;

&#x20; ssl\_certificate\_key /etc/nginx/certs/localhost.key;

&#x20; ssl\_session\_timeout 10m;

&#x20; ssl\_session\_cache   shared:SSL:10m;

&#x20; ssl\_protocols TLSv1.3;

&#x20; ssl\_prefer\_server\_ciphers off;

&#x20; ssl\_ecdh\_curve X25519:secp384r1;

&#x20; ssl\_session\_tickets off;

&#x20; ssl\_stapling off;

&#x20; # If using a publicly-trusted certificate, you may enable OCSP stapling:

&#x20; # ssl\_stapling on;

&#x20; # ssl\_stapling\_verify on;

&#x20; # resolver 1.1.1.1 8.8.8.8 valid=300s;

&#x20; # resolver\_timeout 5s;

&#x20; # ssl\_trusted\_certificate /etc/ssl/certs/ca-certificates.crt;



&#x20; client\_max\_body\_size 2m;

&#x20; client\_body\_timeout 10s;

&#x20; client\_header\_timeout 10s;

&#x20; keepalive\_timeout 10s;

&#x20; send\_timeout 10s;



&#x20; # Security headers (include HSTS here only)

&#x20; add\_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

&#x20; add\_header X-Frame-Options "DENY" always;

&#x20; add\_header X-Content-Type-Options "nosniff" always;

&#x20; add\_header Referrer-Policy "strict-origin-when-cross-origin" always;

&#x20; add\_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;

&#x20; add\_header Cross-Origin-Opener-Policy "same-origin" always;

&#x20; add\_header Cross-Origin-Resource-Policy "same-origin" always;

&#x20; add\_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;



&#x20; location = /rest/user/login {

&#x20;   limit\_req zone=login burst=5 nodelay;

&#x20;   limit\_req\_log\_level warn;

&#x20;   proxy\_pass http://juice;

&#x20; }



&#x20; location / {

&#x20;   proxy\_pass http://juice;

&#x20; }

}

```



> Note: the starter config uses ports \*\*8080\*\* (HTTP) and \*\*8443\*\* (HTTPS) instead of 80/443 to avoid clashing with local services. All commands below and the acceptance-criteria proof use these ports.



\### A. HTTPS redirect proof

HTTP/1.1 308 Permanent Redirect

Server: nginx

Date: Fri, 17 Jul 2026 08:40:48 GMT

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



\### B. TLS 1.3 proof

Can't use SSL\_get\_servername

depth=0 CN=juice.local

verify error:num=18:self-signed certificate

CONNECTION ESTABLISHED

Protocol version: TLSv1.3

Ciphersuite: TLS\_AES\_256\_GCM\_SHA384

Peer certificate: CN=juice.local



\### C. Security headers proof (all 6 present)

HTTP/1.1 200 OK

Server: nginx

Date: Fri, 17 Jul 2026 08:40:55 GMT

Content-Type: text/html; charset=UTF-8

Content-Length: 9903

Connection: keep-alive

Feature-Policy: payment 'self'

X-Recruiting: /#/jobs

Accept-Ranges: bytes

Cache-Control: public, max-age=0

Last-Modified: Fri, 17 Jul 2026 08:40:28 GMT

ETag: W/"26af-19f6f3bf6ce"

Vary: Accept-Encoding

Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

X-Frame-Options: DENY

X-Content-Type-Options: nosniff

Referrer-Policy: strict-origin-when-cross-origin

Permissions-Policy: camera=(), geolocation=(), microphone=()

Cross-Origin-Opener-Policy: same-origin

Cross-Origin-Resource-Policy: same-origin

Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'



\### What each header defends against (1 sentence each)



\- \*\*HSTS\*\*: forces browsers to only ever connect over HTTPS for this host (and subdomains) for the given max-age, preventing SSL-stripping attacks on subsequent visits.

\- \*\*X-Content-Type-Options: nosniff\*\*: stops browsers from MIME-sniffing a response away from its declared Content-Type, which blocks a class of stored-XSS attacks that rely on the browser reinterpreting a file as HTML/JS.

\- \*\*X-Frame-Options: DENY\*\*: prevents the page from being embedded in an `<iframe>` on any origin, defeating clickjacking attacks.

\- \*\*Referrer-Policy\*\*: limits how much of the URL (path/query) is leaked to third-party sites via the `Referer` header when users click outbound links.

\- \*\*Permissions-Policy\*\*: explicitly disables sensitive browser APIs (camera, microphone, geolocation) for the page, reducing the attack surface if the app is ever compromised via XSS.

\- \*\*Content-Security-Policy\*\*: restricts which origins scripts, styles, and other resources may be loaded from, which is the primary browser-side defense against XSS payload execution.



\---



\## Task 2: Production Posture



\### Rate limit proof



| HTTP code | Count out of 60 |

|-----------|----------------:|

| 429 | 53 |

| 500 | 7 |



> The `500`s come from Juice Shop itself responding to a bare GET on `/rest/user/login` (no body), not from the rate limiter — the `limit\_req\_zone` (10 req/min, burst 5, `nodelay`) is clearly enforced: only 7 of 60 concurrent requests were let through to the upstream at all.



\### Timeout enforced



Testing over plain HTTP (port 8080) against a raw socket showed the connection stayed open \~20s+ without `client\_header\_timeout` visibly firing, because that directive is scoped to the HTTPS `server {}` block only, not the HTTP one. Repeating the test against the TLS port (8443) with an incomplete request line confirmed the fail-closed timeout works exactly as configured:

Elapsed: 10.01s

Server closed connection (EOF / graceful FIN) - TIMEOUT WORKED



This matches `client\_header\_timeout 10s;` in the `8443` server block.



\### Cipher hardening

Server Temp Key: X25519, 253 bits

New, TLSv1.3, Cipher is TLS\_AES\_256\_GCM\_SHA384



`ssl\_ecdh\_curve X25519:secp384r1;` and TLS 1.3's built-in AEAD cipher suites are confirmed in use (`TLS\_AES\_256\_GCM\_SHA384` negotiated, `X25519` used for key exchange). Note: an explicit `ssl\_ciphers` directive listing the TLS 1.3 suite names (`TLS\_AES\_128\_GCM\_SHA256:...`) was tried first but caused nginx to fail to start (`SSL\_CTX\_set\_cipher\_list ... no cipher match`) against this OpenSSL/nginx build — TLS 1.3 cipher suites are negotiated by nginx automatically and are not meant to be set via the legacy `ssl\_ciphers` directive, so that line was removed and only `ssl\_ecdh\_curve` / `ssl\_session\_tickets off` were kept.



\### Cert rotation runbook (7 steps)



1\. \*\*Detect expiry\*\*: monitor certificate `notAfter` via a scheduled job (`openssl x509 -enddate -noout -in localhost.crt`) or an external uptime/cert-monitoring service (e.g. cron + `check\_ssl\_cert`, or a hosted monitor) alerting 30/14/7 days before expiry.

2\. \*\*Order new cert\*\*: for a real domain, request a new certificate via ACME (Let's Encrypt / certbot) or the internal CA; for this lab, regenerate a new self-signed cert with `openssl req -x509 -newkey rsa:4096 ...`.

3\. \*\*Validate\*\*: verify the new cert's subject, SAN entries, expiry date, and chain (`openssl verify`, `openssl x509 -text -noout`) before deploying it anywhere.

4\. \*\*Atomic swap\*\*: write the new `.crt`/`.key` to a staging path, then atomically `mv` them into place over the paths nginx reads (`/etc/nginx/certs/localhost.crt`/`.key`), avoiding a window where only one of the two files is updated.

5\. \*\*Verify\*\*: reload nginx (`nginx -s reload`, or `docker compose restart nginx`) and re-run `openssl s\_client -connect host:443` plus `curl -vI` to confirm the new certificate (correct expiry/serial) is being served, with zero dropped connections.

6\. \*\*Rollback plan\*\*: keep the previous cert/key pair backed up until the new one is confirmed healthy in production traffic for a defined soak period; if validation fails, restore the old files and reload immediately.

7\. \*\*Audit\*\*: log who rotated the cert, when, old vs new serial/fingerprint, and the verification result, in the change-management/ops log for compliance traceability.



\### What OCSP stapling buys you



OCSP stapling lets nginx pre-fetch the certificate's revocation status from the CA and attach ("staple") it to the TLS handshake, so the client doesn't have to make its own separate OCSP request to the CA — this improves both privacy (the CA doesn't see every client visiting the site) and handshake latency/reliability. It only matters for \*\*publicly-trusted\*\* certificates, because OCSP validates a cert against a real CA's revocation database; a self-signed lab certificate has no CA-issued OCSP responder to staple a response from, so `ssl\_stapling` is documented here but left `off` and has no effect in this environment.



\---



\## Bonus: WAF Sidecar with OWASP CRS



\### Setup choice



\- \*\*WAF used\*\*: ModSecurity v3 (`owasp/modsecurity-crs:nginx-alpine` official image), per the lab's explicit guidance to use option (c).

\- \*\*OWASP CRS version\*\*: 3.3.10 (bundled with the `nginx-alpine` tag pulled).

\- \*\*Paranoia level\*\*: 1 (`BLOCKING\_PARANOIA: "1"`).

\- \*\*Rule engine\*\*: `MODSEC\_RULE\_ENGINE: "On"` (blocking, not detection-only).



\### Architecture



The WAF container proxies directly to the `juice` backend (`BACKEND: http://juice:3000`) on a separate host port (`9080`), running alongside the already-hardened Nginx stack from Task 1/2 (which stays on `8080`/`8443`). This keeps the Task 1+2 TLS/header work intact while cleanly demonstrating the WAF layer's added value, per the lab's own note that ModSecurity is the "gentler entry point" with richer CRS documentation compared to Coraza/Caddy.



\### Attack payload sent



`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)



\### Before WAF (Nginx alone, port 8443)

no-waf: HTTP 500



The request reached Juice Shop unfiltered; the app itself errored on the malformed SQL, but nothing blocked or inspected the payload in transit.



\### After WAF (port 9080)

with-waf: HTTP 403



\### Audit log excerpt (the rule that fired)

ModSecurity: Warning. detected SQLi using libinjection. \[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] \[line "46"] \[id "942100"] \[rev ""] \[msg "SQL Injection Attack Detected via libinjection"] \[data "Matched Data: s\&1c found within ARGS:q: ' OR 1=1--"] \[severity "2"] \[ver "OWASP\_CRS/3.3.10"] \[maturity "0"] \[accuracy "0"] \[tag "application-multi"] \[tag "language-multi"] \[tag "platform-multi"] \[tag "attack-sqli"] \[tag "paranoia-level/1"] \[tag "OWASP\_CRS"] \[tag "capec/1000/152/248/66"] \[tag "PCI/6.5.2"] \[hostname "localhost"] \[uri "/rest/products/search"] \[unique\_id "17842792517.909731"] \[ref "v28,10"]

ModSecurity: Access denied with code 403 (phase 2). Matched "Operator Ge' with parameter 5' against variable TX:ANOMALY\_SCORE' (Value: 5' ) \[file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] \[line "81"] \[id "949110"] \[rev ""] \[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] \[severity "2"] \[ver "OWASP\_CRS/3.3.10"] \[tag "modsecurity"] \[tag "attack-generic"] \[hostname "localhost"] \[uri "/rest/products/search"] \[unique\_id "17842792517.909731"]



Rule ID: \*\*942100\*\* — OWASP CRS rule name: \*\*SQL Injection Attack Detected via libinjection\*\* (with the request ultimately blocked by the anomaly-scoring rule \*\*949110\*\*, Inbound Anomaly Score Exceeded, once 942100's score of 5 crossed the paranoia-level-1 threshold).



\### Tradeoff analysis



A WAF buys \*\*runtime, payload-level inspection of live traffic\*\* — something SAST/DAST/Conftest gates from earlier in the pipeline cannot provide, since those tools scan source code, running test instances, or IaC manifests \*before\* deployment, not the actual production request stream. Even a codebase that passed every static/dynamic scan can still be hit by a novel or zero-day-style injection attempt in production; the WAF is the layer that can catch and block that attempt in real time without a code change or redeploy. The cost is real, though: at higher paranoia levels (3-4) false-positive rates climb sharply and can break legitimate traffic (the lab's own pitfalls section warns paranoia 4 "blocks everything"), the WAF is another stateful component to operate, patch, and monitor (plus another TLS/cert surface if terminating TLS itself), and every WAF exception/allow-rule written to fix a false positive is itself a small crack in the defense that needs review. A WAF is a poor fit — or at least not the first investment — for internal-only services with a small, trusted, already-authenticated client set where the traffic pattern is well understood and low-risk, for extremely latency-sensitive paths where the added inspection hop is unacceptable, or as a substitute for fixing the underlying vulnerability in code (it should complement, not replace, secure coding and the existing SAST/DAST gates).



\---



\## Cleanup



```bash

cd labs/lab11

docker compose -f docker-compose.yml -f waf/docker-compose.override.yml down

```

