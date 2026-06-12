\# Lab 1 — Submission



\## Triage Report: OWASP Juice Shop



\### Scope \& Asset



\* Asset: OWASP Juice Shop (local lab instance)

\* Image: `bkimminich/juice-shop:v20.0.0`

\* Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

\* Host OS: Windows 11

\* Docker version: `Docker version 29.5.3, build d1c06ef`



\### Deployment Details



\* Run command used:

&nbsp; `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`

\* Access URL: http://127.0.0.1:3000

\* Network exposure: 127.0.0.1 only? \[x] Yes \[ ] No

\* Container restart policy: `no`



\### Health Check



\* HTTP code on `/`: `HTTP 200`

\* API check: `/api/Products` returned a JSON product list successfully.

\* Application version:



```json

{"version":"20.0.0"}

```



\* Container uptime:



```text

CONTAINER ID   IMAGE                           COMMAND                  CREATED         STATUS         PORTS                      NAMES

c8698cd3f29f   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   2 minutes ago   Up 2 minutes   127.0.0.1:3000->3000/tcp   juice-shop

```



\### Initial Surface Snapshot



\* Login/Registration visible: \[x] Yes — Login is visible in the Account area.

\* Product listing/search present: \[x] Yes — Products are displayed on the main page.

\* Admin or account area discoverable: \[x] Yes — Account menu is visible in the top navigation area.

\* Client-side errors in DevTools console: \[ ] Yes \[x] No — no visible red console errors observed.

\* Pre-populated local storage / cookies: Local Storage for `http://127.0.0.1:3000` was empty during inspection.



\### Security Headers (Quick Look)



Run:



```bash

curl.exe -I http://127.0.0.1:3000

```



Output:



```text

HTTP/1.1 200 OK

Access-Control-Allow-Origin: \*

X-Content-Type-Options: nosniff

X-Frame-Options: SAMEORIGIN

Feature-Policy: payment 'self'

X-Recruiting: /#/jobs

Accept-Ranges: bytes

Cache-Control: public, max-age=0

Last-Modified: Fri, 12 Jun 2026 19:46:40 GMT

ETag: W/"26af-19ebd5f4f17"

Content-Type: text/html; charset=UTF-8

Content-Length: 9903

Vary: Accept-Encoding

Date: Fri, 12 Jun 2026 19:48:49 GMT

Connection: keep-alive

Keep-Alive: timeout=5

```



Which of these are MISSING?



\* \[x] `Content-Security-Policy`

\* \[x] `Strict-Transport-Security`

\* \[ ] `X-Content-Type-Options: nosniff`

\* \[ ] `X-Frame-Options`



\### Top 3 Risks Observed



\#### 1. Security Misconfiguration



The application does not return some common hardening headers such as Content-Security-Policy and Strict-Transport-Security. Missing security headers can weaken browser-side protections and increase the impact of other vulnerabilities. This maps to \*\*OWASP Top 10:2025 A06 – Security Misconfiguration\*\*.



\#### 2. Broken Access Control



The application exposes account-related functionality and user interaction features. Access-control weaknesses are one of the most common classes of vulnerabilities and could allow unauthorized actions if not properly implemented. This maps to \*\*OWASP Top 10:2025 A01 – Broken Access Control\*\*.



\#### 3. Injection Risk



The application provides multiple API endpoints and accepts user-controlled input. Since Juice Shop is intentionally vulnerable, injection-style attacks against search, authentication, and API functionality are realistic concerns. This maps to \*\*OWASP Top 10:2025 A04 – Injection\*\*.


## GitHub Community

I starred the course repository and the simple-container-com/api repository to keep track of useful open-source projects related to the course.

I followed the course instructor, teaching assistants, and several classmates to stay connected with the course community and observe collaborative development practices on GitHub.
