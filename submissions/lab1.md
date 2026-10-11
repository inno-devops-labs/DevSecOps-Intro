# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 — get from `docker inspect juice-shop --format '{{.Image}}'`>
- Host OS: <macOS 26.5.1>
- Docker version: <29.2.1>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: <default `no`>

### Health Check
- HTTP code on `/`: <HTTP 200>
- API check: {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-09T10:48:09.331Z"% 

- Container uptime: <Up 32 minutes>

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: <...>
- Product listing/search present: [x] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [x] Yes [ ] No — notes: <...>
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: <
:3000/rest/user/login:1 
 Failed to load resource: the server responded with a status of 401 (Unauthorized)
:3000/rest/user/login:1 
 Failed to load resource: the server responded with a status of 401 (Unauthorized)
:3000/rest/user/login:1 
 Failed to load resource: the server responded with a status of 401 (Unauthorized)>
- Pre-populated local storage / cookies: cookieconsent_status	dismiss	127.0.0.1	/	2027-06-09T10:50:23.000Z	27						Medium
language	ru_RU	127.0.0.1	/	2027-06-09T10:52:06.000Z	13						Medium
welcomebanner_status	dismiss	127.0.0.1	/	2027-06-09T10:50:16.000Z	27						Medium

### Security Headers (Quick Look)
- Run: curl -I http://127.0.0.1:3000 2>&1 | head -20. Paste output: 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 09 Jun 2026 10:48:09 GMT
ETag: W/"26af-19eabff34bc"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 09 Jun 2026 11:27:33 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

 - [x] Content-Security-Policy
 - [x] Strict-Transport-Security
 - [] X-Content-Type-Options: nosniff
 - [] X-Frame-Options

### Top 3 Risks Observed

1. Missing Content Security Policy

The application does not send a Content-Security-Policy header. Without CSP, the browser has fewer restrictions on loading and executing scripts, which can increase the impact of Cross-Site Scripting (XSS) vulnerabilities if they are discovered.

OWASP Top 10:2025 A05 Security Misconfiguration

2. Missing Strict-Transport-Security

The Strict-Transport-Security header is not present. HSTS helps ensure that browsers always use HTTPS connections and prevents downgrade attacks. Although this lab runs locally, missing HSTS would be a security concern in a production environment.

OWASP Top 10:2025 A05 Security Misconfiguration

3. Publicly Accessible API Endpoints

Several API endpoints, such as product listings and reviews, are accessible without authentication. While this may be intended for application functionality, publicly exposed endpoints increase the attack surface and provide information that could be useful during reconnaissance.

OWASP Top 10:2025 A01 Broken Access Control

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>`)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes

## GitHub Community

I starred the course repository and the simple-container-com/api project. I also followed the professor, teaching assistants, and several classmates.

Starring repositories helps increase project visibility, supports maintainers, and allows developers to bookmark useful projects for future reference. Following other developers helps discover new projects, stay informed about their work, and build professional connections that can be useful for collaboration and career growth.
