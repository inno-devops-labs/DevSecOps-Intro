# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`
- Host OS: `Ubuntu 24.04`
- Docker version: `29.1.3, build 29.1.3-0ubuntu3~24.04.2`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [X] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T17:40:54.708Z"
  ```
- Container uptime: Up 43 minutes


### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [X] Yes [ ] No — notes: In the account menu
- Product listing/search present: [X] Yes [ ] No — notes: On the main page
- Admin or account area discoverable: [X] Yes [ ] No — notes: Account menu in the top right
- Client-side errors in DevTools console: [ ] Yes [X] No — notes: no errors
- Pre-populated local storage / cookies: Empty, since it was my first time visiting the page

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
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
Last-Modified: Fri, 12 Jun 2026 17:40:55 GMT
ETag: W/"26af-19ebcec2e30"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 18:27:58 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Exposed API without rate limiting** — allows for the DDoS and brute-force attacks. OWASP A06:2025 - Insecure Design
2. **Missing Security Headers** — the website doesnt have CSP and STS, which allows for the XSS, clickjacking attacks. OWASP A02:2025, Security Misconfiguration
3. **Login without MFA** — no multi-factor authentication, OWASP A07:2025 - Authentication Faliures

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title clear / No secrets/large temp files / Submission file exists
- Auto-fill verified: [ ] Yes

## GitHub Community

Stars help me bookmark interesting projects for later reference and indicate project popularity. Following developers lets me see what theyre working on, discover new projects through their activity, and build professional connections for future collaboration in team projects.
