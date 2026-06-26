# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Windows 11 (WSL 2.7.3.0)
- Docker version: 29.5.2

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [X] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`): `{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-08T16:32:53.569Z"`
- Container uptime: `About an hour`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [ ] Yes [X] No — notes: it's not on the main page, but "Login" is visible when I click "Account"
- Product listing/search present: [X] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [X] Yes [ ] No — notes: "Account" visible, "Admin" not visible
- Client-side errors in DevTools console: [X] Yes [ ] No — notes: One error
- Pre-populated local storage / cookies: None

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
`  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 08 Jun 2026 16:32:56 GMT
ETag: W/"26af-19ea8147f05"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 08 Jun 2026 17:59:54 GMT
Connection: keep-alive
Keep-Alive: timeout=5`

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
[X] Content-Security-Policy
[X] Strict-Transport-Security
[] X-Content-Type-Options: nosniff
[] X-Frame-Options

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. HTTP instead of HTTPS, lack of Strict-Transport-Security (A06: Security Misconfiguration). A hacker could intercept a user's traffic in a local network.
2. Lack of Content-Security-Policy (A04: Injection). A hacker could inject their own code onto the page through some parameters, and the browser will execute that code.
3. I pressed a button that required an account and saw a 401 error with a detailed description ("Parameter "key" is required and cannot be empty") in the console, before being prompted to log in. The error should be hidden from the user; otherwise, a hacker could try and guess the parameter "key". It is A05: Insecure Design.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title is clear (feat(labN): <topic> style); No secrets/large temp files committed; Submission file at submissions/labN.md exists
- Auto-fill verified: [ ] Yes — PR description showed my template. No, it didn't. I probably messed up with commits, but I don't know for sure what happened.