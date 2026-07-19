# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Windows 11 (WSL2, Ubuntu)
- Docker version: `Docker version 29.5.3`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: no (default — no `--restart` flag set)

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`): 
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T19:27:59.898Z"
  ```
- Container uptime: `Up 27 minutes`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: available via the Account menu in the top-right corner
- Product listing/search present: [x] Yes [ ] No — notes: homepage shows the product catalog with search
- Admin or account area discoverable: [x] Yes [ ] No — notes: account area present; admin panel reachable at route /#/administration
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: no errors in DevTools are present
- Pre-populated local storage / cookies: token is present in local storage, language, token and welcomebanner_status are present in cookies

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
Last-Modified: Fri, 12 Jun 2026 19:28:03 GMT
ETag: W/"26af-19ebd4e42e7"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 20:02:23 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing key security headers** — the server response lacks Content-Security-Policy and Strict-Transport-Security, so the browser does nothing to restrict injected scripts and does not enforce HTTPS. This opens the door to XSS and clickjacking. Category: **A02:2025 — Security Misconfiguration**.
2. **Weak access control over data via the API** — the app exposes objects by direct identifiers (baskets, reviews, profiles) without proper authorization checks, a classic IDOR. By substituting another user's id, an attacker can read or modify someone else's data. Category: **A01:2025 — Broken Access Control**.
3. **Weak authentication and open registration** — the login form is vulnerable to SQL injection (bypass like `' OR 1=1 --`), registration is open with no verification, and the password policy is weak. Together these allow authentication bypass and access to admin functions. Category: **A07:2025 — Authentication Failures** (overlapping A05 — Injection).

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title is clear / No secrets or large temp files / Submission file exists
- Auto-fill verified: [x] Yes — PR description showed my template (https://github.com/zeitrin/DevSecOps-Intro/pull/1)

## GitHub Community
Stars in open source act as bookmarks and as a trust signal at the same time: the more stars a project has, the higher its visibility and the easier it is for other developers to discover a useful tool. Following developers helps you track their activity, learn about new projects, and build professional connections — in team work this makes coordination and sharing of work easier.
