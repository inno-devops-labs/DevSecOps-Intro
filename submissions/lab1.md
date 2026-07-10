# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `Windows 11 25H2`
- Docker version: `28.3.0`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no`

### Health Check
- HTTP code on `/`: `200`
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T19:30:57.156Z"
  ```
- Container uptime: `Up 31 minutes`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Accessible from the topbar.
- Product listing/search present: [x] Yes [ ] No — notes: On the main page.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Although there doesn't seem to be a visible indication of an admin page a user can find, it can be discovered by analyzing code or bruteforcing. Access to the page is restricted without superuser privileges.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No errors present.
- Pre-populated local storage / cookies: Adds a cookie to store language preference on first load. Local storage was empty.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 19:31:00 GMT
ETag: W/"26af-19ebd50f802"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 20:22:37 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. Broken Access Control — Admin page is discoverable by any unauthorized user. Bruteforcing an admin's account credentials is enough to get full control over the shop. OWASP Top 10:2025 A01.
2. Security Misconfiguration — Missing security headers, vulnerable to client-side attacks such as Cross-Site Scripting. OWASP Top 10:2025 A05.
3. Injection — The responses seems to be taken directly from the database. If there are no server-side checks of user-input, the DB is vulnerable to SQL-injection. OWASP Top 10:2025 A04.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: 
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets/large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

Starring repositories helps increasing their popularity and shows what you're interested in to other people. Following other developers helps stay up to date with their activity and projects.