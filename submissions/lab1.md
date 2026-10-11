# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0>
- Host OS: <Майкрософт Windows 11 Домашняя для одного языка>
- Docker version: <Docker version 28.3.0, build 38b7060>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check : 46
- Container uptime: Up 20 minutes

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Account (top right) -> Login -> Registration
- Product listing/search present: [x] Yes [ ] No — notes: products are located on the main page, the search bar is on the top of the page next to "Account"
- Admin or account area discoverable: [x] Yes [ ] No — notes: account area is accessible after logging in, admin should be available on /administration endpoint after logging on as admin
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: there was only "runtime.lastError: Could not establish connection"
- Pre-populated local storage / cookies: there were cookies in Application -> Cookies: `language`, `welcomebanner_status`, `cookieconsent_status` and`continueCode`

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000`. Paste output:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 16:53:01 GMT
ETag: W/"26af-19eb799f6d0"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 17:23:10 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Broken Access Control** — endpoints like `/api/Products/<id>/reviews`  and /basket reply without rights checking. Maps to **A01:2025 — Broken Access Control**.
2. **Security Misconfiguration** — Local Storage/JS has clues on how to exploit the system itself. Maps to **A06:2025 — Security Misconfiguration** 
3. **Cryptographic Failures** — HTTP is used instead of HTTPS. Maps to **A04:2025 — Cryptographic Failures**.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

Starring repositories lets me bookmark useful projects and quickly return to them later. It also acts as a signal of trust and popularity: stars increase a project's visibility and motivate maintainers. Starred repos show up on my profile, reflecting the kinds of work I care about in open source.

Following developers helps me see what classmates and instructors are working on, discover new projects through their activity, and stay updated on my classmates' work. This makes collaboration on team projects easier and helps me build professional connections beyond the classroom.