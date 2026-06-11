# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Arch Linux, Linux 7.0.10-arch1-1, x86_64
- Docker version: 29.5.2

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? Yes
- Container restart policy: No

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`): {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-10T21:37:17.403Z"
- Container uptime: 12 hours

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: Yes
- Product listing/search present: Yes
- Admin or account area discoverable: Yes
- Client-side errors in DevTools console: No
- Pre-populated local storage / cookies: Before authentication, Local Storage for `http://127.0.0.1:3000` was empty. Cookies were present: `continueCode`, `language=en`, and `welcomebanner_status=dismiss`. After registration/login, a `token` value appeared in both Local Storage and Cookies; the token value was redacted because it is an authentication token.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```  
% Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0   9903   0      0   0      0      0      0                              0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 21:37:19 GMT
ETag: W/"26af-19eb377e2a7"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 09:25:54 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Authentication token stored client-side** — After registration/login, a JWT-like `token` appeared in both Local Storage and Cookies. This matters because tokens stored in browser-accessible storage can become high-value targets. This maps to OWASP Top 10:2025 A07 — Identification & Authentication Failures.
2. **Missing security headers** — The initial HTTP response does not include several browser security headers. This matters because the browser receives fewer built-in protections against attacks. This maps to OWASP Top 10:2025 A06
3. **Public product and review API surface** — Product data and review-related API calls are visible from the browser Network tab during normal browsing. It expands the attack surface and should be tested later for missing authorization checks, unauthorized data access, and unsafe input handling. This maps to OWASP Top 10:2025 A01 — Broken Access Control.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] No — the template file exists at `.github/PULL_REQUEST_TEMPLATE.md`, but it did not auto-fill for the first PR because this PR introduces the template itself. The PR body was filled manually using the same template structure.

## GitHub Community

Starring repositories matters in open source because it helps make useful projects more visible and also lets me quickly find them later. Following developers is useful for team projects and professional growth because it helps me track their public work, learn from their activity, and stay connected with people from the course.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): https://github.com/Troshkins/DevSecOps-Intro/actions/runs/27350872180
- Workflow run duration: 21s
- Curl response excerpt: 
Waiting for Juice Shop... attempt 1/30
{"version":"20.0.0"}
Juice Shop version endpoint is healthy
0s
Homepage returned HTTP 200
