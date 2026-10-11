# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Windows 10
- Docker version: Docker version 29.5.3, build d1c06ef

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [X] Yes [ ] No
- Container restart policy: `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
```
{"data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T19:38:39.285Z","updatedAt":"2026-06-11T19:38:39.285Z","deletedAt":null}, ...]
```
- Number of products: 46
- Container uptime:
```
NAMES        STATUS
juice-shop   Up About an hour
```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [X] Yes [ ] No — notes: There is a "Login" button at the top right corner that redirects to the login/registration form.
- Product listing/search present: [X] Yes [ ] No — notes: 46 products are visible, and the search button at the top is available and works.
- Admin or account area discoverable: [X] Yes [ ] No — notes: `/administration` is available after logging in. If not authenticated, the page returns `403. You are not allowed to access this page!`. The `/rest/admin/application-version` endpoint returns `{"version":"20.0.0"}` without authentication.
- Client-side errors in DevTools console: [X] Yes [ ] No — notes: Browser console shows warnings and accessibility issues such as missing discernible button text and missing form labels; no critical JavaScript exception blocks the app.
- Pre-populated local storage / cookies: `welcomebanner_status`, `language`

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 19:38:43 GMT
ETag: W/"26af-19eb831ac26"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 21:12:03 GMT
Connection: keep-alive
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **No Content Security Policy** - The application does not include a `Content-Security-Policy` header and does not enforce `Strict-Transport-Security`. Without these protections, browser-based attacks may have a greater impact. This issue is related to **OWASP Top 10: Security Misconfiguration**.

2. **Discoverable Administrative Functionality** - The administration page can be identified through application routes, and the application version can be viewed without authentication. While access to the admin page is restricted, exposing this information may help an attacker gather details about the system. This is related to **Broken Access Control** and information disclosure.

3. **Publicly Accessible API Endpoints** - Product information and search functionality are available without authentication. This is expected for an online shop, but it also increases the exposed attack surface of the application. Proper input validation and access control are important to reduce potential risks related to **Injection** and **Security Misconfiguration**.

## PR Template Setup
- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — template file created, but GitHub did not auto-populate the draft PR because the template is not yet present in the base branch, which should not be modified.

## GitHub Community
- I starred the course repository and `simple-container-com/api`, and followed the professor, TAs, and classmates (Philip-78, RanisKhaertdinov, JoraXD). Stars help bookmark useful open-source projects and show support to maintainers, while following other developers helps me learn from their work and stay connected in team projects.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/Muratich/DevSecOps-Intro/actions/runs/27381865868/job/80920267728
- Workflow run duration: 19s
- Curl response excerpt:
```
{"version":"20.0.0"}
```
