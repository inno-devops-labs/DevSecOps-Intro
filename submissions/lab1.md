# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `Microsoft Windows 11 Pro 10.0.26200`
- Docker version: `Docker version 29.2.0, build 0b9d198`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: `http://127.0.0.1:3000`
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no`

### Health Check

- HTTP code on `/`: `200`
- API endpoint used for product listing: `/api/Products`
- Product count from `/api/Products`: `46`
- Version endpoint response from `/rest/admin/application-version`:

```json
{"version":"20.0.0"}
```

- API check, first 200 chars of `/api/Products`:

```text
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T09:22:06.124Z"
```

- Container uptime/status: `Up 2 minutes`

### Initial Surface Snapshot

- Login/Registration visible: [x] Yes [ ] No — notes: Account menu is visible in the top-right area and exposes login/registration flow.
- Product listing/search present: [x] Yes [ ] No — notes: Product cards are visible on the landing page; the shop interface loads normally.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account-related area is discoverable from the UI. Admin functionality was not authenticated or accessed.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No blocking client-side errors were observed during basic loading and navigation.
- Pre-populated local storage / cookies: Browser storage exists for the application session after loading the page; no manual credentials were added.

### Security Headers

Command used:

```powershell
curl.exe -I http://127.0.0.1:3000
```

Output:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 09:22:06 GMT
ETag: W/"26af-19eb5fd2580"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 09:24:41 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Header quick look:

- Content-Security-Policy: `Missing`
- Strict-Transport-Security: `Missing`
- X-Content-Type-Options: nosniff: `Present`
- X-Frame-Options: `Present`

### Top 3 Risks Observed

1. **Security headers / hardening gaps — A02:2025 Security Misconfiguration.**  
   Missing or incomplete browser security headers can increase the impact of client-side attacks such as script injection or clickjacking. Even in a local lab, this is important because the same triage habit is used for real applications.

2. **Unauthenticated public attack surface — A01:2025 Broken Access Control.**  
   Product and review-related API calls are visible from browser traffic and can be reached without authentication for normal browsing. This does not automatically mean a vulnerability exists, but it marks an important area for later authorization testing.

3. **Input-heavy application flows — A05:2025 Injection / A07:2025 Authentication Failures.**  
   Login, registration, search, product review, and account flows are natural high-risk areas because they process user-controlled input and identity-related actions. These surfaces should be prioritized in later SAST/DAST labs.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear: `feat(labN): <topic>` style
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template. To be checked after opening the draft PR.

## GitHub Community

Starring repositories matters because it helps bookmark useful open-source projects and gives maintainers a visibility signal. Following developers helps track course-related work, discover useful repositories, and build professional collaboration habits.

## Bonus: CI Smoke Test

* Workflow file: `.github/workflows/lab1-smoke.yml`
* Trigger: `pull_request` on main and manual `workflow_dispatch`
* Run URL: https://github.com/m1d0rfeed/DevSecOps-Intro/actions/runs/27338466060/job/80768758602
* Workflow run duration: 17s
* Curl response excerpt:

```text
{"version":"20.0.0"}
Juice Shop is healthy

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Connection: keep-alive
Keep-Alive: timeout=5
```
