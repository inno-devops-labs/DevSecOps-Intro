# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

* Asset: OWASP Juice Shop (local lab instance)
* Image: `bkimminich/juice-shop:v20.0.0`
* Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
* Host OS: Arch Linux, Linux 7.0.10-arch1-1, x86_64
* Docker version: 29.5.2

### Deployment Details

* Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
* Access URL: `http://127.0.0.1:3000`
* Network exposure: 127.0.0.1 only — Yes
* Container restart policy: No
* Container ID: `c9c3a6b9fff6`
* Container status: `Up 24 minutes`
* Port mapping: `127.0.0.1:3000->3000/tcp`

### Health Check

* HTTP code on `/`: `200`
* Application version: `{"version":"20.0.0"}`
* Product count: `46`
* Docker status:

```text
c9c3a6b9fff6   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   24 minutes ago   Up 24 minutes   127.0.0.1:3000->3000/tcp   juice-shop
```

### Initial Surface Snapshot (from browser exploration)

* Login/Registration visible: Yes
* Product listing/search present: Yes
* Admin or account area discoverable: Yes
* Client-side errors in DevTools console: No
* Pre-populated local storage / cookies: Before authentication, Local Storage for `http://127.0.0.1:3000` was empty. Cookies were present: `continueCode`, `language=en`, and `welcomebanner_status=dismiss`. After registration/login, a `token` value appeared in both Local Storage and Cookies; the token value was redacted because it is an authentication token.
* Network/API surface: Product and review API requests were visible in the browser Network tab during normal browsing.

### Security Headers (Quick Look)

Run:

```bash
curl -sI http://127.0.0.1:3000 | head -20
```

Observed response:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 10 Sep 2026 10:27:35 GMT
ETag: W/"26af-1a08adbcadf"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 10 Sep 2026 10:34:17 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING?

* [x] `Content-Security-Policy`
* [x] `Strict-Transport-Security`
* [ ] `X-Content-Type-Options: nosniff`
* [ ] `X-Frame-Options: SAMEORIGIN`

Missing security headers are mapped to OWASP Top 10:2025 **A02 — Security Misconfiguration**.

### Top 3 Risks Observed

1. **Authentication token stored client-side** — After registration/login, an authentication token appeared in both Local Storage and Cookies. This makes client-side token storage part of the application's security surface and should be reviewed for token protection, lifetime, and handling. This maps to OWASP Top 10:2025 **A07 — Authentication Failures**.

2. **Missing security headers** — The initial HTTP response does not include `Content-Security-Policy` or `Strict-Transport-Security`. This represents a security configuration issue and reduces the browser-level security controls applied to the application. This maps to OWASP Top 10:2025 **A02 — Security Misconfiguration**.

3. **Public product and review API surface** — Product and review API endpoints are visible in the browser Network tab during normal browsing. Their authorization boundaries should be tested to determine whether users can access or modify resources they should not be allowed to access. This maps to OWASP Top 10:2025 **A01 — Broken Access Control**.


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