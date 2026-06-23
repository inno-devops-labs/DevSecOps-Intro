# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v20.0.0
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: macOS 15.7.1
- Docker version: Docker version 29.2.1, build a5c7197

### Deployment Details
- Run command used: docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no`

### Health Check
- HTTP code on /: HTTP 200
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T07:50:35.288Z"
  ```
- Container uptime:
```
 CONTAINER ID   IMAGE                           COMMAND                  CREATED         STATUS              PORTS                      NAMES
 bb50bda1c2c1   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   2 minutes ago   Up About a minute   127.0.0.1:3000->3000/tcp   juice-shop
```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Account menu is available in the top-right corner and provides Login options.
- Product listing/search present: [x] Yes [ ] No — notes: Product cards are displayed on the landing page and search functionality is available.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account-related functionality is discoverable through the Account menu in the user interface.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No client-side errors were observed during initial exploration.
- Pre-populated local storage / cookies:
  - Local Storage: empty
  - Session Storage: `itemTotal = 0`
  - Cookies:
    - `language = en`
    - `welcomebanner_status = dismiss`

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
Last-Modified: Fri, 12 Jun 2026 07:50:35 GMT
ETag: W/"26af-19ebacfb76b"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 07:51:56 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options'


### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. Missing Content Security Policy (CSP) — The application does not send a `Content-Security-Policy` header. Without CSP, browsers have fewer protections against malicious script execution and content injection attacks if an XSS vulnerability exists. This maps to OWASP Top 10:2025 A05 – Security Misconfiguration.

2. Missing HTTP Strict Transport Security (HSTS) — The `Strict-Transport-Security` header is not present in the response. HSTS helps ensure that browsers use HTTPS and prevents protocol downgrade attacks. This maps to OWASP Top 10:2025 A05 – Security Misconfiguration.

3. Publicly Accessible API Endpoints — Product information and related API endpoints are accessible without authentication, which increases the application's exposed attack surface. While public endpoints are expected for an online store, they should be carefully protected against unauthorized access, excessive data exposure, and business logic abuse. This maps primarily to OWASP Top 10:2025 A01 – Broken Access Control.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template 

## GitHub Community

- Starred course repository: [x] Yes
- Starred `simple-container-com/api`: [x] Yes
- Followed professor and TAs:
  - [x] `@Cre-eD`
  - [x] `@Naghme98`
  - [x] `@pierrepicaud`
- Followed at least 3 classmates: [x] Yes

Starring repositories matters because it helps useful open-source projects become more visible and signals community interest to maintainers. Following developers helps in team projects and professional growth because it makes it easier to track teammates' work, discover useful repositories, and learn from how other developers collaborate.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): `https://github.com/Esqavator/DevSecOps-Intro/actions/runs/27420024599/job/81042827263?pr=1`
- Workflow run duration: `17s`
- Curl response excerpt:

```text
{"version":"20.0.0"}
Juice Shop is ready
Homepage HTTP status: 200

## Submission Links

- PR to course repository: `https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1000`
- PR to my fork: `https://github.com/Esqavator/DevSecOps-Intro/pull/1`
