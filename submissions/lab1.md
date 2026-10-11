# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Windows 11 with WSL2 (Ubuntu 24.04)
- Docker version: Docker version 29.5.3, build d1c06ef

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: <should be 200>
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T12:41:52.295Z"
  ```
- Container uptime: Up 31 minutes

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Accessible via the navigation bar under the "Account" dropdown.
- Product listing/search present: [x] Yes [ ] No — notes: The main landing page shows interactive item grid with a functional text search bar at the top.
- Admin or account area discoverable: [ ] Yes [x] No — notes: Navigating to `http://127.0.0.1:3000/#/administration` exposes a hidden, protected page and shows correct error hadling message.
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: Some standard web component rendering logs.
- Pre-populated local storage / cookies: In cookies found language presets (`language: en`),and there are banner close status (`welcomebanner_status: dismiss`), and dynamic UI token slots.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 12:41:53 GMT
ETag: W/"26af-19ebbda69e9"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 13:58:35 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Security Headers** — application fails to supply a `Content-Security-Policy` header in its responses. This maps directly to **A06:2021-Security Misconfiguration** and means the browser has no restrictions on where scripts can be loaded from or executed.
2. **Permissive Cross-Origin Information Sharing** — The backend API responses explicitly return the header `Access-Control-Allow-Origin: *`, allowing any external website or malicious script to read data from the application via the victim's browser. This falls under **A01:2021-Broken Access Control** because it completely bypasses the browser's Same-Origin Policy isolation boundary, exposing sensitive server responses to unauthorized things.
3. **Missing Strict-Transport-Security** — The server configuration does not issue an `HTTP Strict-Transport-Security` header to mandate encrypted communication channels. This corresponds to **A05:2021-Security Misconfiguration / Cryptographic Failures**, as it allows user sessions to be downgraded to unencrypted HTTP protocol formats.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (https://github.com/kvakz/DevSecOps-Intro/pull/2)

## GitHub Community

### Engagement Proof
- [x] Starred the main course repository
- [x] Starred the simple-container-com/api project
- [x] Followed the Professor (@Cre-eD) and TAs (@Naghme98, @pierrepicaud)
- [x] Followed at least 3 course classmates

### Analytical Summary
Starring repositories acts as an essential signal mechanism within open-source DevSecOps ecosystems. It allows engineers to flag and monitor critical tools, track community trust levels, and ensure visibility for secure code infrastructure. Following security researchers, professors, and teammates fosters collaborative professional growth, establishing automated feeds to observe modern code patterns, patch notifications, and peer-reviewed architectural developments.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/kvakz/DevSecOps-Intro/actions/runs/27427220435
- Workflow run duration: 25s
- Curl response excerpt:
  ```
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: *
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Feature-Policy: payment 'self'
  X-Recruiting: /#/jobs
  Content-Type: application/json; charset=utf-8
  Content-Length: 20
  ETag: W/"14-+EBpZnfu193JzIOBjXsY1+KveN8"
  Vary: Accept-Encoding
  Date: Fri, 12 Jun 2026 15:59:21 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5
  ```
