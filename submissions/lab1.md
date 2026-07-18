# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest / image ID: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Arch Linux
- Docker version: `Docker version 29.5.1, build 2518b52d94`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: `no`

### Health Check
- HTTP code on `/`: 200
- Product count from `/api/Products`: 46
- Version check from `/rest/admin/application-version`: `{"version":"20.0.0"}`
- API check (first 200 chars of `/api/Products`):
  ```json
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T11:00:57.053Z"
  ```
- Container uptime:
  ```
NAMES        STATUS          PORTS
juice-shop   Up 10 minutes   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: visible through the Account menu; login and registration are reachable from the UI.
- Product listing/search present: [x] Yes [ ] No — notes: product cards are listed on the landing page; product data is also available through `/api/Products`.
- Admin or account area discoverable: [x] Yes [ ] No — notes: account functionality is visible from the top navigation; admin-related backend endpoint `/rest/admin/application-version` is reachable and exposes the application version.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: no blocking client-side errors were observed during initial load and product browsing.
- Pre-populated local storage / cookies: browser state contains normal Juice Shop client/UI state such as language or welcome/cookie-banner preferences; no user authentication token was present before login.
- Product detail network behavior: opening a product detail triggers API calls such as `/api/Products/<id>/reviews`; reading product/review data does not require authentication during initial browsing.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Output:
```
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0      0   0      0   0      0      0      0                              0  0   9903   0      0   0      0      0      0                              0  0   9903   0      0   0      0      0      0                              0  0   9903   0      0   0      0      0      0                              0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 11:00:57 GMT
ETag: W/"26af-19ebb7e0182"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 11:11:54 GMT
Connection: keep-alive
Keep-Alive: timeout=5

```

Which of these are MISSING?
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed
1. **Missing or incomplete browser hardening headers** — The initial header check shows that at least some defensive headers are absent or not explicitly configured. This matters because headers such as CSP, HSTS, X-Frame-Options, and X-Content-Type-Options reduce the impact of common browser-side attacks; this maps to OWASP Top 10:2025 A06 Security Misconfiguration.
2. **Discoverable unauthenticated API surface** — Product data and review-related endpoints are easy to discover from DevTools and can be queried directly. Even when public reads are intended, this increases the reconnaissance surface and should be reviewed for excessive data exposure or missing authorization boundaries; this maps to OWASP Top 10:2025 A01 Broken Access Control.
3. **Input-heavy application surface around login, registration, search, and product interaction** — The first exploration immediately exposes forms, account flows, and API-backed product functionality. These areas are common entry points for injection, authentication abuse, and validation mistakes, so they should be prioritized in later DAST/manual testing; this maps to OWASP Top 10:2025 A03 Injection and A07 Identification & Authentication Failures.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (PASTE_DRAFT_PR_URL_HERE_AFTER_PUSH)

## GitHub Community

I starred the course repository and `simple-container-com/api` because stars work both as bookmarks and as a public signal that helps useful open-source projects gain visibility. I also followed the professor, TAs, and classmates because following developers makes it easier to track course activity, discover related projects, and build professional connections for future teamwork.

Completed actions:
- [x] Starred the course repository
- [x] Starred `simple-container-com/api`
- [x] Followed @Cre-eD
- [x] Followed @Naghme98
- [x] Followed @pierrepicaud
- [x] Followed at least 3 classmates from the course

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (green): PASTE_GREEN_ACTIONS_RUN_URL_HERE_AFTER_PR
- Workflow run duration: PASTE_WORKFLOW_DURATION_HERE
- Curl response excerpt:
  ```
HTTP/1.1 200 OK / Homepage HTTP status: 200
  ```
