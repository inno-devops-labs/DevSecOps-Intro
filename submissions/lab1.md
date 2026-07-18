# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9`
- Host OS: macOS Tahoe 26.2 (25C56)
- Docker version: Docker version 27.x (run `docker --version` and update)

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default (`no` — no `--restart` flag was passed)

### Health Check
- HTTP code on `/`: 200
- API check (`/api/Products` product count): 46 products returned
- Container uptime:
  ```
  NAMES        STATUS         PORTS
  juice-shop   Up 6 minutes   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Login and Register options available under the Account menu (top-right corner)
- Product listing/search present: [x] Yes [ ] No — notes: Homepage displays product catalog with search functionality
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account menu visible in top-right; admin panel discoverable via navigation
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: Console is clean, no red errors observed
- Pre-populated local storage / cookies: None — Local Storage is empty on first load before any login

### Security Headers (Quick Look)

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 09 Jun 2026 22:29:50 GMT
ETag: W/"26af-19eae819e8a"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 09 Jun 2026 22:35:57 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING?
- [x] `Content-Security-Policy` — **MISSING**
- [x] `Strict-Transport-Security` — **MISSING**
- [ ] `X-Content-Type-Options: nosniff` — present
- [ ] `X-Frame-Options` — present (SAMEORIGIN)

### Top 3 Risks Observed

1. **Missing Content-Security-Policy (CSP)** — The absence of a CSP header means the browser will execute any inline scripts or load resources from any origin without restriction. This makes the application highly susceptible to Cross-Site Scripting (XSS) attacks, where an attacker can inject malicious scripts that run in a victim's browser. Maps to **A03:2025 – Injection**.

2. **Wildcard CORS (`Access-Control-Allow-Origin: *`)** — The server allows any external origin to make cross-origin requests to the API. A malicious website could send requests to Juice Shop on behalf of a logged-in user and read the responses, potentially leaking sensitive data such as user information or order history. Maps to **A01:2025 – Broken Access Control**.

3. **Missing Strict-Transport-Security (HSTS)** — Without HSTS, the application does not instruct browsers to enforce HTTPS connections. This leaves the app vulnerable to protocol downgrade attacks and man-in-the-middle interception where an attacker on the same network could intercept traffic in plaintext. Maps to **A02:2025 – Cryptographic Failures**.


## GitHub Community

- Starred: `juice-shop/juice-shop` and `simple-container-com/api`
- Following: Cre-eD, Naghme98, pierrepicaud, cQu1x, ARCshekin, joraXD, 0xsmk

Stars help bookmark useful projects and signal community trust to maintainers —
a high star count is often the first thing engineers check before adopting an
open-source tool. Following teammates and professors surfaces their activity in
your GitHub feed, which is a real habit in DevSecOps teams where you want
visibility into what libraries or tools your colleagues are evaluating.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- PR URL: https://github.com/inno-devops-labs/DevSecOps-Intro/pull/934
- Note: Checks tab shows 0 — Actions may be disabled for fork PRs on this repo
