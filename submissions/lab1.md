# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS
- Docker version: Docker version 29.2.0, build 0b9d198

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes
- Container restart policy: default (`no`)

### Health Check
- HTTP code on `/`: 200
- Product count via `/api/Products`: 46 products returned
- Version check via `/rest/admin/application-version`: `{"version": "20.0.0"}`
- Container uptime:
NAMES        STATUS              PORTS
juice-shop   Up About a minute   127.0.0.1:3000->3000/tcp

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes — Account menu in top-right corner contains Login form with email/password fields, "Log in with Google" OAuth option, and "Not yet a customer?" registration link
- Product listing/search present: [x] Yes — 46 products displayed on homepage with search bar; product detail modal loads on click showing name, description, price
- Admin or account area discoverable: [x] Yes — `/rest/admin/application-version` endpoint publicly accessible without authentication, returns version info
- Client-side errors in DevTools console: [x] Yes — `ResizeObserver loop completed with undelivered notifications` (non-critical browser warning); pre-connections to `fonts.googleapis.com` and `fonts.gstatic.com`
- Pre-populated local storage / cookies: Local Storage is empty on first visit; cookie banner shown on load ("This website uses fruit cookies")
- Network requests observed: On product click — multiple XHR requests to `/api/Products/<id>/reviews` and `/api/Users/whoami` fired without authentication; WebSocket (`socket.io`) connection established on load

### Security Headers (Quick Look)
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Cache-Control: public, max-age=0
Content-Type: text/html; charset=UTF-8
Content-Length: 9903

Which of these are MISSING:
- [x] `Content-Security-Policy` — **MISSING** — no restriction on script sources, enables XSS escalation
- [x] `Strict-Transport-Security` — **MISSING** — no HSTS, allows downgrade to HTTP
- [ ] `X-Content-Type-Options: nosniff` — present ✅
- [ ] `X-Frame-Options` — present (SAMEORIGIN) ✅

Additional concern: `Access-Control-Allow-Origin: *` — wildcard CORS allows any origin to read API responses

### Top 3 Risks Observed

1. **Broken Access Control (A01:2025)** — The endpoint `/rest/admin/application-version` is publicly accessible without any authentication, exposing internal version information. Additionally, `/api/Users/whoami` and `/api/Products/<id>/reviews` return data to unauthenticated users. Access control checks are missing across multiple API endpoints, allowing anonymous users to interact with resources that should require authentication.

2. **Security Misconfiguration (A05:2025)** — The application is missing critical security headers: `Content-Security-Policy` is absent, leaving the app vulnerable to XSS without browser-level mitigation; `Strict-Transport-Security` is not set, allowing HTTP downgrade attacks. `Access-Control-Allow-Origin: *` is set globally, meaning any third-party origin can read API responses, creating significant data exposure risk.

3. **Injection (A03:2025)** — Juice Shop contains SQL injection vulnerabilities in its search and login endpoints. The search bar at `/rest/products/search?q=` passes user input into database queries without sufficient sanitisation. The login form is vulnerable to authentication bypass via SQL injection (e.g. entering `' OR 1=1--` as email). These issues can lead to full database compromise.

---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets/large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template on branch push

---

## GitHub Community

- Starred the course repository (`0xsmk/DevSecOps-Intro`) and the `simple-container-com/api` project
- Following professor (@Cre-eD), TAs (@Naghme98, @pierrepicaud)
- Following classmates: @Philip-78, @L10nff, @JoraXD

**Why starring repositories matters:** Stars act as public bookmarks that signal trust and popularity — a high star count helps the community discover quality projects, and starred repos appear in your GitHub profile showing your technical interests to potential collaborators and employers.

**Why following developers helps:** Following classmates and professors creates a lightweight activity feed of their public contributions, making it easy to discover new tools they use, spot collaboration opportunities, and stay aligned on course-related repositories throughout the semester.

---

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): _to be filled after PR is opened_
- Workflow run duration: _to be filled after PR is opened_
- Curl response excerpt:
HTTP 200
Smoke test passed — Juice Shop returned HTTP 200
