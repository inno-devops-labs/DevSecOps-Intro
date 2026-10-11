k# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`
- Host OS: Kali Linux (rolling)
- Docker version: 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes
- Container restart policy: default (`no`)

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T15:40:48.909Z"
  ```
- Container uptime: `juice-shop   Up 9 minutes   127.0.0.1:3000->3000/tcp`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes — Account menu (top-right) contains Login and Register forms accessible without authentication
- Product listing/search present: [x] Yes — 46 products returned via `/api/Products`; search bar functional on main page
- Admin or account area discoverable: [x] Yes — `/#/administration` accessible after login; `/rest/admin/application-version` returns version info with no auth required
- Client-side errors in DevTools console: [x] Yes — Angular routing errors observed on navigation to undefined paths
- Pre-populated local storage / cookies: No pre-populated items on first load; `cookieconsent_status` cookie written after cookie banner interaction; `welcomeBannerStatus` key added to localStorage on dismiss

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
Last-Modified: Fri, 12 Jun 2026 15:40:51 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Date: Fri, 12 Jun 2026 15:50:24 GMT
Connection: keep-alive
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy` — **MISSING**: no CSP header present, allowing unrestricted inline scripts and external resource loading
- [x] `Strict-Transport-Security` — **MISSING**: application runs over plain HTTP with no HSTS enforcement
- [ ] `X-Content-Type-Options: nosniff` — **present**
- [ ] `X-Frame-Options` — **present** (SAMEORIGIN)

### Top 3 Risks Observed

1. **Broken Access Control (A01:2025)** — The `/rest/admin/application-version` endpoint returns exact version information to any unauthenticated caller. This gives an attacker precise target intelligence to look up known CVEs for that specific release without needing any credentials, directly lowering the cost of exploitation.

2. **Security Misconfiguration (A05:2025)** — The `Access-Control-Allow-Origin: *` response header permits any web origin to read API responses via cross-origin requests. Combined with the absent `Content-Security-Policy`, a malicious page could silently exfiltrate product data, user sessions, or other API responses from a victim's browser session.

3. **Injection (A03:2025)** — The product search endpoint (`/rest/products/search?q=`) passes user input directly into SQL queries without sanitisation, making it vulnerable to SQL injection. A successful exploit could allow an attacker to read, modify, or delete any data in the underlying SQLite database, including user credentials and order history.

---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title follows `feat(labN): <topic>` convention
  - No secrets or large temp files committed
  - Submission file exists at `submissions/labN.md`
- Auto-fill verified: [ ] Yes — PR description showed the template automatically when the PR was opened from `feature/lab1`

---

## GitHub Community

Starring repositories signals to the maintainer that the project is useful and helps others discover quality tools through GitHub's trending and recommendation algorithms — it is the open-source equivalent of a citation. Following developers provides a live feed of their commits, new repositories, and activity, which is practical in team projects for staying aware of what colleagues are shipping and in professional growth for learning patterns and tooling from experienced engineers directly through their public work.

Actions completed:
- [x] Starred the course repository (`DevSecOps-Intro`)
- [x] Starred `simple-container-com/api`
- [x] Following professor @Cre-eD
- [x] Following TA @Naghme98
- [x] Following TA @pierrepicaud
- [x] Following 3+ classmates from the course

---

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): https://github.com/Wilikson173/DevSecOps-Intro/actions/runs/27428430062/job/81072211251
- Workflow run duration: ~23s
- Curl response excerpt:
  ```
  Homepage HTTP status: 200
  HTTP 200 confirmed — smoke test passed.
  ```
