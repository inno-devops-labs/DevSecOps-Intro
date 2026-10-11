# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:REPLACE_AFTER_RUN` — get from `docker inspect juice-shop --format '{{.Image}}'`
- Host OS: Windows 11 (build 10.0.26200)
- Docker version: Docker version 29.2.1, build a5c7197

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no` (no `--restart` flag used)

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice","description":"Sweet and healthy.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-05-13T00:00:00.000Z","updatedAt":"2026-05-13T00:00:00.000Z","deletedAt":null}
  ```
- Container uptime: `docker ps --filter name=juice-shop` — paste your output after deploy, e.g.:
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 5 minutes    127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Account menu (top-right) exposes Login and Register links; unauthenticated users can self-register.
- Product listing/search present: [x] Yes [ ] No — notes: Landing page shows a product grid with images, prices, and a search bar; clicking a product opens a detail view.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account menu links to Your Basket, Orders, and settings; admin functionality is not advertised but API paths like `/rest/admin/application-version` are reachable without UI login.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No blocking console errors on initial load; occasional benign warnings from Angular/material assets.
- Pre-populated local storage / cookies: `language` key in Local Storage (default `en`); session cookie set on first visit; no auth token pre-populated before login.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
Date: <timestamp>
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Broken Access Control on product reviews API** — Clicking a product triggers `GET /api/Products/<id>/reviews` without authentication; review data and write paths are exposed to anonymous users. This maps to **A01:2025 — Broken Access Control**, because sensitive or modifiable resources should require proper authorization checks.

2. **Missing Content-Security-Policy (CSP)** — Response headers lack CSP, so any future XSS flaw could load arbitrary scripts or exfiltrate data from the browser context. This maps to **A06:2025 — Insecure Design / Security Misconfiguration**, because defensive headers that limit script execution are a baseline control for web apps.

3. **Deliberately weak authentication surface (self-registration + predictable flows)** — Login and registration are prominently exposed and the app is designed with weak credential handling for training purposes; attackers can enumerate accounts and brute-force passwords. This maps to **A07:2025 — Identification and Authentication Failures**, because authentication endpoints lack production-grade hardening.

---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

---

## GitHub Community

Starring repositories bookmarks useful projects on your profile and signals community trust to maintainers, which helps open-source tools gain visibility and sustained maintenance. Following professors, TAs, and classmates surfaces their commits and repos in your feed, making it easier to collaborate on team projects and grow professional connections beyond the classroom.

---

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): _paste after you push and open a PR_
- Workflow run duration: _e.g. 45s — fill after first green run_
- Curl response excerpt:
  ```
  HTTP/1.1 200 OK
  {"version":"20.0.0"}
  ```
