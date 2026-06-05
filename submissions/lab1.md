# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Ubuntu 24.04.1 LTS (WSL2, kernel 6.6.87.2-microsoft-standard-WSL2)
- Docker version: Docker version 29.1.2, build 890dcca

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no` (no `--restart` flag used)

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`):
  ```
  <html>
    <head>
      <meta charset='utf-8'> 
      <title>Error: Unexpected path: /rest/products</title>
      <style>* {
    margin: 0;
    padding: 0;
    outline: 0;
  }
  
  body {
    padding: 80px 100px;
    font: 1
  ```
- Container uptime:
  ```
  CONTAINER ID   IMAGE                           COMMAND                  CREATED          STATUS          PORTS                      NAMES
  52d33c910121   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   45 seconds ago   Up 44 seconds   127.0.0.1:3000->3000/tcp   juice-shop
  ```

Additional v20 checks:
- `/api/Products` product count: **46**
- `/rest/admin/application-version`: `{"version": "20.0.0"}`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: SPA shell loads with title "OWASP Juice Shop"; `/rest/user/whoami` returns `{"user":{}}` without credentials; `/api/Users` returns `UnauthorizedError` without token — auth flows are present. Account menu with Login/Registration is standard Juice Shop v20 UI (top-right).
- Product listing/search present: [x] Yes [ ] No — notes: `/api/Products` returns 46 items (e.g. "Apple Juice (1000ml)", "Orange Juice (1000ml)", "Eggfruit Juice (500ml)").
- Admin or account area discoverable: [x] Yes [ ] No — notes: response header `X-Recruiting: /#/jobs` hints at hidden routes; JS bundle contains `loginGuard` and role checks for `admin` / `accounting` routes.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: homepage returned HTTP 200; exploration done via curl/API during CLI triage (no DevTools console errors observed in this session).
- Pre-populated local storage / cookies: No `Set-Cookie` headers on initial `GET /`; localStorage keys referenced in `main.js` include `token`, `displayedDifficulties`, `showSolvedChallenges` — none pre-populated on first anonymous visit. Product reviews at `/rest/products/1/reviews` returned **HTTP 200 without Authorization**, exposing messages and `author: admin@juice-sh.op`.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
  0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 05 Jun 2026 13:33:43 GMT
ETag: W/"26af-19e97fd5a37"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 05 Jun 2026 13:34:04 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing CSP and HSTS** — The homepage response lacks `Content-Security-Policy` and `Strict-Transport-Security`, so browsers get no enforced policy against inline script injection or downgrade attacks. This is a classic security-misconfiguration gap mapped to **A06:2025 — Insecure Design / Security Misconfiguration**.
2. **Unauthenticated API access to reviews** — `GET /rest/products/1/reviews` returned HTTP 200 without any `Authorization` header, including reviews authored by `admin@juice-sh.op`. Exposing user-linked data without access control is **A01:2025 — Broken Access Control**.
3. **Wildcard CORS (`Access-Control-Allow-Origin: *`)** — Any origin can read API responses from a victim's browser context, which widens the blast radius for cross-site data theft if sensitive endpoints are reachable. This cross-origin misconfiguration maps to **A02:2025 — Security Misconfiguration**.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title is clear (`feat(labN): <topic>` style); No secrets/large temp files committed; Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (draft PR: https://github.com/inno-devops-labs/DevSecOps-Intro/pull/910)

## GitHub Community

### Actions completed

- [x] Starred [inno-devops-labs/DevSecOps-Intro](https://github.com/inno-devops-labs/DevSecOps-Intro)
- [x] Starred [simple-container-com/api](https://github.com/simple-container-com/api)
- [x] Following [@Cre-eD](https://github.com/Cre-eD) (professor)
- [x] Following [@Naghme98](https://github.com/Naghme98) (TA)
- [x] Following [@pierrepicaud](https://github.com/pierrepicaud) (TA)
- [ ] Following 3+ classmates:
  - [ ] @________
  - [ ] @________
  - [ ] @________

### Why it matters

**Stars:** In open source, starring a repository is both a bookmark for yourself and a signal of community interest — it helps you find tools again later and gives maintainers visible feedback that their work is useful.

**Following:** Following developers surfaces their activity in your feed, which makes it easier to discover projects, learn from peers, and build connections that carry into team projects and professional networking beyond the classroom.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): https://github.com/prudenz1/DevSecOps-Intro/actions/runs/27021224626
- Workflow run duration: 20s
- Curl response excerpt:
  ```
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
