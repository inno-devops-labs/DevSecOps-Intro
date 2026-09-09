# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS (Docker Desktop)
- Docker version: Docker version 28.2.2, build e6534b4

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no` (no `--restart` flag passed)

### Health Check
- HTTP code on `/`: 200
- API check (`/api/Products` — `/rest/products` was removed in v20.0.0):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T15:59:01.274Z"
  ```
  Product count (`jq '.data | length'`): 46
  Version (`/rest/admin/application-version`): {"version":"20.0.0"}
- Container uptime: `juice-shop   Up 20 seconds   127.0.0.1:3000->3000/tcp`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes — Account menu (top-right) exposes Login and "Not yet a customer?" registration.
- Product listing/search present: [x] Yes — product grid loads on landing page; search box in the top bar queries `/rest/products/search`.
- Admin or account area discoverable: [x] Yes — `#/administration` route exists; gated by auth, but the route itself is reachable client-side.
- Client-side errors in DevTools console: [ ] Yes [x] No — clean on normal load (verify on your run).
- Pre-populated local storage / cookies: cookies `language`, `welcomebanner_status`, `cookieconsent_status`; after registering/login a JWT `token` and basket id (`bid`) appear in storage. The JWT is base64-decodable client-side.

### Security Headers (Quick Look)
`curl -I http://127.0.0.1:3000 2>&1 | head -20`:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 15:59:02 GMT
ETag: W/"26af-19ebc8ee853"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 15:59:19 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Missing (maps to **Security Misconfiguration — A02:2025**):
- [x] `Content-Security-Policy` — absent
- [x] `Strict-Transport-Security` — absent (served over plain HTTP)
- [ ] `X-Content-Type-Options: nosniff` — present
- [ ] `X-Frame-Options` — present (`SAMEORIGIN`)

> Also observed: `Access-Control-Allow-Origin: *` (permissive CORS) and `X-Recruiting` / `Feature-Policy` headers that disclose framework/easter-egg info.

### Top 3 Risks Observed
1. **Broken Access Control (A01:2025)** — Juice Shop exposes REST endpoints (product reviews, basket, feedback) without proper authorization and addresses objects via sequential numeric IDs (e.g. `/api/Products/<id>`). This enables IDOR and horizontal access to data and actions that should be restricted. It is the highest-impact class because it hands an attacker resources outside their privilege level.
2. **Security Misconfiguration (A02:2025)** — The app ships without a Content-Security-Policy and without HSTS, and is served over plain HTTP, so there is no defence-in-depth against injected scripts and no enforced transport encryption. It also returns `Access-Control-Allow-Origin: *` (permissive CORS) and discloses its exact build via `/rest/admin/application-version`, aiding cross-origin abuse and fingerprinting.
3. **Injection (A05:2025)** — The login flow is SQL-injectable: supplying `' OR 1=1--` in the email field bypasses authentication. Injection stays high-severity because it can compromise the entire data layer (auth bypass, data exfiltration).

---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: clear title (`feat(labN): <topic>`) · no secrets/large temp files committed · `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — template committed at `.github/PULL_REQUEST_TEMPLATE.md` and used as the PR body (see PR #1013)

---

## GitHub Community

Starred the course repo and `simple-container-com/api`, and followed the professor (@Cre-eD), TAs (@Naghme98, @pierrepicaud), and 3+ classmates. Starring bookmarks useful projects and signals trust/popularity to maintainers, while following classmates and instructors surfaces their activity and makes future team collaboration and discovery easier.

---

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/Slash228/DevSecOps-Intro/actions/runs/27428879358
- Workflow run duration: 20s
- Curl response excerpt:
  ```
  Juice Shop healthy after 4s
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
  Date: Fri, 12 Jun 2026 16:30:00 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5
  {"version":"20.0.0"}
  ```
