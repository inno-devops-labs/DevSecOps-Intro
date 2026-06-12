# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`
- Host OS: REMnux (Ubuntu 20.04-based)
- Docker version: `Docker version 26.1.3, build 26.1.3-0ubuntu1~20.04.1`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no` (no `--restart` flag used)

### Health Check
- HTTP code on `/`: `200`
- API check (first 200 chars of `/api/Products`):
  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T10:31:40.266Z"
  ```
- Container uptime: 4bd57343c74b   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   14 minutes ago   Up 14 minutes   127.0.0.1:3000->3000/tcp   juice-shop

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes:  Login and Sign Up buttons present
- Product listing/search present: [x] Yes [ ] No — notes: Product cards displayed on homepage, search field available
- Admin or account area discoverable: [ ] Yes [x] No — notes: No direct admin link on landing page; authentication required
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: Console clean, no errors detected
- Pre-populated local storage / cookies: language (set to 'en'), token (empty until login)


### Security Headers (Quick Look)
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 10:31:40 GMT
ETag: W/"26af-19ebb633283"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 10:34:55 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy` - MISSING
- [x] `Strict-Transport-Security` - MISSING
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. Broken Access Control (A01) — The API endpoint /api/Products/<id>/reviews returns data without authentication. This allows an unauthenticated attacker to read other users' reviews and potentially exfiltrate data, violating the principle of least privilege.
2. Cryptographic Failures (A02) — Absence of the HSTS header and operation over HTTP (in local environment) means that in production traffic could be intercepted. If the application transmits credentials or tokens without TLS, this leads to sensitive data exposure.
3. Security Misconfiguration (A05) — The complete absence of CSP and HSTS indicates a default 'open' configuration. Combined with intentionally vulnerable Juice Shop code, this creates a broad surface for XSS, clickjacking, and MIME-sniffing attacks.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

### Actions Completed
- [x] Starred course repository
- [x] Starred [simple-container-com/api](https://github.com/simple-container-com/api)
- [x] Following Professor [@Cre-eD](https://github.com/Cre-eD)
- [x] Following TA [@Naghme98](https://github.com/Naghme98)
- [x] Following TA [@pierrepicaud](https://github.com/pierrepicaud)
- [x] Following 3+ classmates: `<, @username2, @username3>`

### Why Stars Matter in Open Source
Stars are the currency of attention in the open-source ecosystem. A repository with 1000+ stars attracts more contributors and sponsors than an equivalent one with 10 stars.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/raaller/DevSecOps-Intro/actions/runs/27413678469
- Workflow run duration: 27s
- Curl response excerpt:
  ```
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: *
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Feature-Policy: payment 'self'
  HTTP Status: 200
  ```
