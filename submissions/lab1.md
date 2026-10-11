# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: macOS 26.5.1
- Docker version: Docker version 29.2.1, build a5c7197

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [X] Yes [ ] No
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T10:50:09.594Z", ...
  ```
- Number of products: 46
- Container uptime:
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 29 minutes   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [X] Yes [ ] No — notes: Login and registration are available from the Account menu in the top-right area.
- Product listing/search present: [X] Yes [ ] No — notes: The homepage shows a product catalog with multiple juice shop items and a search field.
- Admin or account area discoverable: [ ] Yes [X] No — notes: Account menu is visible, but no admin area was directly visible before login.
- Client-side errors in DevTools console: [ ] Yes [X] No — notes: No runtime errors were observed in the Console. DevTools Issues showed form/accessibility warnings such as missing form field labels or autocomplete attributes, plus one browser cookie/navigation warning.
- Pre-populated local storage / cookies: `loglevel: DEBUG` was present in local storage. Cookies included `cookieconsent_status=dismiss`, `language=en`, and `welcomebanner_status=dismiss`; no authentication token was present before login.

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
Last-Modified: Fri, 12 Jun 2026 10:50:09 GMT
ETag: W/"26af-19ebb741e2b"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 11:09:06 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Content Security Policy** — The response does not include a `Content-Security-Policy` header, so the browser has fewer restrictions on where scripts and other resources may load from. This increases the impact of possible XSS issues and maps to OWASP Top 10:2025 A06 Security Misconfiguration.

2. **Missing HSTS** — The response does not include `Strict-Transport-Security`, so a production deployment over HTTPS would not instruct browsers to force secure connections. This is acceptable for a local HTTP lab, but would be a security misconfiguration in production, mapping to A06 Security Misconfiguration.

3. **Public unauthenticated API surface** — Product and review endpoints are visible from browser network traffic and can be queried without logging in. Public product data may be expected, but exposed APIs should be reviewed carefully for broken access control and excessive data exposure; this maps to A01 Broken Access Control.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [X] Yes — Auto-fill did not trigger on this first PR because `.github/PULL_REQUEST_TEMPLATE.md` is introduced by the same PR and is not yet present in `main`.

## GitHub Community

- Followed `@Cre-eD`, `@Naghme98`, `@pierrepicaud`
- Followed classmates `@stikking`, `@Muratich`, `@Nik-ari-ai`
- Starred course repo and simple-container-com/api

Starring repositories matters in open source because it bookmarks useful projects, supports their visibility, and signals community interest to future users. Following the professor, TAs, and classmates helps track course-related work, discover useful examples, and build professional connections for future collaboration.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL: https://github.com/wyroxx/DevSecOps-Intro/actions/runs/27414596512
- Workflow run duration: 20s
- Curl response excerpt:
  ```
  Run curl -sI http://127.0.0.1:3000 | head -20
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 12:06:39 GMT
ETag: W/"26af-19ebbba2516"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 12:06:39 GMT
Connection: keep-alive
Keep-Alive: timeout=5

  ```
