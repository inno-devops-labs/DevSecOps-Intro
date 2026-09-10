# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Windows 11
- Docker version: Docker version 29.2.1, build a5c7197

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No 
- Container restart policy: default `no` (we didn't use `--restart` flag)

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`): {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-09T18:28:05.316Z","updatedAt":"2026-06-09T18:28:05.316Z","deletedAt":null},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange_juice.jpg","createdAt":"2026-06-09T18:28:05.316Z","updatedAt":"2026-06-09T18:28:05.316Z","deletedAt":null}
- Container uptime: Up 29 minutes

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes — notes: Icon in top-right corner, opens a modal.
- Product listing/search present: [x] Yes — notes: Grid of products, search bar at the top.
- Admin or account area discoverable: [x] Yes — notes: "Account" menu in top-right, "Administration" link is hidden but can be found in source code.
- Client-side errors in DevTools console: [ ] Yes — notes: No critical errors on initial load.
- Pre-populated local storage / cookies: Yes, `token` (JWT), `bid` (basket ID), and language preferences are stored in Local Storage.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000`
Output:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 09 Jun 2026 18:28:06 GMT
ETag: W/"26af-19eada44b5c"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 09 Jun 2026 18:57:52 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Which of these are MISSING? 
- [x] Content-Security-Policy (CSP)
- [x] Strict-Transport-Security (HSTS)
- [ ] X-Content-Type-Options: nosniff (Usually present in Juice Shop)
- [ ] X-Frame-Options

### Top 3 Risks Observed
1. **Missing Strict-Transport-Security (HSTS):** The application is served over plain HTTP locally. If deployed in production without HSTS, it is vulnerable to Man-in-the-Middle (MitM) attacks where an attacker can downgrade connections. *Maps to OWASP A02: Cryptographic Failures.*
2. **Unauthenticated API Endpoints:** The `/api/Products/<id>/reviews` endpoint can be accessed without any authentication token. This exposes internal data structures and could allow attackers to scrape data or attempt injection attacks without needing a user session. *Maps to OWASP A01: Broken Access Control.*
3. **Sensitive Data in Client-Side Storage:** The application stores a JWT `token` and basket ID (`bid`) in the browser's Local Storage. If the application has an XSS (Cross-Site Scripting) vulnerability, an attacker can easily steal these tokens via JavaScript. *Maps to OWASP A03: Injection (leading to Session Hijacking) or A05: Security Misconfiguration.*
## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title format, No secrets, Submission file exists
- Auto-fill verified:
- [x] Yes — PR description showed my template when I opened the draft PR.

## GitHub Community

- **Why starring repositories matters in open source:** Starring acts as a bookmark for useful tools and shows appreciation to maintainers, helping them gauge the project's impact and popularity within the community.
- **How following developers helps in team projects and professional growth:** Following team members and industry experts allows you to track their contributions, discover new repositories they star, and stay updated on best practices and emerging technologies in real-time.
- testing

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/alileeeek/DevSecOps-Intro-1/actions/runs/27268726593
- Workflow run duration: 20s
- Curl response excerpt:
```text
{"version":"20.0.0"}Juice Shop is up and healthy!
