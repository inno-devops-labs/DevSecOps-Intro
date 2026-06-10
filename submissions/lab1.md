# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0>
- Host OS: <Windows 11>
- Docker version: <Docker version 28.3.0, build 38b7060>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: <default `no`>

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/products`): {
    "status":  "success",
    "data":  [
                 "@{id=1; name=Apple Juice (1000ml); description=The all-time classic.; price=1.99; deluxePrice=0.99; image=apple_juice.jpg; createdAt=202

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No
- Product listing/search present: [x] Yes [ ] No
- Admin or account area discoverable: [x] Yes [ ] No
- Client-side errors in DevTools console: [ ] Yes [x] No
- Pre-populated local storage / cookies: empty

### Security Headers (Quick Look)

Instead of 'curl -I http://127.0.0.1:3000 2>&1 | head -20' I used 'curl.exe -I http://127.0.0.1:3000 2>&1 | Select-Object -First 20'

Output: curl.exe :   % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
строка:1 знак:1
+ curl.exe -I http://127.0.0.1:3000 2>&1 | Select-Object -First 20
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (  % Total    % ... Time   Current:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

                                 Dload  Upload  Total   Spent   Left   Speed
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 14:54:42 GMT
ETag: W/"26af-19eb20747ca"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 15:19:40 GMT
Connection: keep-alive
Keep-Alive: timeout=5 


- Which of these are MISSING?
  - [x] `Content-Security-Policy`
  - [x] `Strict-Transport-Security`
  - [ ] `X-Content-Type-Options: nosniff` (этот есть)
  - [ ] `X-Frame-Options`

### Top 3 Risks Observed
1. **Missing Content-Security-Policy (CSP)** — Without CSP, the browser has no restrictions on script sources, styles, or other resources. This leaves the application vulnerable to XSS attacks: an attacker can inject a malicious script through an input field, and the browser will execute it without restriction. (OWASP Top 10:2025 — A06: Security Misconfiguration)

2. **Missing Strict-Transport-Security (HSTS)** — Without HSTS, the browser is not forced to use HTTPS. An attacker can perform a downgrade attack and intercept user traffic. Even if HTTPS is configured on the server, the initial request may be sent over plain HTTP. (OWASP Top 10:2025 — A02: Cryptographic Failures)

3. **Admin endpoint exposes version without authentication** — The `/rest/admin/application-version` endpoint returns the exact application version to any unauthenticated user. This facilitates reconnaissance: an attacker can look up known vulnerabilities for the specific version. (OWASP Top 10:2025 — A01: Broken Access Control)


## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)


## GitHub community
* Why starring repositories matters in open source: tars increase an open-source project's visibility in GitHub search results and signal community trust. A higher star count often correlates with project maturity and adoption. Starring a repository also bookmarks it for future reference and displays it on one's GitHub profile, indicating personal interests and areas of expertise.
* How following developers helps in team projects and professional growth: Following developers surfaces their public activity in the GitHub feed — repositories they create, fork, and star. This enables discovery of new tools and workflows, facilitates learning from more experienced developers, and helps build a professional network. Within the course context, following classmates simplifies collaboration and mutual support. Professionally, a well-curated GitHub network can lead to job referrals and collaborative opportunities.


## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL: (ссылка появится после того, как создадите PR)
- Workflow run duration: (посмотрите в GitHub Actions после запуска)
- Curl response excerpt:

⏳ Waiting for Juice Shop to start...
✅ Juice Shop is ready!
Found ~46 products

