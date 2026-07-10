# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9
- Host OS: macOS 26.3.1
- Docker version: Docker version 28.1.1, build 4eba377

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/api/Products`):
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
  Dload  Upload   Total   Spent    Left  Speed
  100 16011  100 16011    0     0   417k      0 --:--:-- --:--:-- --:--:--  422k
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T12:16:31.991Z"%
- Container uptime: ac0948a01f25   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   24 minutes ago   Up 24 minutes   127.0.0.1:3000->3000/tcp   juice-shop

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Login and registration options are accessible
- Product listing/search present: [x] Yes [ ] No — notes: catalog and search functionality are visible
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account-related interface elements are visible and accessible
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No client-side errors observed.
- Pre-populated local storage / cookies: token in local storage; continueCode, language, token, welcomebanner_status in cookies

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:

% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
Dload  Upload   Total   Spent    Left  Speed
0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 11:16:23 GMT
ETag: W/"26af-19eb665c4bb"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 11:51:03 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Content Security Policy** — The website does not restrict the types of scripts that can be executed in the browser, which may increase the likelihood of malicious code being executed, such as XSS attacks.
2. **Missing Strict-Transport-Security** — The server does not mandate the use of secure HTTPS connections. This could potentially allow users to access the website via less secure connections.
3. **Permissive CORS configuration** — The server permits requests from any source (Access-Control-Allow-Origin: *). This could potentially expose sensitive information to unauthorized external websites.


## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: No — PR template was not auto-inserted in fork PR creation flow (GitHub limitation). Template exists and is valid in repository.

## GitHub Community

- Why starring repositories matters in open source:
```
  Starring repositories helps highlight useful open-source projects and increases their visibility.
```
- How following developers helps in team projects and professional growth:
```  
  Following developers keeps you updated on their work and supports learning and collaboration in team projects.
```

## Bonus: CI Smoke Test

- Workflow file: .github/workflows/lab1-smoke.yml
- Trigger: pull_request on main
- Run URL: https://github.com/RanisKhaertdinov/DevSecOps-Intro/actions/runs/27348689468/job/80804229000
- Curl response excerpt:
  HTTP/1.1 200 OK
  ...