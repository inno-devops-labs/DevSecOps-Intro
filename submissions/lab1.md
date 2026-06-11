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
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`): returned error
- API check (first 200 chars of `/api/Products`): {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T13:07:45.456Z"
- Container uptime: Up 26 minutes

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: button Account in right upper corner, after tapping on it you can login or register
- Product listing/search present: [x] Yes [ ] No — notes: products are listed on main page, also search is present in right upper corner
- Admin or account area discoverable: [ ] Yes [x] No — notes: on http://127.0.0.1:3000/#/administration error occurs - "403
You are not allowed to access this page!"
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: no errors, only 4 verbose messages
- Pre-populated local storage / cookies: Local Storage is empty. Cookies: `continueCode=O3VMEvaDgyX8LvJ4qo7EwW6m29xP0pOGzRkZKY1bB3MNjOVprl5QenrK4a2x`, `cookieconsent_status=dismiss`, `language=en`, `welcomebanner_status=dismiss`

### Security Headers (Quick Look)

Run: `Invoke-WebRequest -Uri http://127.0.0.1:3000 -UseBasicParsing | Select-Object -ExpandProperty Headers`
(used instead of curl since I don't have curl on my Windows)

Output:
Key                         Value
---                         -----
Access-Control-Allow-Origin *
X-Content-Type-Options      nosniff
X-Frame-Options             SAMEORIGIN
Feature-Policy              payment 'self'
X-Recruiting                /#/jobs
Vary                        Accept-Encoding
Connection                  keep-alive
Keep-Alive                  timeout=5
Accept-Ranges               bytes
Content-Length              9903
Cache-Control               public, max-age=0
Content-Type                text/html; charset=UTF-8
Date                        Thu, 11 Jun 2026 14:24:35 GMT
ETag                        W/"26af-19eb6cbc54c"
Last-Modified               Thu, 11 Jun 2026 13:07:48 GMT

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. **Missing Content-Security-Policy header** — Without Content-Security-Policy, app is vulnerable to XSS attacks (attacker injects malicious scripts into the page that the browser would trust). This is A04: Injection in OWASP Top 10:2025.

2. **Missing Strict-Transport-Security header** — Without Strict-Transport-Security, the browser might at first connect through HTTP before upgrading to HTTPS, allowing attackers to perform SSL stripping attacks. This is A06: Security Misconfiguration.

3. **Access-Control-Allow-Origin: * ** — Any website can make cross-origin requests to this app's API. If logged-in user visits a malicious site, that site could read their data. This is A01: Broken Access Control.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title is clear, No secrets/large temp files committed, Submission file exists
- Auto-fill verified: [x] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

Starring repositories helps developers bookmark interesting projects, shows support to maintainers, and makes projects more visible to others. Following developers on GitHub helps build professional connections and discover new projects.

Stars given to:
- inno-devops-labs/DevSecOps-Intro
- simple-container-com/api

Following: @Cre-eD, @Naghme98, @pierrepicaud, and 3 classmates.