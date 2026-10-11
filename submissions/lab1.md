# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Proof of Juice Shop v20.0.0 container running on 127.0.0.1:3000
```
PS C:\Users\user\PycharmProjects\pythonProject18\DevSecOps-Intro> docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES        STATUS         PORTS
juice-shop   Up 5 minutes   127.0.0.1:3000->3000/tcp
```
### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `Windows 11 Pro 25H2`
- Docker version: `Docker version 29.4.0, build 9d7ad9f`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? Yes 
- Container restart policy: `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`):
```{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T13:14:37.512Z"```
- Container uptime: `Up About an hour`

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: Yes: account button in top right corner
- Product listing/search present: Yes: list of all products on main page and search bar in the top
- Admin or account area discoverable: Yes: area account
- Client-side errors in DevTools console: No: no errors
- Pre-populated local storage / cookies: none before login

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
Last-Modified: Thu, 11 Jun 2026 13:14:38 GMT
ETag: W/"26af-19eb6d20a05"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding

```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Security Headers** — Juice Shop lacks CSP and HSTS headers. This makes it vulnerable to XSS attacks and
                                protocol downgrade attacks. Maps to OWASP Top 10:2025 — A06: Security Misconfiguration.

2. **API Path Confusion** — The `/rest/products` endpoint returns 500 error while `/api/products` works. 
                          Inconsistent API design may lead to endpoint discovery issues. Maps to A01: Broken Access Control.

3. **Admin Area Exposure** — The /#/administration route is discoverable even though it requires authentication. Attackers can identify admin functionality location. Maps to A01: Broken Access Control.

### GitHub Community
- Why starring repositories matters in open source
    It helps bookmark interesting projects for references, showing yourself interests, help projects gain visibility, showing community trust
- How following developers helps in team projects and professional growth
    It helps to see on what projects developers are working on, discover new projects, build professional connections, for future collaborations of classmates

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/k111liza/DevSecOps-Intro/actions/runs/27376256611
- Workflow run duration: 24s
- Curl response excerpt:
```
< HTTP/1.1 200 OK
< Access-Control-Allow-Origin: *
< X-Content-Type-Options: nosniff
<!--
< X-Frame-Options: SAMEORIGIN
< Feature-Policy: payment 'self'
< X-Recruiting: /#/jobs
< Accept-Ranges: bytes
< Cache-Control: public, max-age=0
< Last-Modified: Thu, 11 Jun 2026 20:44:49 GMT
< ETag: W/"26af-19eb86e30de"
< Content-Type: text/html; charset=UTF-8
< Content-Length: 9903
< Vary: Accept-Encoding
< Date: Thu, 11 Jun 2026 20:44:55 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
```
## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)