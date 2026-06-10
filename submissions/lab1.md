## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`
- Host OS: `EndeavourOS`
- Docker version: `Docker version 29.5.2, build 79eb04c7d8`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`):
- ```html
  <html>
    <head>
      <meta charset='utf-8'>  
      <title>Error: Unexpected path: /rest/products</title>
      <style>* {
    margin: 0;
```
- Container uptime: Up 22 minutes

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Found under the "Account" dropdown menu in the top right corner.
- Product listing/search present: [x] Yes [ ] No — notes: Homepage displays a grid of products with a search bar at the top.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account area exists, but admin area is not explicitly linked in the main UI without authentication.
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: Several warnings regarding SameSite cookies and missing source maps.
- Pre-populated local storage / cookies: Found `language` and `cookieconsent_status` in cookies, and empty `token` / `cartId` fields in Local Storage.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```bash
 % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current  
                                Dload  Upload  Total   Spent   Left   Speed  
 0   9903   0      0   0      0      0      0                              0  
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: *  
X-Content-Type-Options: nosniff  
X-Frame-Options: SAMEORIGIN  
Feature-Policy: payment 'self'  
X-Recruiting: /#/jobs  
Accept-Ranges: bytes  
Cache-Control: public, max-age=0  
Last-Modified: Wed, 10 Jun 2026 06:30:39 GMT  
ETag: W/"26af-19eb039d024"  
Content-Type: text/html; charset=UTF-8  
Content-Length: 9903  
Vary: Accept-Encoding  
Date: Wed, 10 Jun 2026 06:59:48 GMT  
Connection: keep-alive  
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Security Headers** — I noticed from the curl output that essential headers like `Content-Security-Policy` and `Strict-Transport-Security` are completely missing. Without these, the application is an easy target for basic client-side attacks like clickjacking. This maps to OWASP Top 10:2025 A06: Security Misconfiguration.
2. **Verbose Error Leaks** — When I tried curling the old `/rest/products` endpoint, the server didn't just return a 404, but threw a full 500 HTML page exposing the Express.js version and internal server paths (like `/juice-shop/build/routes/angular.js`). Leaking stack traces gives attackers way too much info about the backend structure. I'd map this to OWASP Top 10:2025 A06: Security Misconfiguration.
3. **Unprotected Auth Endpoints** — The login and registration forms are publicly accessible without any obvious rate limiting or CAPTCHA. It looks like someone could easily script a brute-force or credential stuffing attack against the user accounts. This falls under OWASP Top 10:2025 A02: Identification and Authentication Failures.

## PR Template Setup
- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title is clear, No secrets/large temp files committed, Submission file at `submissions/lab1.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template.

## GitHub Community
- Starring repositories matters because it helps bookmark useful projects, shows community trust, and boosts the project's visibility in the open-source ecosystem.
- Following developers is crucial for discovering new tools they work on, building professional connections, and tracking teammates' activity for future collaboration.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/chebudelphin/DevSecOps-Intro/actions/runs/27261249935/job/80507240551?pr=1
- Workflow run duration: 17s
- Curl response excerpt:
```text
HTTP/1.1 200 OK

0 9903 0 0 0 0 0 0 --:--:-- --:--:-- --:--:-- 0

Access-Control-Allow-Origin: *

X-Content-Type-Options: nosniff

X-Frame-Options: SAMEORIGIN

Feature-Policy: payment 'self'

X-Recruiting: /#/jobs

Accept-Ranges: bytes

Cache-Control: public, max-age=0

Last-Modified: Wed, 10 Jun 2026 07:45:07 GMT

ETag: W/"26af-19eb07dff25"

Content-Type: text/html; charset=UTF-8

Content-Length: 9903

Vary: Accept-Encoding

Date: Wed, 10 Jun 2026 07:45:09 GMT

Connection: keep-alive

Keep-Alive: timeout=5
```
