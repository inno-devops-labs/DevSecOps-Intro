# Lab 1 — Submission

```markdown
## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)
```
## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:... — get from `docker inspect juice-shop --format '{{.Image}}'`>
    sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: <e.g. macOS 14.5 / Ubuntu 24.04>
    macOS 26.5.1
- Docker version: <output of `docker --version`>
    29.6.2

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [/] Yes [ ] No (explain if No)
- Container restart policy: <default `no` or `--restart` flag?>

### Health Check
- HTTP code on `/`: <should be 200>
    yes 200 ok
- API check (first 200 chars of `/api/Products`):
  ```
  {
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "Apple Juice (1000ml)",
      "description": "The all-time classic.",
      "price": 1.99,
      "deluxePrice": 0.99,
      "ima
  ```
- Container uptime: <output of `docker ps --filter name=juice-shop`>
    3 hours

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [X] Yes [ ] No — notes: <...>
- Product listing/search present: [X] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [X] Yes [ ] No — notes: <...>
- Client-side errors in DevTools console: [ ] Yes [X] No — notes: <...>
- Pre-populated local storage / cookies: <list what you saw> 
    nothing in the local storage, for cookies it shows the welcome banner and the language.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
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
Last-Modified: Sun, 26 Jul 2026 22:38:20 GMT
ETag: W/"26af-19fa0944a58"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 27 Jul 2026 02:07:33 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **<risk name>** — <why it matters; map to one OWASP Top 10:2025 category>
    A05:2025 Injection - Allows a user to alter the database tables without going through the correct process/authentications "admin@juice-sh.op'--"
2. **<risk name>** — <why; map to OWASP>
    A06:2025 Insecure Design - Does not have the correct system design to prevent users from easily accessing restricted areas - missing Content-Security-Policy and Strict-Transport-Security
3. **<risk name>** — <why; map to OWASP>
    A01:2025 Broken Access Control - Allows users to enter in guessed urls to access restricted areas.