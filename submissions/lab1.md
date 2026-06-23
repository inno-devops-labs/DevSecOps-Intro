# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: macOS 26.5.1
- Docker version: 29.5.3, build d1c06ef

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [X] Yes [ ] No
- Container restart policy: <default `no` or `--restart` flag?>

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`):
```html
<html>
  <head>
    <meta charset='utf-8'>
    <title>Error: Unexpected path: /rest/products</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 1%  
```
- Container uptime: ed7c44ded799   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   48 minutes ago   Up 48 minutes   127.0.0.1:3000->3000/tcp   juice-shop

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [X] Yes [ ] No — notes: "Login" button in sidebar 
- Product listing/search present: [X] Yes [ ] No — notes: different products listed
- Admin or account area discoverable: [X] Yes [ ] No — notes: <...>
- Client-side errors in DevTools console: [ ] Yes [X] No — notes: in my Safari there was no Errors in DevTools. Found only "The source list for Content Security Policy directive 'img-src' contains an invalid source: '/assets/public/images/uploads/default.svg'. It will be ignored."
- Pre-populated local storage / cookies: contunueCode, cookieconsent_status, language, token, welcomebanner_status,juiceshop_chat_conversations,token



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
Last-Modified: Thu, 11 Jun 2026 08:31:00 GMT
ETag: W/"26af-19eb5ce5bbd"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 09:39:21 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing HTTP headers** — As mentioned before, `Content-Security-Policy` and `Strict-Transport-Security` are missing. This leaves the application and its users vulnerable to client-side attacks such as Cross-Site Scripting. It maps to OWASP A02:2025
2. **Login Bruteforce** — The authentication interface does not restrict the number of failed login attempts. This allows to perform brute-force attacks without interruption, falling under OWASP A06:2025
3. ****Unprotected Directory Access (/ftp)** — The application exposes an internal `/ftp` directory to the public without requiring any authentication. This allows completely unauthorized users to browse and download confidential files. This is OWASP A01:2025 - Broken Access Control.



## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: 
  - Title is clear (feat(labN): <topic> style)
  - No secrets/large temp files committed
  - Submission file at submissions/labN.md exists
- Auto-fill verified: [ ] Yes — PR description showed my template. Link to PR: 
