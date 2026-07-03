# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
- Host OS: Kali 2026.1
- Docker version: Docker version 28.5.2+dfsg3, build 9cc6dea35e9a963f281434761c656fba4ac43aed

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`): {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-10T10:26:09.077Z"

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: endpoints `/login` and `/register`
- Product listing/search present: [x] Yes [ ] No — notes: endpoint `/search` and query parameter `q`
- Admin or account area discoverable: [x] Yes [] No — notes: account area is visible, but admin cannot be found with just navigation.
- Client-side errors in DevTools console: [x] Yes [] No — notes: simple alerts of failed requests
- Pre-populated local storage / cookies: continueCode, language, token, welcomebanner_status, email

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
Last-Modified: Wed, 10 Jun 2026 10:26:09 GMT
ETag: W/"26af-19eb1116db7"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 10:56:20 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

* [x] `Content-Security-Policy`
* [x] `Strict-Transport-Security`
* [ ] `X-Content-Type-Options: nosniff`
* [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. XSS on main page in search functionality. Can cause in stealing cookies and ATO. Payload: `http://127.0.0.1:3000/#/search?q=1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E`

2. IDOR allows to view other baskets. Endpoint `GET /rest/basket/{id}` with path-parameter `id` vulnerable to idor via simple incrementation.

3. XXE in endpoint `POST /file-upload`. We can upload xml file with entity that includes `/etc/passwd` content. So its local file inclusion vulnerability. Payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><stockCheck><productId>&xxe;</productId></stockCheck>`

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
    - [x] Title is clear (`feat(labN): <topic>` style)
    - [x] No secrets/large temp files committed
    - [x] Submission file at `submissions/lab1.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community
Starring repositories signals appreciation and increases project visibility, helping maintainers gauge interest and attract contributors. Following developers keeps you updated on their work, fosters collaboration in team projects, and exposes you to best practices for professional growth