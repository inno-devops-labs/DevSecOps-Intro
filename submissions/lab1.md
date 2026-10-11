# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
- Host OS: Kali GNU/Linux Rolling 6.19.14-1+kali1
- Docker version: Docker version 28.5.2+dfsg4

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no`

### Health Check
- HTTP code on `/`: <should be 200>
- API check (first 200 chars of `/rest/products`):
```
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-10T00:00:00.000Z"
```
- Container uptime:
```
CONTAINER ID   IMAGE                           COMMAND                  CREATED          STATUS          PORTS                      NAMES
9dffcc6b0d93   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   17 minutes ago   Up 17 minutes   127.0.0.1:3000->3000/tcp   juice-shop
```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Located in the top right corner under the "Account" dropdown.
- Product listing/search present: [x] Yes [ ] No — notes: Main page displays a grid of products; search bar in the top navigation.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account area is visible, but admin features are hidden behind authorization.
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: Minor warnings regarding missing sourcemaps and some blocked requests depending on browser tracking protection.
- Pre-populated local storage / cookies: Local storage contains `language` and `welcomeBannerStatus`.

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
Last-Modified: Wed, 10 Jun 2026 07:41:39 GMT
ETag: W/"26af-19eb07acf71"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 08:00:55 GMT
Connection: keep-alive
Keep-Alive: timeout=
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

* [x] `Content-Security-Policy`
* [x] `Strict-Transport-Security`
* [ ] `X-Content-Type-Options: nosniff`
* [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. **Authentication Bypass (SQLi)** — The login form likely communicates directly with a backend database without proper input sanitization. This maps to OWASP Top 10:2025 A03 (Injection), as an attacker could manipulate the authentication query to bypass login restrictions and access administrative functions.
2. **Broken Object Level Authorization (IDOR)** — The application uses predictably structured API endpoints (like `/api/Products/<id>/reviews`). This maps to OWASP Top 10:2025 A01 (Broken Access Control), meaning a user might be able to intercept requests via a proxy and manipulate the IDs to view or edit reviews and data belonging to other users.
3. **Cross-Site Scripting (XSS)** — The search functionality and review submission forms reflect user input onto the page. This maps to OWASP Top 10:2025 A03 (Injection), allowing malicious actors to execute arbitrary JavaScript in the context of other users' sessions, potentially leading to session hijacking.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: Title is clear, No secrets/large temp files committed, Submission file at submissions/labN.md exists
- Auto-fill verified: [x] Yes — PR description showed my template

## GitHub Community

**Actions completed:**
- [x] Starred the course repository.
- [x] Starred `simple-container-com/api`.
- [x] Followed Professor @Cre-eD and TAs (@Naghme98, @pierrepicaud).
- [x] Followed 3 classmates.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): [link](https://github.com/wannebetheshy/DevSecOps-Intro/actions/runs/27266269902/job/80524004413)
- Workflow run duration: 19s
- Curl response excerpt:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 09:18:25 GMT
ETag: W/"26af-19eb0d36913"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 09:18:25 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
