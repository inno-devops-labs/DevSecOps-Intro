# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
- Host OS: Ubuntu 24.04
- Docker version: Docker version 28.2.2, build 28.2.2-0ubuntu1~24.04.1

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no` 

### Health Check
- HTTP code on `/`: HTTP 200
- API check (first 200 chars of `/rest/products`):
[
  {
    "id": 1,
    "name": "Apple Juice (1000ml)",
    "description": "The all-time classic.",
    "price": 1.99,
    "deluxePrice": 0.99,
    "image": "apple_juice.jpg",
    "createdAt": "2026-06-10T10:37:05.133Z",
    "updatedAt": "2026-06-10T10:37:05.133Z",
    "deletedAt": null
  },
  {
    "id": 2,
    "name": "Orange Juice (1000ml)",
    "description": "Made from oranges hand-picked by Uncle Dittmeyer.",
    "price": 2.99,
    "deluxePrice": 2.49,
    "image": "orange_juice.jpg",
    "createdAt": "2026-06-10T10:37:05.133Z",
    "updatedAt": "2026-06-10T10:37:05.133Z",
    "deletedAt": null
  }
]

- Container uptime: juice-shop   Up 14 minutes   127.0.0.1:3000->3000/tcp

### Initial Surface
- Login/Registration visible: [x] Yes [ ] No — notes: button Account on the right top angle
- Product listing/search present: [x] Yes [ ] No — notes: products on the main page
- Admin or account area discoverable: [x] Yes [ ] No — notes: Account contain login && registration
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: No errors
- Pre-populated local storage / cookies: Cookies:  language=en

### Secure Headers (Quick Look)
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
Last-Modified: Wed, 10 Jun 2026 10:37:06 GMT
ETag: W/"26af-19eb11b729d"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 11:14:48 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Not present HTTP strict transport seciruty** — It means that browseer will not enforce HTTPS connections. Credentials and all trafic transmitted as a plain text, making it vulnerable to man-in-the-middle attacks.
2. **No content security policy** — The absence of a CSP header allows the browser to load scripts from any source. 
This makes the application highly vulnerable to Cross-Site Scripting (XSS) attacks.
3. **Insecure cookie attribute ** — no 'Secure' and 'HttpOnly' flags. This means it can be intercepted over unencrypted HTTP and accessed via JavaScript, enabling session hijacking.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

By starring projects you can save them to use it in the future for referencing and it helps to developer team make the project popular.By following developers you can see what they do, their field of interests and collaborate with them in the future

