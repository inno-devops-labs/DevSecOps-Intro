# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

* Asset: OWASP Juice Shop (local lab instance)
* Image: `bkimminich/juice-shop:v20.0.0`
* Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
* Host OS: macOS 26.3.1 (a), Darwin 25.3.0 arm64
* Docker version: 29.4.0

### Deployment Details

* Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
* Access URL: http://127.0.0.1:3000
* Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
* Container restart policy: default `no`

### Health Check

* HTTP code on `/`: 200
* API check (first 200 chars of `/api/Products`):

  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-09T14:22:59.424Z"
  ```
* Container uptime:

  ```
  CONTAINER ID   IMAGE                           COMMAND                  CREATED             STATUS             PORTS                      NAMES
  074605cde18a   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   About an hour ago   Up About an hour   127.0.0.1:3000->3000/tcp   juice-shop2
  ```

### Initial Surface Snapshot (from browser exploration)

* Login/Registration visible: [x] Yes [ ] No — notes: Login and Registration are available through the account menu.
* Product listing/search present: [x] Yes [ ] No — notes: Product catalog is displayed on the landing page and search functionality is available.
* Admin or account area discoverable: [x] Yes [ ] No — notes: Account area is visible, but no administrator functionality was visible without authentication.
* Client-side errors in DevTools console: [ ] Yes [x] No — notes: No obvious client-side errors observed during browsing.
* Pre-populated local storage / cookies: none observed.

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 09 Jun 2026 14:22:59 GMT
ETag: W/"26af-19eacc3e462"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 09 Jun 2026 15:22:06 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

* [x] `Content-Security-Policy`
* [x] `Strict-Transport-Security`
* [ ] `X-Content-Type-Options: nosniff`
* [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. **Missing Security Headers** — The application does not return `Content-Security-Policy` or `Strict-Transport-Security` headers. Missing browser protections can increase exposure to attacks such as XSS and insecure transport. **OWASP Top 10:2025 — A05 Security Misconfiguration.**

2. **Publicly Accessible API Endpoints** — API endpoints such as `/api/Products` and `/rest/admin/application-version` can be accessed without authentication. Public APIs increase the attack surface and may expose functionality or information useful during reconnaissance. **OWASP Top 10:2025 — A01 Broken Access Control.**

3. **User-Controlled Input Through Search and Authentication Forms** — The application contains search, login, and registration forms that accept user input. Improper validation of these inputs could potentially lead to injection or other application-layer attacks. **OWASP Top 10:2025 — A03 Injection.**

## PR Template Setup

* File: `.github/PULL_REQUEST_TEMPLATE.md`
* Sections included:

  * Goal
  * Changes
  * Testing
  * Artifacts & Screenshots
* Checklist items:

  * Title is clear (`feat(labN): <topic>`)
  * No secrets/large temp files committed
  * Submission file at `submissions/labN.md` exists
* Auto-fill verified: [ ] Yes — PR description showed my template

I followed Professor and TAs. Starred the highlighted project. I already follow couple of my classmates.
Starring repositories helps users bookmark useful projects, supports maintainers, and highlights popular tools within the open-source community

