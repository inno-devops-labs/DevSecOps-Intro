# Lab 1 — Submission

## Task 1 — Deploy Juice Shop & Triage Report (6 pts)

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce` (from `docker inspect juice-shop --format '{{.Image}}'`)
- Host OS: Ubuntu 24.04 
- Docker version: `Docker version 29.4.0, build 9d7ad9f`

### Deployment Details
- Run command used:

  ```bash
  docker run -d --name juice-shop \
    -p 127.0.0.1:3000:3000 \
    bkimminich/juice-shop:v20.0.0
  ```
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No — container bound to localhost
- Container restart policy: default (`no`)

### Health Check
- HTTP code on `/`: `200`
API check (first 200 chars of `/api/Products`):

  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-10T01:28:01.171Z"...
  ```

- Product count from `/api/Products`: `46`
- Container uptime: Up 12 hours

  ```text
  juice-shop   Up 12 hours   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: account menu has Login/Register.
- Product listing/search present: [x] Yes [ ] No — notes: products displayed on landing page.
- Admin or account area discoverable: [x] Yes [ ] No — notes: Admin endpoints under `/rest/admin/` discovered via API probe, hidden admin endpoint discoverable via `/#/administration`, unauthorized access to critical configuration via `/rest/admin/application-configuration`.
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: None observed during initial load.
- Pre-populated local storage / cookies: Local storage empty, cookies include: `continueCode`, `cookieconsent_status`, `language`, `welcomebanner_status`.

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 | head -20`. Paste output:

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
Last-Modified: Wed, 10 Jun 2026 01:28:02 GMT
ETag: W/"26af-19eaf24c181"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 03:05:31 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06):
- [x] `Content-Security-Policy` — missing
- [x] `Strict-Transport-Security` — missing (site served over HTTP)
- [ ] `X-Content-Type-Options: nosniff` —  present
- [ ] `X-Frame-Options` — present

### Top 3 Risks Observed (2-3 sentences each)

1. **Missing Content-Security-Policy (and HSTS).**
   No CSP header is returned, so the browser has no policy to restrict script
   sources which widens the blast radius of any XSS injection. The absence of
   `Strict-Transport-Security` also allows downgrade to cleartext HTTP.  These are insecure default header settings. Mapping: **OWASP Top 10:2025 — A02 Security Misconfiguration.**

2. **Permissive CORS: `Access-Control-Allow-Origin: *`.**
   The API allows any origin to read its responses. Combined with unauthenticated data endpoints like `/api/Products`, this lets a third-party site query and exfiltrate content from a victim's browser leading to an access-control failure. Mapping: **OWASP Top 10:2025 — A01 Broken Access Control.**

3. **Information disclosure / fingerprinting.**
   The custom `X-Recruiting: /#/jobs` header and `/rest/admin/application-version` (version 20.0.0) leak unnecessary detail. These leaks make it trivial to fingerprint the stack and target known CVEs matching the exact version a configuration that exposes more than it should. Mapping: **OWASP Top 10:2025 — A02 Security Misconfiguration.**

---

## PR Template Setup

- File added: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist included: Title style, No secrets/large files, `submissions/labN.md` present
- Auto-fill verification: To verify, push `feature/lab1` and open a draft PR — the PR description should pre-fill with this template.
---

## Task 3 — GitHub Community Engagement (1 pt)

- Starred: DevSecOps-Intro (course repo), simple-container-com/api
- Followed: @Cre-eD, @Naghme98, @pierrepicaud, and three classmates

Why: Starring in the open source community helps discovery and signals interest; following instructors and peers enables collaboration and timely updates. It can also serve as a token of appreciation for maintainers/contributors and helps for bookmarking purposes.

---

## Bonus Task — Smoke-Test Workflow in GitHub Actions (2 pts)

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): [<link to your Actions run>](https://github.com/IamdLite/DevSecOps-Intro/actions/runs/27287731734/job/80599483714?pr=1)
- Workflow run duration: 22s
- Curl response excerpt:
```
Run curl --silent --fail -I http://localhost:3000 | head -n 20
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 15:41:12 GMT
ETag: W/"26af-19eb231dc77"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 15:41:13 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

---

## Cleanup

```bash
docker stop juice-shop || true
# docker rm juice-shop  # optional
```
