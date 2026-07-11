# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 26.3.1 (Darwin 25.3.0)
- Docker version: Docker version 28.3.0, build 38b7060

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no` (no `--restart` flag used)

### Health Check
- HTTP code on `/`: 200
- API check (first products from `/api/Products`):
  ```
  {"data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg"},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49},...]}
  Total products: 46
  ```
- Container uptime:
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 10 seconds   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Account menu in top-right corner exposes both Login and "Not yet a customer?" registration link
- Product listing/search present: [x] Yes [ ] No — notes: Homepage displays a product grid with 46 items; search bar in the nav supports live filtering
- Admin or account area discoverable: [x] Yes [ ] No — notes: `/rest/admin/application-version` endpoint returns `{"version":"20.0.0"}` unauthenticated; admin panel accessible via `/administration` after login
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: Angular routing warnings visible on first load; no critical JS exceptions blocking functionality
- Pre-populated local storage / cookies: Language preference (`welcomebanner_status`, `cookieconsent_status`) stored on first visit; no auth tokens pre-populated

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Output:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 08 Jun 2026 09:44:38 GMT
ETag: W/"26af-19ea69eb0b2"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 08 Jun 2026 09:44:58 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy` — **MISSING**
- [x] `Strict-Transport-Security` — **MISSING** (HTTP-only service, no TLS)
- [ ] `X-Content-Type-Options: nosniff` — **PRESENT**
- [ ] `X-Frame-Options` — **PRESENT** (set to `SAMEORIGIN`)

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Unauthenticated Admin Endpoint Exposure** — The `/rest/admin/application-version` endpoint returns sensitive version information without requiring any authentication. Exposing version details aids attackers in targeting known CVEs for the specific version. Maps to **A01:2025 — Broken Access Control** (missing authorization check on an administrative resource).

2. **Missing Content-Security-Policy** — The application serves no `Content-Security-Policy` header, leaving the browser with no directive on which scripts, styles, or resources to trust. This makes the app fully susceptible to Cross-Site Scripting (XSS) attacks injecting arbitrary scripts into the page. Maps to **A05:2025 — Security Misconfiguration** (absent defensive header that is widely supported and straightforward to configure).

3. **Wildcard CORS Policy (`Access-Control-Allow-Origin: *`)** — Every response is served with a wildcard CORS header, allowing any origin to make cross-origin requests and read the response. In an authenticated context, this can enable cross-site request forgery-style data exfiltration from a victim's session. Maps to **A07:2025 — Identification and Authentication Failures** (any malicious site can interact with the API on behalf of a logged-in user when cookies are `SameSite=None`).

---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets/large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

---

## GitHub Community

Starring repositories serves as a bookmark system and a signal of quality — a high star count indicates that many developers trust and actively use a project, which makes discovery easier for newcomers evaluating tools. Following professors, TAs, and classmates surfaces their activity in your GitHub feed, helping you stay aware of new repos they open, PRs they review, and tools they rely on — building a lightweight professional network from day one of the course.

Starred the course repository and the `simple-container-com/api` project
Followed professor and TAs
Followed classmates: @0xsmk, @Basinkse21, @prudenz1

---

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): https://github.com/JoraXD/DevSecOps-Intro/actions/runs/27154170994/job/80152612574
- Workflow run duration: 18s
- Curl response excerpt:
  ```
  {"version":"20.0.0"}
  ```
