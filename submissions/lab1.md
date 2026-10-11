# Lab 1 - Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`
- Registry digest from pull: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Ubuntu 24.04.4 LTS
- Docker version: `Docker version 29.4.2, build 055a478`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no`

### Health Check

- HTTP code on `/`: `HTTP 200`
- API check (`/api/Products`, Juice Shop v20 replacement for the old `/rest/products` path):

  ```text
  Product count: 46
  First product excerpt:
  {"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-10T12:35:37.044Z","updatedAt":"2026-06-10T12:35:37.044Z","deleted
  ```

- Version check:

  ```json
  {
    "version": "20.0.0"
  }
  ```

- Container uptime:

  ```text
  NAMES        STATUS          PORTS
  juice-shop   Up 23 seconds   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No - notes: Headless browser DOM showed the Account area, a `Login` link to `#/login`, login email/password fields, and a `Not yet a customer?` registration link to `#/register`.
- Product listing/search present: [x] Yes [ ] No - notes: The landing page rendered product cards, add-to-basket buttons, search UI, and paginator text `1 - 16 of 46`.
- Admin or account area discoverable: [x] Yes [ ] No - notes: Account/login is visible from the navigation; an admin version endpoint at `/rest/admin/application-version` is reachable without authentication and returns the app version.
- Client-side errors in DevTools console: [ ] Yes [x] No - notes: Headless Chrome DevTools Protocol captured no `Runtime.exceptionThrown` events and no console API messages during page load and first product click.
- Pre-populated local storage / cookies: `localStorage` was empty after first load; `document.cookie` contained `language=en`.
- Product detail / reviews: clicking the first product triggered unauthenticated requests to `/rest/products/1/reviews`; the request was visible without login in the browser performance resource list.

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Output:

```text
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 12:35:37 GMT
ETag: W/"26af-19eb187f3f9"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 12:35:53 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 - A06)

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed

1. **Security headers are incomplete** - The app sends `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN`, but it does not send a `Content-Security-Policy` or `Strict-Transport-Security` on the local HTTP response. This maps to OWASP Top 10:2025 **A06: Security Misconfiguration**, because missing baseline browser controls can increase impact from XSS, downgrade, and clickjacking-adjacent issues.

2. **Version and implementation details are exposed** - `/rest/admin/application-version` is reachable without authentication and discloses `20.0.0`. This maps to **A06: Security Misconfiguration** and **A10: Mishandling of Exceptional Conditions**, because metadata disclosure helps attackers select version-specific payloads and confirms stack behavior.

3. **Unauthenticated public attack surface is broad** - The landing page exposes product listing, search, basket actions, login, feedback, AI chat, and other routes before authentication. This maps mainly to **A01: Broken Access Control** and **A04: Injection**, because public endpoints are where authorization gaps and untrusted-input paths are first tested.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] No - PR #947 was opened successfully, but the template did not auto-fill because this PR introduces `.github/PULL_REQUEST_TEMPLATE.md` for the first time. The PR body was filled manually with the same required sections.

## GitHub Community

- [x] Starred the course repository
- [x] Starred `simple-container-com/api`
- [x] Followed professor `@Cre-eD`
- [x] Followed TA `@Naghme98`
- [x] Followed TA `@pierrepicaud`
- [x] Followed at least 3 classmates

Stars matter in open source because they act as both bookmarks and public signals that a project is useful to the community. Following developers helps in team projects because it makes classmates' and maintainers' work easier to discover, review, and learn from.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): N/A so far - upstream PR #947 shows `Checks 0`, so GitHub did not run the newly-added workflow on this fork PR.
- Workflow run duration: N/A - no workflow run was created by GitHub for this PR.
- Curl response excerpt:

  ```text
  N/A - no GitHub Actions run was created. Local equivalent check passed:
  curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
  HTTP 200
  ```
