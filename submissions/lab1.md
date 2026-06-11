# Lab 1 - Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 15.5 (Build 24F74), Apple Silicon
- Docker version: `Docker version 29.4.0, build 9d7ad9f`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no`

I first noticed that port 3000 was already used by a local Grafana container, so I stopped only that container and then started Juice Shop on the required localhost-only bind.

### Health Check

- HTTP code on `/`: `HTTP 200`
- API check (first 200 chars of `/api/Products`; v20.0.0 moved product listing from `/rest/products`):

```json
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T13:28:13.887Z"
```

- Product count from `/api/Products`: `46`
- Version check from `/rest/admin/application-version`:

```json
{
  "version": "20.0.0"
}
```

- Container uptime:

```text
NAMES        STATUS         PORTS
juice-shop   Up 3 minutes   127.0.0.1:3000->3000/tcp
```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No - notes: Account menu exposed a `Login` item. The login page had Email, Password, Remember me, "Log in with Google", Forgot password, and "Not yet a customer?" registration link.
- Product listing/search present: [x] Yes [ ] No - notes: homepage loaded "All Products", search control, basket, language selector, and 15 products on the first page out of 46 total.
- Admin or account area discoverable: [x] Yes [ ] No - notes: Account menu is visible before login; `/rest/admin/application-version` is reachable and returns the app version without authentication.
- Client-side errors in DevTools console: [ ] Yes [x] No - notes: no browser console errors were captured. I did trigger the in-app "Error Handling" challenge banner once after testing a wrong reviews path, which was useful but not a DevTools console error.
- Pre-populated local storage / cookies: no cookies were set in this session, and Local Storage appeared empty before login. After dismissing the cookie/welcome dialogs I still did not see an auth token or user data.

Product detail check: opening "Apple Juice (1000ml)" showed description, price, and a Reviews section with 2 reviews. The reviews endpoint `http://127.0.0.1:3000/rest/products/1/reviews` returned `HTTP 200` without authentication and included reviewer emails such as `admin@juice-sh.op` and `basil@juice-sh.op`.

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`

```text
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
  0  9903    0     0    0     0      0     HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 13:28:14 GMT
ETag: W/"26af-19eb6de7a20"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 13:32:04 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are missing?

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

Extra note: `Access-Control-Allow-Origin: *` is also very permissive. It is okay for a deliberately vulnerable training app, but I would flag it immediately on a real production app.

### Top 3 Risks Observed

1. **Weak browser-side hardening** - The app does return `nosniff` and `SAMEORIGIN`, but it is missing CSP and HSTS on the main page. In a real app this would make XSS impact and downgrade/transport mistakes easier to exploit, so I map it to **A06 Security Misconfiguration**.

2. **Unauthenticated public API surface** - Product and review data are readable before login, and the version endpoint is also available anonymously. Product browsing is expected for a shop, but the review endpoint exposes user emails and the version endpoint gives attackers fingerprinting information, so I map this to **A01 Broken Access Control**.

3. **Error handling leaks and challenge feedback** - While checking the wrong path `/api/Products/1/reviews`, Juice Shop returned an Express-style error page and the UI marked the "Error Handling" challenge as solved. That is intentional for this lab target, but in a normal app it would be a sign that unusual paths are not handled cleanly, so I map it to **A10 Mishandling of Exceptional Conditions**.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes - pending GitHub draft PR. The local file path and required sections are present; I will confirm the auto-filled description after pushing `feature/lab1`.

## GitHub Community

Starring the course repository and `simple-container-com/api` matters because stars work both as bookmarks for me and as small visibility signals for maintainers. Following the professor, TAs, and classmates is useful because it turns GitHub into a lightweight activity feed: I can notice what people are building, compare lab approaches, and find collaborators faster.

Manual GitHub UI checklist before submitting:

- [ ] Star course repository
- [ ] Star `simple-container-com/api`
- [ ] Follow `@Cre-eD`
- [ ] Follow `@Naghme98`
- [ ] Follow `@pierrepicaud`
- [ ] Follow at least 3 classmates

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Permissions: workflow-level `contents: read`
- Image: `bkimminich/juice-shop:v20.0.0`
- Readiness timeout: 60 seconds, polling `/rest/admin/application-version`
- Run URL (must be green): pending first GitHub Actions run after opening the PR
- Workflow run duration: pending first GitHub Actions run after opening the PR
- Curl response excerpt:

```text
Pending green GitHub Actions run. Local equivalent returned:
HTTP/1.1 200 OK
{"version":"20.0.0"}
```
