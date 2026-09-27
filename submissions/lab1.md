# Lab 1 — Anton Bugaev (CBS-03)

## Triage report

### Asset
- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 26.6.2 (Darwin 25.6.0 arm64, Build 25G83)
- Docker version: Docker version 29.2.1, build a5c7197

### Deployment
- Run command:
  ```bash
  docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
  ```
- Access URL: http://127.0.0.1:3000
- Port binding: bound to `127.0.0.1:3000` only (not `0.0.0.0`). That matters because Juice Shop is deliberately vulnerable; publishing it on every interface would expose it on dorm/shared Wi-Fi.
- Restart policy: `no` (default; container does not restart automatically after stop/crash)

### Health
- HTTP code on `/`: `HTTP 200`
- Version endpoint: `{"version":"20.0.0"}`
- Product count: `46`
- `docker ps` line:
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 40 seconds   127.0.0.1:3000->3000/tcp
  ```

### Surface
1. **Login and registration.** Account menu (top right) exposes Login; the login form has email/password, “Forgot your password?”, Google login, and a “Not yet a customer?” link to registration. Registration is reachable at `/#/register`.
2. **Products.** Homepage lists the catalog (“All Products”, 15 items per page). `/api/Products` returns 46 items; individual product details are available without authentication.
3. **Admin / account area.** Side navigation and account flows exist; `/rest/admin/application-configuration` is reachable without a session and returns a `config` object. Unauthenticated `whoami` returns `{"user":{}}`.
4. **Console errors.** After dismissing the welcome banner and cookie notice, the UI loads the product grid without hard failures; no blocking console errors observed during basic browsing of home and login.
5. **Local storage and cookies.** After dismissing banners, cookies included `language=en` and `welcomebanner_status=dismiss`. Application Local Storage was empty before login. Cookie consent banner sets cookie-related preferences in the browser.

Network observation: opening a product triggers unauthenticated calls such as `/api/Products/:id` and `/rest/products/:id/reviews` (HTTP 200 with a `data` envelope) — no auth token required for catalog/reviews reads.

### Headers
`curl -sI http://127.0.0.1:3000 | head -20` output:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 14 Sep 2026 07:32:39 GMT
ETag: W/"26af-1a09ed51353"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 14 Sep 2026 07:33:18 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Four-header checklist:
| Header | Status |
|--------|--------|
| Content-Security-Policy | **missing** |
| Strict-Transport-Security | **missing** |
| X-Content-Type-Options | present (`nosniff`) |
| X-Frame-Options | present (`SAMEORIGIN`) |

Missing CSP and HSTS fall under OWASP Top 10:2025 **A02 Security Misconfiguration**.

### Top 3 risks

1. **Missing CSP and HSTS (security headers gap)** — Without Content-Security-Policy, XSS payloads can load arbitrary scripts; without Strict-Transport-Security there is no browser-enforced HTTPS policy if the app is later exposed beyond localhost. Combined with `Access-Control-Allow-Origin: *`, client-side attack surface is wide. **OWASP Top 10:2025 A02 — Security Misconfiguration.**

2. **Unauthenticated sensitive/admin-adjacent APIs** — Catalog, product reviews, and `/rest/admin/application-configuration` respond without authentication. That leaks configuration and review content and makes it trivial to probe for further privilege issues. **OWASP Top 10:2025 A01 — Broken Access Control.**

3. **Cleartext HTTP local service with intentional vulnerabilities** — Traffic to `http://127.0.0.1:3000` is unencrypted. On a shared host or if the bind is ever widened, session tokens and credentials can be sniffed; Juice Shop also ships with known XSS/injection challenges that become exploitable once reachable. **OWASP Top 10:2025 A04 — Cryptographic Failures.**

## PR template

- File path: `.github/PULL_REQUEST_TEMPLATE.md`
- Section names: **Goal**, **Changes**, **Testing**, **Artifacts & Screenshots**
- Checklist items:
  - title follows `feat(labN): `
  - no secrets or large temp files committed
  - `submissions/labN.md` exists
- Draft PR to course repo (Moodle submission): https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1706
- Template auto-fill demo on fork (PR into own `main`, template from `.github/PULL_REQUEST_TEMPLATE.md`): https://github.com/An11y/DevSecOps-Intro/pull/1 — body uses the required **Goal / Changes / Testing / Artifacts & Screenshots** sections and checklist from the template file on branch `feature/lab1`.

Note: a cross-fork PR into `inno-devops-labs/DevSecOps-Intro` does not pull the template from your fork’s default branch; the course repo has no student PR template. The fork PR above demonstrates auto-fill behaviour for grading Task 2.

## GitHub community

Stars signal that a project is used and valued, which helps maintainers justify time, attract contributors, and make the work discoverable. Following classmates and staff keeps course updates and peer work in your feed so collaboration and review loops stay visible during the semester.

Completed:
- Starred `inno-devops-labs/DevSecOps-Intro` and `simple-container-com/api`.
- Following staff: [@Cre-eD](https://github.com/Cre-eD), [@Naghme98](https://github.com/Naghme98), [@pierrepicaud](https://github.com/pierrepicaud).
- Following classmates: [@dilfd2006](https://github.com/dilfd2006), [@mobgun](https://github.com/mobgun), [@Mukhin-I](https://github.com/Mukhin-I).

## Bonus: CI smoke test

- Workflow path: `.github/workflows/lab1-smoke.yml`
- Run URL (green `pull_request` run on fork PR #1): https://github.com/An11y/DevSecOps-Intro/actions/runs/34818903644
- Course draft PR (for Moodle): https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1706 — upstream Actions for first-time contributors stay `action_required` until staff approve; the same workflow file is green on the fork PR above.
- Run duration: ~19s (queued at 07:39:56Z, completed ~07:40:15Z)
- Curl output excerpt from the job log:
  ```
  {"version":"20.0.0"}
  Smoke OK after 3s
  ```
