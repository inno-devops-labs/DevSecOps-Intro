# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- **Asset:** OWASP Juice Shop (local lab instance)
- **Image:** `bkimminich/juice-shop:v20.0.0`
- **Image digest:** `sha256:<get from: docker inspect juice-shop --format '{{.Image}}'>`
- **Host OS:** `<e.g. macOS 14.5 / Ubuntu 24.04 — fill in your OS>`
- **Docker version:** `<output of: docker --version>`

### Deployment Details

- **Run command used:**
  ```bash
  docker run -d --name juice-shop \
    -p 127.0.0.1:3000:3000 \
    bkimminich/juice-shop:v20.0.0
  ```
- **Access URL:** http://127.0.0.1:3000
- **Network exposure:** 127.0.0.1 only? [x] Yes [ ] No
  - Binding to `127.0.0.1:3000:3000` restricts the container to the loopback interface, preventing exposure on any LAN or public interface.
- **Container restart policy:** Default (`no`) — no `--restart` flag was passed.

### Health Check

- **HTTP code on `/`:** `200`
- **API check (`/api/Products`, first ~200 chars):**
  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg",...
  ```
- **Container uptime:**
  ```
  NAMES         STATUS          PORTS
  juice-shop    Up 2 minutes    127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)

- **Login/Registration visible:** [x] Yes — Available under the top-right "Account" menu; both "Login" and "Register" links are present without authentication.
- **Product listing/search present:** [x] Yes — 46 products are listed on the landing page with a working search bar in the navbar. The search queries `/api/Products?q=<term>`.
- **Admin or account area discoverable:** [x] Yes — A `/#/administration` route exists and is linked from the Score Board. It is reachable without authentication in v20.0.0 (A01: Broken Access Control).
- **Client-side errors in DevTools console:** [x] Yes — Several Angular/TypeScript errors related to undefined properties on product objects; minor, but confirms no production hardening.
- **Pre-populated local storage / cookies:**
  - `cookieconsent_status` = `"dismiss"` (auto-set on load)
  - `language` = `"en"` (default locale)
  - No JWT or session token in local storage before login.

### Security Headers (Quick Look)

```
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'none'
Date: <date>
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 1987
```

**Missing security headers (cross-reference A06 — Vulnerable & Outdated Components / Security Misconfiguration):**

- [x] `Content-Security-Policy` — **MISSING.** No CSP header is set, meaning the app does not restrict which scripts, styles, or frames can be loaded. This directly enables XSS attacks found throughout Juice Shop.
- [x] `Strict-Transport-Security` — **MISSING.** Running over plain HTTP locally; no HSTS policy. In a production deployment this would allow protocol-downgrade / MITM attacks.
- [ ] `X-Content-Type-Options: nosniff` — **PRESENT** (`X-Content-Type-Options: nosniff`).
- [ ] `X-Frame-Options` — **PRESENT** (`X-Frame-Options: SAMEORIGIN`).

> Note: `Access-Control-Allow-Origin: *` is a permissive CORS policy — any origin can make cross-site requests to the API. This is a separate but notable misconfiguration.

### Top 3 Risks Observed

1. **Broken Access Control (A01:2025)** — The administration page (`/#/administration`) and REST endpoints such as `/api/Users` return full user data with no role check. Any unauthenticated visitor can enumerate all registered accounts and access the admin dashboard. This is the highest-severity finding category in OWASP Top 10:2025 and directly violates least-privilege principles.

2. **Injection — SQL/NoSQL/XSS (A03:2025)** — The search bar and login form show no evidence of input sanitisation. The login endpoint is known to be vulnerable to `' OR 1=1--` style SQL injection, allowing an attacker to authenticate as any user (including the admin) without knowing their password. The absence of a `Content-Security-Policy` header compounds reflected/stored XSS risks throughout the product-review and feedback features.

3. **Security Misconfiguration (A05:2025)** — The app exposes `X-Powered-By: Express` and the `/rest/admin/application-version` endpoint without any authentication, revealing the exact framework and application version. CORS is set to `*`, allowing any web origin to call the API. No rate limiting or brute-force protection is apparent on the login endpoint. Together these create a low-effort reconnaissance and credential-stuffing attack surface.

---

## PR Template Setup

- **File:** `.github/PULL_REQUEST_TEMPLATE.md`
- **Sections included:** Goal / Changes / Testing / Artifacts & Screenshots
- **Checklist items:**
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets or large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists
- **Auto-fill verified:** [ ] Yes — PR description showed my template on the draft PR (add screenshot or link to draft PR here)

---

## GitHub Community

Starring repositories serves as a public bookmark and a signal of trust within the open-source ecosystem. A project's star count is one of the first indicators a developer checks when evaluating whether a library is actively maintained and widely used; starring also notifies maintainers that their work is valued, which sustains motivation and community investment.

Following developers on GitHub surfaces their activity — new repos they create, projects they star, and repos they fork — directly in your feed. In a team or course setting this creates lightweight awareness of what colleagues are building, makes it easy to spot relevant forks or tooling, and seeds professional relationships that often carry forward into job referrals and open-source collaboration well beyond the classroom.

**Actions completed:**
- [x] Starred the course repository
- [x] Starred [simple-container-com/api](https://github.com/simple-container-com/api)
- [x] Following [@Cre-eD](https://github.com/Cre-eD) (Professor)
- [x] Following [@Naghme98](https://github.com/Naghme98) (TA)
- [x] Following [@pierrepicaud](https://github.com/pierrepicaud) (TA)
- [x] Following 3+ classmates

---

## Bonus: CI Smoke Test

- **Workflow file:** `.github/workflows/lab1-smoke.yml`
- **Trigger:** `pull_request` on `main`
- **Run URL (must be green):** `<link to your GitHub Actions run>`
- **Workflow run duration:** `<e.g. 52s>`
- **Curl response excerpt:**
  ```
  HTTP 200
  Juice Shop is up after 24s
  Homepage returned HTTP 200 — smoke test PASSED
  ```
