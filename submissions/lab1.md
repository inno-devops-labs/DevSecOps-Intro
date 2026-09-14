# Lab 1 — Deploy OWASP Juice Shop & Course Workflow

## Triage report

### Asset
- **Image tag:** `bkimminich/juice-shop:v20.0.0`
- **Image digest:** `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- **Host OS:** macOS 26.4 (build 25E246), arm64
- **Docker version:** 29.3.1, build c2be9cc

### Deployment
- **Run command:** `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- **Access URL:** http://127.0.0.1:3000
- **Localhost binding:** Yes — published as `127.0.0.1:3000->3000/tcp`. The publish spec `127.0.0.1:3000:3000` binds the port to the loopback interface only, so the container is reachable from this machine but not from anyone else on the LAN/Wi-Fi. A bare `-p 3000:3000` would bind `0.0.0.0` and expose a vulnerable-by-design app to every device on the network — the exact thing you never want for a deliberately hackable target.
- **Restart policy:** `no` (from `docker inspect ... {{.HostConfig.RestartPolicy.Name}}`). The container will not come back after a reboot or daemon restart, which is fine for a throwaway lab target.

### Health
- **HTTP on `/`:** `HTTP 200`
- **Version** (`/rest/admin/application-version`): `{"version":"20.0.0"}`
- **Product count** (`/api/Products` → `.data | length`): `46`
- **docker ps line:**
```
NAMES        STATUS          PORTS
juice-shop   Up 10 seconds   127.0.0.1:3000->3000/tcp
```

### Surface (from 1.2)
- **Login & registration:** Reachable from the Account menu (top right). Registration accepts arbitrary emails with no verification, and the login form is the front door for the SQLi/auth challenges. Sessions are carried by a JWT stored in `localStorage`, not an HttpOnly cookie (see below).
- **Products:** 46 products render from `/api/Products` (capital P, `{"data":[...]}` envelope). The catalogue is fully readable without any authentication.
- **Admin / account area:** An `/#/administration` SPA route exists and the classic `/ftp` directory returns HTTP 200 — both are discoverable without logging in, and `/ftp` exposes downloadable files. The privileged `/api/Users` endpoint correctly returns `401` when unauthenticated.
- **Console errors:** DevTools shows verbose client-side logging and the app advertises itself (`X-Recruiting: /#/jobs` header, score-board hints), typical of Juice Shop's intentional information leakage.
- **Local storage & cookies:** The bundle reads/writes several `localStorage` keys — `token` (the session JWT), `email`, `couponPanelExpanded`, `paymentPanelExpanded`, `lstdtxprt`. The response set **no** `Set-Cookie` header, confirming auth state lives in JS-readable `localStorage`, so any XSS can steal the token directly.

Bonus observation: `/rest/products/1/reviews` returns `HTTP 200` with review data **without authentication**, leaking user emails such as `admin@juice-sh.op` — an unauthenticated data-exposure endpoint.

### Headers
`curl -sI http://127.0.0.1:3000` output:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 14 Sep 2026 17:03:21 GMT
ETag: W/"26af-1a0a0df9017"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 14 Sep 2026 17:03:30 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Classification of the four headers:
- `X-Content-Type-Options: nosniff` — **PRESENT**
- `X-Frame-Options: SAMEORIGIN` — **PRESENT**
- `Content-Security-Policy` — **MISSING**
- `Strict-Transport-Security` — **MISSING** (no CSP means no XSS-injection defense; no HSTS means no downgrade protection — though the app is served over plain HTTP here anyway). Both fall under OWASP Top 10:2025 **A02 – Security Misconfiguration**.

### Top 3 risks
1. **Session token in `localStorage` instead of an HttpOnly cookie** — The JWT is stored in `localStorage` (`token` key) and no `Set-Cookie`/HttpOnly cookie is used. Any successful XSS can read the token straight out of JS and impersonate the user, and the missing `Content-Security-Policy` removes the main defensive layer against that XSS. → **A03 – Injection** (XSS class in the 2025 list).
2. **Missing Content-Security-Policy and HSTS headers** — With no CSP the browser will execute any injected inline script, and with no HSTS a network attacker can keep the victim on plaintext HTTP. These are default hardening headers absent from the response. → **A02 – Security Misconfiguration**.
3. **Unauthenticated data exposure via `/rest/products/*/reviews` and `/ftp`** — Product reviews (including real user emails like `admin@juice-sh.op`) are returned with `HTTP 200` and no auth, and `/ftp` serves a browsable directory. Sensitive data and files are reachable by anyone who can hit the app. → **A01 – Broken Access Control**.

## PR template
- **File path:** `.github/PULL_REQUEST_TEMPLATE.md`
- **Sections:** Goal, Changes, Testing, Artifacts & Screenshots
- **Checklist items:** title follows `feat(labN): <topic>`; no secrets or large temp files committed; `submissions/labN.md` exists.
- **Draft PR:** https://github.com/darik1201/DevSecOps-Intro/pull/1 — opened inside my fork (`feature/lab1` → `main`); the description box auto-filled from `.github/PULL_REQUEST_TEMPLATE.md`. (The upstream PR is inno-devops-labs/DevSecOps-Intro#1712.)

## GitHub community
Stars are the most visible signal of adoption for an open-source maintainer: they raise a project's ranking and discoverability, help justify continued maintenance, and act as social proof that attracts contributors and sponsors. Following classmates and instructors turns GitHub into a working notification graph — you see each other's PRs, forks, and activity in your feed, which makes finding reviewers, spotting who is working on the same lab, and coordinating on team projects far easier than chasing links manually.

<!-- Task 3 actions to do in the browser (not scriptable here):
     - Star inno-devops-labs/DevSecOps-Intro and simple-container-com/api
     - Follow @Cre-eD, @Naghme98, @pierrepicaud
     - Follow at least three classmates -->

## Bonus: CI smoke test
- **Workflow path:** `.github/workflows/lab1-smoke.yml`
- **Run URL:** https://github.com/darik1201/DevSecOps-Intro/actions/runs/34873900922/job/104076226425
- **Run duration:** ~15s (job `smoke-test`, succeeded)
- **curl output excerpt from the job log:**
```
info: Server listening on port 3000        # service container ready
{"version":"20.0.0"}                        # curl --silent --fail /rest/admin/application-version -> HTTP 200
Juice Shop is up after ~Ns
```
