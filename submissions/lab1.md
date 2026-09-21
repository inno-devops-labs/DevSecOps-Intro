# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

## Triage report

### Asset

- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Windows 10 (10.0.19045), Docker running via Docker Desktop with the WSL2/Linux engine
- Docker version: `Docker version 29.6.1, build 8900f1d`
- Git version: `git version 2.55.0.windows.2`

### Deployment

- Run command: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: `http://127.0.0.1:3000`
- Port binding: bound to `127.0.0.1` only, not `0.0.0.0`. This matters because Juice Shop is intentionally vulnerable — a bare `-p 3000:3000` would publish it on every network interface, including whatever Wi-Fi the host machine is on, letting anyone on that network reach and exploit it. Binding to loopback keeps the attack surface limited to the local machine.
- Restart policy: none set (default `no`) — the container does not restart automatically if it crashes or the host reboots, which is acceptable for a local, throwaway lab container but would not be for anything long-lived.

### Health

- HTTP code on `/`: `HTTP 200`
- Version output: `{"version":"20.0.0"}`
- Product count output: `46`
- `docker ps` line:
  ```
  NAMES        STATUS          PORTS
  juice-shop   Up 25 seconds   127.0.0.1:3000->3000/tcp
  ```

### Surface

- **Login and registration:** the Account menu (top right) exposes both a login form and a "Not yet a customer?" registration flow. Registration only asks for email, password (with a repeat field and a security question), no email verification is performed before the account becomes usable.
- **Product list:** the home page lists all 46 products with name, price and image; clicking one opens a detail view with a description and any reviews left on it.
- **Admin or account area:** an `/#/administration` route and a `/rest/admin/application-configuration` endpoint both resolve (HTTP 200) without any authentication check on the initial page load — the client-side route itself renders, though the data it would show is separately access-controlled. This is already a sign the app is not hiding administrative surface area from unauthenticated users.
- **Console errors:** on first load, DevTools shows a handful of `Content-Security-Policy` warnings are notably absent (because there is no CSP at all — nothing to violate), but there are console entries about deprecated Angular APIs and a few 401s from calls the app makes speculatively (e.g. checking the current user session) before you log in.
- **Local storage and cookies:** before logging in, `localStorage` already has an entry from the app's own instrumentation (a `welcomebanner_status` / continue-code style key from earlier interaction) and, after any login attempt, a `token` key holding a JWT is written directly into `localStorage` rather than an `HttpOnly` cookie — meaning any successful XSS on this origin can read the auth token directly.

### Headers

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 21 Sep 2026 10:16:48 GMT
ETag: W/"26af-1a0c377dfe5"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 21 Sep 2026 10:17:17 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

- `X-Content-Type-Options`: **present** (`nosniff`)
- `X-Frame-Options`: **present** (`SAMEORIGIN`)
- `Content-Security-Policy`: **missing**
- `Strict-Transport-Security`: **missing**

### Top 3 risks

1. **JWT stored in `localStorage` instead of an `HttpOnly` cookie.** Any successful cross-site scripting on this origin can read `localStorage` and exfiltrate the session token directly, giving full account takeover with no further exploitation needed. Category: **A05 — Software or Data Integrity Failures** is close, but this is really about session handling exposed to script access — most accurately **A02, Security Misconfiguration** (insecure default storage of session material), which is also where the missing CSP below compounds it.
2. **Missing `Content-Security-Policy` and `Strict-Transport-Security` headers.** Without a CSP, any injected script (reflected or stored XSS) runs with no restriction on which origins it can talk to; without HSTS, a user who ever types `http://` or clicks an HTTP link can be downgraded and man-in-the-middled even if the site normally serves HTTPS. Category: **A02 — Security Misconfiguration**.
3. **Public access to admin-adjacent routes/endpoints without an auth gate at the routing layer.** `/rest/admin/application-configuration` and the `/#/administration` route both return `HTTP 200` for an anonymous, unauthenticated client instead of redirecting or rejecting outright — the app relies on the data layer or client-side checks rather than blocking the route itself, which is a much easier mistake to get wrong than a hard server-side authorization check. Category: **A01 — Broken Access Control**.

## PR template

- File path: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections: **Goal**, **Changes**, **Testing**, **Artifacts & Screenshots**
- Checklist items:
  - [ ] Title follows `feat(labN): <topic>`
  - [ ] No secrets or large temp files committed
  - [ ] `submissions/labN.md` exists
- Draft PR showing the auto-filled description: https://github.com/AlexbittIT/DevSecOps-Intro/pull/1

## GitHub community

Stars matter to open-source maintainers because they are the simplest visible signal of reach and adoption — a maintainer (or their employer, or a grant committee) uses star counts to gauge whether a project is worth continued investment, and a rising star count on a new release is often the first evidence that something landed well. Following people matters in team projects because it keeps their activity (new repos, releases, issues they open) visible in your feed by default, which lowers the friction of noticing when a teammate ships something you need to review or build on, without having to remember to go check.

## Bonus: CI smoke test

- Workflow path: `.github/workflows/lab1-smoke.yml`
- Run URL: https://github.com/AlexbittIT/DevSecOps-Intro/actions/runs/PLACEHOLDER
- Run duration: PLACEHOLDER
- curl output excerpt from the job log: PLACEHOLDER
