# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

## Triage report

### Asset

| Item | Value |
|---|---|
| Image tag | `bkimminich/juice-shop:v20.0.0` |
| Image digest | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Host OS | Windows 11 Pro 25H2 (build 26200.9445); containers run in the Docker Desktop Linux VM (kernel `7.0.12-linuxkit`, `linux/amd64`) |
| Docker version | `Docker version 29.7.2, build a7dcaa6` (client and engine 29.7.2) |

### Deployment

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

- **Access URL:** http://127.0.0.1:3000
- **Bound to localhost only:** yes. `docker inspect juice-shop` shows `{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"3000"}]}`. Juice Shop is vulnerable on purpose. Published on `0.0.0.0`, it would let anyone on the same network (dorm or café Wi-Fi) reach the open `/ftp` backups, the admin configuration and every injectable endpoint on my laptop. With the `127.0.0.1` binding only processes on this machine can connect.
- **Restart policy:** `no` (Docker default, `HostConfig.RestartPolicy.Name`). The container does not come back after a crash or a Docker Desktop restart. For a vulnerable lab target that is what I want: it runs only when I start it by hand.
- The container runs as UID `65532` (non-root), taken from the image config.

### Health

The commands ran in PowerShell on Windows through `curl.exe`. `jq` is not installed, so Python's `json` module computes `.data | length`.

```text
> docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES        STATUS         PORTS
juice-shop   Up 3 minutes   127.0.0.1:3000->3000/tcp

> curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
HTTP 200

> curl -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}

> python -c "import json,urllib.request; print(len(json.load(urllib.request.urlopen('http://127.0.0.1:3000/api/Products'))['data']))"
46

> docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Surface

- **Login and registration.** Account → Login opens `/#/login`. It has email and password fields (the password can be shown in clear text), a "Remember me" checkbox, "Forgot your password?", a separate "Log in with Google" button and a "Not yet a customer?" link to `/#/register`. Registration asks for an email, a password typed twice, a security question from a drop-down and its answer. The drop-down loads from `/api/SecurityQuestions/` with no authentication.
- **Products.** The start page (`/#/search`) shows 46 products, 16 per page ("1 – 16 of 46"). The list comes from `/rest/products/search?q=` and the stock levels from `/api/Quantitys/`, both without a login. Clicking "Apple Juice (1000ml)" opens a detail dialog. Behind it, `/rest/user/whoami?fields=email` and `/rest/products/1/reviews` run with no `Authorization` header and return HTTP 200. Reviews are public and carry the author's email, e.g. `admin@juice-sh.op`, which reveals the admin's login name.
- **Admin or account area.** The UI links to none of it, but `main.js` ships the whole Angular route table (46 paths), including `administration`, `accounting`, `score-board`, `order-history`, `privacy-security`, `two-factor-authentication` and `wallet`. Without a login, `/#/administration` and `/#/accounting` render a client-side "403 You are not allowed to access this page!". `/#/score-board` opens with no login and lists all 178 challenges. `/#/order-history` says "No results found", while its API call `/rest/order-history` actually fails with HTTP 500. On the server, `/api/Users` and `/api/BasketItems` answer 401 "No Authorization header was found". These return 200 to anyone: `/rest/admin/application-configuration` (23 KB of app config), `/metrics` (Prometheus), `/support/logs`, `/encryptionkeys` and `/ftp`. `/ftp` is a directory listing that `robots.txt` advertises (`Disallow: /ftp`). It contains `acquisitions.md`, `coupons_2013.md.bak`, `package.json.bak`, `package-lock.json.bak`, `incident-support.kdbx` and more.
- **Console errors.** A fresh load of `/` logs no errors. `/#/login` and `/#/register` log the Chromium DOM warning "Password field is not contained in a form". `/#/order-history` logs `Failed to load resource: the server responded with a status of 500 (Internal Server Error)` for `/rest/order-history`.
- **Local storage and cookies.** Before login, Local Storage and Session Storage are empty. The first page load sets `language=en` and `continueCode=Pwma6XxDOa3kY5bEJRzoqLnyBWpd9DSk5AKeMNmr8P1lv4w9VjZ2g7Q6g4Rz`, a progress code from `/rest/continue-code`. Dismissing the welcome dialog and the "fruit cookies" banner adds `welcomebanner_status=dismiss` and `cookieconsent_status=dismiss`. JavaScript can read all four cookies (no `HttpOnly`). None has `Secure`, and all have `SameSite=Lax`.

### Headers

```text
> curl -sI http://127.0.0.1:3000 | head -20
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 11 Sep 2026 11:56:08 GMT
ETag: W/"26af-1a0905338cd"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 11 Sep 2026 11:59:23 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

| Header | Result |
|---|---|
| `Content-Security-Policy` | **Missing** |
| `Strict-Transport-Security` | **Missing** |
| `X-Content-Type-Options` | Present: `nosniff` |
| `X-Frame-Options` | Present: `SAMEORIGIN` |

Missing: `Content-Security-Policy` and `Strict-Transport-Security`. The app is served over plain HTTP, so HSTS would have no effect here anyway. A real deployment needs TLS in front of it and then HSTS. The response also carries `Access-Control-Allow-Origin: *` and `X-Recruiting: /#/jobs`, which leaks an unlisted route.

### Top 3 risks

1. **Sensitive files and internal endpoints open without authentication — A01:2025 Broken Access Control.** `/ftp` is a public directory listing with backups (`package.json.bak`, `coupons_2013.md.bak`) and a KeePass database (`incident-support.kdbx`). `/metrics`, `/support/logs`, `/rest/admin/application-configuration` and the Score Board also open without a login. They are "protected" only by not being linked in the UI, and `robots.txt` even points to `/ftp`. Anyone who reaches the port can take dependency versions, business documents and a password database to crack offline, all without authenticating.
2. **No browser-side hardening — A02:2025 Security Misconfiguration.** Without a CSP, any XSS bug runs with full access to the page and its data. Without TLS and HSTS, credentials and session tokens cross the network in clear text. The wildcard `Access-Control-Allow-Origin: *` and cookies without `HttpOnly`/`Secure` widen the damage further. All of these are configuration settings (security middleware or reverse proxy), not code changes, so leaving them out is a misconfiguration.
3. **Verbose, inconsistent error handling — A10:2025 Mishandling of Exceptional Conditions.** `GET /api/Orders` returns HTTP 500 with a full stack trace. It reveals the framework (`Express ^4.22.1`) and internal paths such as `/juice-shop/build/routes/angular.js:42:18`. `/rest/order-history` without a token crashes with 500 instead of answering 401, and the UI hides that behind "No results found". Stack traces hand attackers a map of the code and its versions. Endpoints that crash instead of rejecting the request cleanly show that unexpected input is not handled safely.

## PR template

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections: **Goal**, **Changes**, **Testing**, **Artifacts & Screenshots**
- Checklist items:
  - [ ] PR title follows `feat(labN): <topic>`
  - [ ] No secrets or large temporary files committed
  - [ ] `submissions/labN.md` exists
- Draft PR with the auto-filled description: https://github.com/mobgun/DevSecOps-Intro/pull/1 (draft, `feature/lab1` → `mobgun:main`)
- GitHub reads PR templates only from the base repository's default branch, so the template is also committed on `main` of my fork and the draft PR targets that branch. The description box opened already filled with the Goal / Changes / Testing / Artifacts & Screenshots / Checklist template.

## GitHub community

Stars are a cheap, public signal of use and trust. Maintainers cite them when they ask for sponsorship, contributors or corporate adoption, and stars help other people find a project in search and trending lists. Following classmates and instructors puts their repositories and activity in my feed, so in a team project I see what others are working on and which tools they rely on without having to ask.

## Bonus: CI smoke test

- Workflow: `.github/workflows/lab1-smoke.yml` (`on: pull_request` to `main`, workflow-level `permissions: contents: read`, Juice Shop `v20.0.0` as a service container, `curl --silent --fail` polling with a 60-second deadline)
- Run URL: https://github.com/mobgun/DevSecOps-Intro/actions/runs/34598315606 (event `pull_request` on draft PR #1, conclusion **success**)
- Run duration: 20 s (`run_duration_ms: 20000`). The `smoke` job ran from 12:19:21 to 12:19:38 UTC: "Initialize containers" (pull and start Juice Shop) took 11 s and "Wait for Juice Shop (up to 60 s)" took 4 s.
- Curl output from the job log:

```text
not ready yet (1s), retrying...
{"version":"20.0.0"}
Juice Shop is up after 4s
```
