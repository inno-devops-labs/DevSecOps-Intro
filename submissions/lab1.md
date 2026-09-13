# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

## Triage report

### Asset

| Field | Value |
|---|---|
| Image tag | `bkimminich/juice-shop:v20.0.0` |
| Image digest | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Host OS | macOS 26.5.2 (Darwin 25.5.0, Apple Silicon) |
| Docker version | Docker 29.4.3, build 055a478 (Docker Desktop, linux/arm64 VM) |
| Application version (reported by the app) | `20.0.0` |

Digest obtained from the image, not the container:

```bash
$ docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Deployment

Run command:

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

- **Access URL:** http://127.0.0.1:3000
- **Port binding:** localhost only. `-p 127.0.0.1:3000:3000` tells Docker to publish the container port on the loopback interface only, so nothing outside this laptop can reach it. A bare `-p 3000:3000` would bind `0.0.0.0` and expose a deliberately vulnerable app — with SQL injection, unauthenticated file access and a stored admin database — to every machine on whatever network I happen to be on (university Wi-Fi, a café hotspot). It would also punch through the macOS firewall prompt path via Docker Desktop's proxy. Loopback binding is the difference between a lab and an incident.
- **Restart policy:** `no` (the default). Verified with `docker inspect juice-shop --format '{{.HostConfig.RestartPolicy.Name}}'` → `no`. The container does not come back after a reboot or a Docker Desktop restart, which is what I want for a vulnerable target: it only runs when I deliberately start it.

### Health

```bash
$ docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES        STATUS          PORTS
juice-shop   Up 32 seconds   127.0.0.1:3000->3000/tcp

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
HTTP 200

$ curl -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}

$ curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
46
```

All four match the expected values in the spec: the container is up and bound to `127.0.0.1:3000`, the root path returns `HTTP 200`, the app self-reports `20.0.0`, and the catalogue holds 46 products.

### Surface

What I found while clicking through http://127.0.0.1:3000 (DevTools open):

1. **Login and registration.** `#/login` is an email + password form with a "Remember me" checkbox, a "Forgot your password?" link and a "Log in with Google" OAuth button. `#/register` asks for email, password, repeat password, a security question and answer. The password field shows a live strength meter and enforces only 5–40 characters — no complexity or breach check, and the security-question mechanism is a second, weaker credential path into any account.
2. **Products.** The catalogue renders 46 items from `GET /rest/products/search?q=` (and `GET /api/Products`). Clicking a product fires `GET /rest/products/<id>/reviews`. I confirmed from the command line that this needs **no authentication**: `curl -s http://127.0.0.1:3000/rest/products/1/reviews` returns `HTTP 200` with review bodies **and the reviewers' e-mail addresses in cleartext** (`"author":"admin@juice-sh.op"`, `"author":"basil..."`). That is an unauthenticated user-enumeration source. Other calls on page load — `/rest/admin/application-configuration`, `/rest/languages`, `/api/Quantitys/`, `/api/Challenges/?name=Score Board`, a `socket.io` polling channel — are also anonymous.
3. **Admin / account area.** The Account menu (top right) holds login/registration, basket and order history. Navigating directly to `#/administration` renders a red **"403 — You are not allowed to access this page!"** box, but that is a *client-side* Angular guard: the route, the bundle and the admin component are all shipped to the anonymous browser. The corresponding API is the thing that actually enforces anything — `curl http://127.0.0.1:3000/api/Users` returns `HTTP 401`. Separately, `GET /ftp` returns `HTTP 200` with a **browsable directory listing** including `coupons_2013.md.bak`, `package.json.bak`, `package-lock.json.bak`, `incident-support.kdbx` (a KeePass database), `encrypt.pyc` and `announcement_encrypted.md` — backup and secret-bearing files served to anyone. `GET /metrics` and `GET /snippets` are also `HTTP 200` unauthenticated.
4. **Console errors.** The DevTools console stayed clean on load, on `#/login`, on `#/register` and on `#/administration` — no uncaught exceptions, no CSP violation reports (there is no CSP to violate). What the app *does* volunteer is error information in the UI: within seconds of first load it popped **"You successfully solved a challenge: Error Handling (Provide an error that is neither very graceful nor consistently handled)"**, and after I curled `/metrics` it popped **"Exposed Metrics"**. So the verbose-error and exposed-telemetry weaknesses are real and trivially reachable; they surface as app banners rather than as browser console noise.
5. **Local storage and cookies.** `localStorage` and `sessionStorage` were both **empty** before login. `document.cookie` returned `language=en; continueCode=O3VMEvaDgyX8LvJ4qo7EwW6m29xP0pOGzRkZKY1bB3MNjOVprl5QenrK4a2x`. The fact that I could read them from JavaScript proves neither cookie is `HttpOnly`; the response carried no `Set-Cookie` with `Secure` or `SameSite` either. `continueCode` is the anonymous progress token — a bearer-style value fully exposed to any script on the page. After a real login Juice Shop additionally stores the JWT in a readable `token` cookie / `localStorage`, which is the classic XSS-to-account-takeover chain.

### Headers

```bash
$ curl -sI http://127.0.0.1:3000 | head -20
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sun, 13 Sep 2026 15:27:16 GMT
ETag: W/"26af-1a09b613e27"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Sun, 13 Sep 2026 15:27:57 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Classification of the four headers in question:

| Header | Present? | Value / note |
|---|---|---|
| `Content-Security-Policy` | **Missing** | Nothing constrains script sources; any injected `<script>` or inline handler executes with full privileges. |
| `Strict-Transport-Security` | **Missing** | Consistent with plain HTTP here, but it means no downgrade protection is baked into the app itself. |
| `X-Content-Type-Options` | **Present** | `nosniff` — browsers will not MIME-sniff responses. |
| `X-Frame-Options` | **Present** | `SAMEORIGIN` — basic clickjacking protection (no `frame-ancestors` equivalent, since there is no CSP). |

So two of four are present and two are missing. Two more findings from the same output: `Access-Control-Allow-Origin: *` lets any origin read responses from this app, and `X-Recruiting: /#/jobs` is a non-standard header leaking application detail. Missing security headers map to **OWASP Top 10:2025 A02 — Security Misconfiguration**.

### Top 3 risks

**1. Unauthenticated exposure of backup and secret files via `/ftp` — A01: Broken Access Control.**
`GET /ftp` returns a browsable listing and the files download without any session. `package.json.bak` and `package-lock.json.bak` hand an attacker the exact dependency tree to match against known CVEs; `coupons_2013.md.bak` is business data; `incident-support.kdbx` is a KeePass vault, i.e. a credential store that can be cracked offline at leisure. No authentication decision is made at all on this path, which is the definition of broken access control, and it needs nothing more than a browser to exploit.

**2. No Content-Security-Policy (and no HSTS), combined with JS-readable session cookies — A02: Security Misconfiguration.**
The app ships no CSP, so there is no second line of defence behind its output encoding: one reflected or stored XSS anywhere in the 46-product catalogue or the review fields executes unrestricted, including calls back to attacker-controlled hosts. Because `continueCode` (and, after login, the JWT) is readable from `document.cookie` with no `HttpOnly` flag, that XSS converts directly into session theft and account takeover. `Access-Control-Allow-Origin: *` on top of this lets a malicious page read API responses cross-origin.

**3. Unauthenticated user enumeration and information leakage through the API and error handling — A06: Insecure Design** (the verbose-error half also touches A10: Mishandling of Exceptional Conditions).
`/rest/products/<id>/reviews` returns real account e-mail addresses to anonymous callers, `/metrics` exposes Prometheus telemetry about the running app, `/snippets` is open, and the app volunteered an "Error Handling" challenge within seconds of first contact because it returns errors that are neither graceful nor consistent. Individually these are leaks; together they are a design that never treated "who is asking" as an input to "what do I return". An attacker builds a valid-account list for free and then aims credential stuffing at it, with verbose errors distinguishing a wrong password from an unknown user.

### 1.4 — container kept, not removed

```bash
$ docker stop juice-shop
juice-shop
```

The container and the `bkimminich/juice-shop:v20.0.0` image stay on disk; Labs 4, 5, 7, 8 and 10 reuse the same artefact (same digest as recorded above).

## PR template

- **File path:** `.github/PULL_REQUEST_TEMPLATE.md`
- **Sections:** `## Goal` (one sentence), `## Changes` (bullet list), `## Testing` (commands and observed output), `## Artifacts & Screenshots`
- **Checklist items:**
  - `Title follows `feat(labN): <topic>``
  - `No secrets or large temp files committed`
  - `submissions/labN.md exists`

Auto-fill evidence: <!-- TODO: paste the draft-PR link here after pushing `feature/lab1` and opening the draft PR; the description box must already show the four headings and three checklist items before typing anything. -->

## GitHub community

Done: starred the course repository and [simple-container-com/api](https://github.com/simple-container-com/api); followed the professor [@Cre-eD](https://github.com/Cre-eD) and the TAs [@Naghme98](https://github.com/Naghme98) and [@pierrepicaud](https://github.com/pierrepicaud).

A star is the cheapest honest signal a maintainer gets. It feeds GitHub's ranking and trending lists, so it is most of how the next person finds the project at all, and it is the number a maintainer points at when arguing for paid time to keep the thing alive — for a security tool it also doubles as a rough proxy for "enough people run this that the bugs have been found by someone other than me". Following people is the team-project half of the same idea: their commits, issues and reviews show up in my feed, so I notice that someone already solved the thing I was about to start, and review requests and mentions land in a place they will actually be read instead of in a chat thread nobody scrolls back through.

## Bonus: CI smoke test

- **Workflow path:** `.github/workflows/lab1-smoke.yml`
- **Trigger:** `pull_request` targeting `main` (not `pull_request_target` — that runs with the base repo's write-scoped token and secrets against fork-controlled code, which is OWASP CI/CD Top 10 risk CICD-SEC-4)
- **Permissions:** `contents: read` at workflow level
- **Target:** `bkimminich/juice-shop:v20.0.0` as a `services:` container with `3000:3000`
- **Health gate:** polls `http://localhost:3000/rest/admin/application-version` with `curl --silent --fail` once a second for up to 60 attempts; the step exits 1 if it never gets a 200

Workflow:

```yaml
name: lab1-smoke

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  smoke:
    name: Juice Shop smoke test
    runs-on: ubuntu-latest

    services:
      juice-shop:
        image: bkimminich/juice-shop:v20.0.0
        ports:
          - 3000:3000

    steps:
      - name: Wait for Juice Shop to answer (up to 60s)
        run: |
          for i in $(seq 1 60); do
            if curl --silent --fail http://localhost:3000/rest/admin/application-version; then
              echo ""
              echo "Juice Shop is up after ${i}s"
              exit 0
            fi
            sleep 1
          done
          echo "Juice Shop did not become healthy within 60 seconds"
          exit 1

      - name: Show version endpoint
        run: curl --silent --fail http://localhost:3000/rest/admin/application-version
```

- **Run URL:** <!-- TODO: paste the green run URL after pushing and opening the draft PR -->
- **Run duration:** <!-- TODO: paste from the run summary -->
- **curl output excerpt from the job log:** <!-- TODO: paste the `{"version":"20.0.0"}` line and the `Juice Shop is up after Ns` line -->

Locally the same poll against the same image tag produced:

```
{"version":"20.0.0"}
```
