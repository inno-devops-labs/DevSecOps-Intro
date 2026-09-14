# Lab 1 — Juice Shop Deploy & Workflow

## Triage report

### Asset

- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: `macOS 26.6.2`, build `25G83`, Darwin `25.6.0`, `arm64`
- Docker version: `Docker version 28.4.0, build d8eb465`

### Deployment

Run command:

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

Access URL: `http://127.0.0.1:3000`

The port is bound to localhost only: `127.0.0.1:3000->3000/tcp`. That matters because Juice Shop is intentionally vulnerable; binding to `0.0.0.0` would expose it to the local network instead of only this machine.

Restart policy: none configured. The container will not automatically restart after `docker stop` or daemon restart.

### Health

`docker ps`:

```text
NAMES        STATUS          PORTS
juice-shop   Up 40 seconds   127.0.0.1:3000->3000/tcp
```

HTTP status on `/`:

```text
HTTP 200
```

Application version:

```json
{"version":"20.0.0"}
```

Product count:

```text
46
```

### Surface

- Login and registration: the SPA exposes account/login/register flows from the Account menu. `GET /rest/user/whoami` without credentials returned `{"user":{}}`, so anonymous users are treated separately from authenticated sessions.
- Products: `GET /api/Products` returned 46 products. Product data is publicly readable before login.
- Admin or account area: `/#/administration` returns the same SPA shell with `HTTP 200`; access control is handled client-side/server-side after the route loads rather than by a separate static page.
- Network/API behavior: `GET /rest/products/1/reviews` returned `HTTP 200` without authentication and exposed review authors/messages, for example `admin@juice-sh.op` and `basil@juice-sh.op`.
- Local storage and cookies: the initial response did not set cookies in curl's cookie jar. The bundled frontend code uses browser storage heavily (`31` `localStorage.getItem`, `9` `localStorage.setItem`, `24` `sessionStorage.getItem`, `13` `sessionStorage.setItem` matches in `main.js`), including language/token-related state.

### Headers

`curl -sI http://127.0.0.1:3000 | head -20`:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 14 Sep 2026 07:38:25 GMT
ETag: W/"26af-1a09eda5a0d"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 14 Sep 2026 07:39:03 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Header classification:

| Header | Present? |
| --- | --- |
| `Content-Security-Policy` | No |
| `Strict-Transport-Security` | No |
| `X-Content-Type-Options` | Yes, `nosniff` |
| `X-Frame-Options` | Yes, `SAMEORIGIN` |

### Top 3 risks

1. Missing CSP and HSTS headers. The app has some hardening headers, but no CSP to limit script execution and no HSTS because it is served over plain HTTP locally. This is OWASP Top 10:2025 A02 Security Misconfiguration.
2. Public unauthenticated data exposure. Product and review endpoints are reachable anonymously and disclose review authors and messages, which increases reconnaissance value even in a training app. This maps to OWASP Top 10:2025 A01 Broken Access Control.
3. Browser-side token/session handling risk. The frontend uses local/session storage for token-related state, which would make XSS more damaging because injected JavaScript can read browser storage. This maps to OWASP Top 10:2025 A03 Injection.

## PR template

Path: `.github/PULL_REQUEST_TEMPLATE.md`

Sections:

- `Goal`
- `Changes`
- `Testing`
- `Artifacts & Screenshots`
- `Checklist`

Checklist items:

- Title follows `feat(labN): <topic>`
- No secrets or large temp files committed
- `submissions/labN.md` exists

Draft PR showing the template-based description: https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1708

## GitHub community

Stars matter because they give maintainers visible feedback that a project is useful and help other users find it. Following people helps team projects because it makes classmates' activity, repositories, and collaboration history easier to discover during reviews and pair work.
