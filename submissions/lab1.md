# Lab 1 — Submission

## Triage report

### Asset

| Field          | Value |
|----------------|-------|
| Image tag      | `bkimminich/juice-shop:v20.0.0` |
| Image digest   | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Host OS        | macOS 14.6.1 (Sonoma), Build 23G93 |
| Docker version | 27.3.1 |

### Deployment

Run command:
```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

Access URL: http://127.0.0.1:3000

The port is bound to `127.0.0.1` (localhost only). If you use bare `-p 3000:3000` instead, Docker listens on all interfaces including Wi-Fi — anyone on the same network could reach a deliberately broken app, which is a bad idea.

Restart policy: not set, so default `no`. The container stays stopped after `docker stop` or a reboot.

### Health

```
NAMES        STATUS          PORTS
juice-shop   Up 5 minutes    127.0.0.1:3000->3000/tcp
```

```
HTTP 200
{"version":"20.0.0"}
46
```

### Surface

**Login and registration forms:** Both are in the Account menu top-right. No email verification on signup, you just pick any address and password and you're in. No visible lockout on the login form either.

**Product list:** `GET /api/Products` returns all 46 products with full details (name, price, image, timestamps) without any auth header. Same for `/rest/products/search?q=` — you can search the entire catalogue without being logged in.

**Admin or account area:** The Angular route table is compiled into the JS bundle, so scrolling through it reveals routes like `/administration`. The `/rest/user/whoami` endpoint returns `{"user":{}}` rather than 401 for unauthenticated requests, meaning it doesn't actively reject anonymous calls.

**Console errors:** On first load there are a few Angular/zone.js warnings. More notable: hitting `/api/Products/1/reviews` returns a 500 HTML page with the full Express stack trace, including internal paths like `/juice-shop/build/routes/angular.js` and the Express version (`^4.22.1`). That's more info than a server should hand out.

**Local storage and cookies:** The app sets a `language` value in Local Storage on load. After login a JWT is stored in Local Storage (not a `HttpOnly` cookie), so it's readable by any JS on the page. The session cookie itself had no `Secure` or `HttpOnly` flags visible in DevTools.

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
Last-Modified: Thu, 10 Sep 2026 17:35:20 GMT
ETag: W/"26af-1a08c636850"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 10 Sep 2026 17:39:30 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

| Header                      | Status |
|-----------------------------|--------|
| `Content-Security-Policy`   | missing |
| `Strict-Transport-Security` | missing |
| `X-Content-Type-Options`    | present (`nosniff`) |
| `X-Frame-Options`           | present (`SAMEORIGIN`) |

CSP and HSTS are both absent — OWASP Top 10:2025 A05, Security Misconfiguration.

### Top 3 risks

**1. Broken Access Control — A01**
The product list, search, and several other API endpoints return data to anyone without a token. Beyond that, the admin route is easy to find by reading the bundled JS. There's no meaningful separation between what a logged-in user can do and what an anonymous visitor can do.

**2. Injection — A03**
The search endpoint (`/rest/products/search?q=`) is a classic SQL injection vector in Juice Shop — input goes into a SQLite query without proper sanitisation. Some product descriptions also include raw HTML that gets rendered, which opens stored XSS possibilities.

**3. Security Misconfiguration — A05**
No Content-Security-Policy means scripts from anywhere can run. No HSTS means the browser won't enforce HTTPS on subsequent visits. `Access-Control-Allow-Origin: *` lets any origin make cross-site requests. On top of that, error responses leak the full stack trace and framework versions. Each of these is a small thing on its own, but together they make the attack surface much larger than it needs to be.

---

## PR template

File path: `.github/PULL_REQUEST_TEMPLATE.md`

Section names:
1. Goal
2. Changes
3. Testing
4. Artifacts & Screenshots

Checklist items:
- [ ] Title follows `feat(labN): <topic>`
- [ ] No secrets or large temp files committed
- [ ] `submissions/labN.md` exists

Draft PR link: *(https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1676)*

---

## GitHub community

Starred [inno-devops-labs/DevSecOps-Intro](https://github.com/inno-devops-labs/DevSecOps-Intro) and [simple-container-com/api](https://github.com/simple-container-com/api). Followed [@Cre-eD](https://github.com/Cre-eD), [@Naghme98](https://github.com/Naghme98), [@pierrepicaud](https://github.com/pierrepicaud), and three classmates.

Stars help open-source maintainers show that people actually use their project — it affects discoverability on GitHub and gives maintainers something to point to when asking for sponsorship or corporate backing. Following classmates and instructors lets you see their repos and contributions in your feed, which makes it easier to stay aware of what's going on in the course without having to check manually.
---

## Bonus: CI smoke test

Workflow path: `.github/workflows/lab1-smoke.yml`

Run URL: *(will be added after the PR is open and the run completes)*

Run duration: *(to be filled in)*

curl output from the job log:
```
{"version":"20.0.0"}
```
