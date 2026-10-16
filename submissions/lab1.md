# Lab 1 Submission

## Triage report

### Asset

- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 26.6.2, build 25G83
- Docker version: `Docker version 29.1.3, build f52814d`

### Deployment

- Run command:

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

- Access URL: http://127.0.0.1:3000
- Port binding: localhost only, `127.0.0.1:3000->3000/tcp`. This matters because Juice Shop is intentionally vulnerable; binding to `127.0.0.1` keeps it reachable only from this machine instead of exposing it to the local network.
- Restart policy: `no`, `MaximumRetryCount: 0`.

### Health

```text
$ docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES        STATUS              PORTS
juice-shop   Up About a minute   127.0.0.1:3000->3000/tcp
```

```text
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
HTTP 200

$ curl -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}

$ curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
46

$ docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Surface

- Login and registration: the top-right Account menu is visible. Login and registration are exposed as part of the account flow.
- Products: the main page shows the product catalog with items such as Apple Juice, Apple Pomace, Banana Juice, and Basil Smoothie. The product API returned 46 products.
- Admin or account area: the page exposes account navigation. The app also makes unauthenticated requests to administrative configuration/version endpoints such as `/rest/admin/application-version` and `/rest/admin/application-configuration`.
- Console errors: no browser console messages were observed during the automated page load. A request to the unexpected path `/api/Products/1/reviews` returned an Express 500 error page and triggered the Juice Shop Error Handling challenge.
- Local storage and cookies: localStorage and sessionStorage were empty on first load. Cookies were set for `continueCode` and `language`; both were not `Secure`, and `continueCode` was not `HttpOnly`.
- Product reviews: `GET /rest/products/1/reviews` returned HTTP 200 without authentication and included review messages and authors.

### Headers

```text
$ curl -sI http://127.0.0.1:3000 | head -20
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sun, 13 Sep 2026 23:44:52 GMT
ETag: W/"26af-1a09d28ce9e"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Sun, 13 Sep 2026 23:46:30 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Header classification:

- `Content-Security-Policy`: missing.
- `Strict-Transport-Security`: missing.
- `X-Content-Type-Options`: present, `nosniff`.
- `X-Frame-Options`: present, `SAMEORIGIN`.

### Top 3 risks

1. **Security headers are incomplete** — The application does not send `Content-Security-Policy` or `Strict-Transport-Security`. Missing hardening headers reduce browser-side protection against script injection impact and insecure transport patterns. OWASP Top 10:2025 category: A02 Security Misconfiguration.
2. **Unauthenticated product review access** — Product review data is available through `GET /rest/products/1/reviews` without authentication. Even if product reviews are public by design, the endpoint exposes author identifiers and demonstrates a broad public API surface that should be reviewed before production use. OWASP Top 10:2025 category: A01 Broken Access Control.
3. **Verbose server error page** — Requesting an unexpected API path returned HTTP 500 with an Express error page and stack trace paths. Detailed error output can help attackers map framework internals and route handling behavior. OWASP Top 10:2025 category: A05 Security Logging and Monitoring Failures.

## PR template

- File path: `.github/PULL_REQUEST_TEMPLATE.md`
- Section names: `Goal`, `Changes`, `Testing`, `Artifacts & Screenshots`, `Checklist`
- Checklist items:
  - PR title follows `feat(labN): <topic>`.
  - No secrets or large temp files committed.
  - `submissions/labN.md` exists.
- Draft PR link or screenshot showing the auto-filled description: TODO — create the draft PR after pushing `feature/lab1`, then paste the PR URL here or add a screenshot.

## GitHub community

Stars help open-source maintainers because they show visible interest in a project and make the repository easier for other users to discover. Following the professor, TAs, and classmates helps team projects because it makes people and their repositories easier to find during collaboration and review.

## Bonus: CI smoke test

- Workflow path: `.github/workflows/lab1-smoke.yml`
- Run URL: TODO — paste the GitHub Actions run URL after opening the PR.
- Run duration: TODO — paste the duration from the GitHub Actions run after it completes.
- Curl output excerpt from the job log: TODO — paste the successful polling line from the GitHub Actions job log after the run is green.
