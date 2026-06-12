# Lab 1 - Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Container image ID from `docker inspect juice-shop --format '{{.Image}}'`: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Microsoft Windows 11 Pro 10.0.26200
- Docker version: `Docker version 29.4.0, build 9d7ad9f`

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No
- Container restart policy: default `no`

### Health Check

- HTTP code on `/`: `HTTP 200`
- Product count from `/api/Products`: `46`
- Application version from `/rest/admin/application-version`:
  ```json
  {"version":"20.0.0"}
  ```
- API check (first 200 chars of `/api/Products`):
  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-12T15:18:22.435Z"
  ```
- Container uptime:
  ```text
  NAMES        STATUS         PORTS
  juice-shop   Up 3 minutes   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No - notes: Headless Edge rendered the navigation and side menu; the Account section exposed a `Login` link at `#/login`.
- Product listing/search present: [x] Yes [ ] No - notes: Search control and product cards loaded. The paginator showed `1 - 16 of 46`, matching the API product count.
- Admin or account area discoverable: [x] Yes [ ] No - notes: The Account menu was visible. The `/rest/admin/application-version` endpoint returned unauthenticated version metadata.
- Client-side errors in DevTools console: [ ] Yes [x] No - notes: No page-blocking client error was observed during headless render. Edge emitted one internal renderer warning unrelated to Juice Shop.
- Pre-populated local storage / cookies: Fresh headless browser profile created `Default/Local Storage/leveldb` metadata only; no app keys matching `token`, `email`, `basket`, `theme`, or `continueCode` were found. The homepage response did not set cookies. The cookie consent banner was visible but not accepted.
- Product detail/reviews observation: `/rest/products/1/reviews` returned `HTTP 200` without authentication and included review messages with author emails. The lab note's `/api/Products/1/reviews` path returned `HTTP 500` with `Unexpected path: /api/Products/1/reviews`.

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Output:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 15:18:27 GMT
ETag: W/"26af-19ebc69bf53"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 15:19:29 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING?

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed

1. **Missing browser policy headers** - The app does not send `Content-Security-Policy` or `Strict-Transport-Security`, which would reduce the impact of script injection and enforce HTTPS in a real deployment. This maps to OWASP Top 10:2025 **A06: Security Misconfiguration** because defensive headers are deployment hardening controls.
2. **Unauthenticated metadata and review access** - Version metadata and product reviews were reachable without authentication, and the reviews endpoint returned author email addresses. This maps to **A01: Broken Access Control** because unauthenticated users can retrieve information that may help enumerate the application.
3. **Unexpected API path returns a verbose 500** - Requesting `/api/Products/1/reviews` returned `HTTP 500` with an error page naming the unexpected path. This maps to **A10: Mishandling of Exceptional Conditions** because an invalid route fails noisily instead of returning a controlled 404/400 response.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - Title is clear (`feat(labN): <topic>` style)
  - No secrets/large temp files committed
  - Submission file at `submissions/labN.md` exists
- Auto-fill verified: [x] Yes - draft PRs were opened and their descriptions used the required template sections:
  - Course PR: https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1004
  - Fork workflow verification PR: https://github.com/4rni4ka/DevSecOps-Intro/pull/1

## GitHub Community

- Starred repositories:
  - `inno-devops-labs/DevSecOps-Intro`
  - `simple-container-com/api`
- Follow actions: blocked by the current `gh` token scope. The token has `gist`, `read:org`, `repo`, and `workflow`, but GitHub requires the `user` scope for `PUT /user/following/{username}`.
- Planned follows after `gh auth refresh -h github.com -s user`: `Cre-eD`, `Naghme98`, `pierrepicaud`, `SamiKO228`, `tayaorshulskaya-oss`, `kvakz`.

Starring repositories matters because it bookmarks useful open-source projects and gives maintainers a public signal that the project is useful. Following developers helps with discovery in team projects because their activity surfaces related work, reviews, forks, and collaboration patterns.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (green): https://github.com/4rni4ka/DevSecOps-Intro/actions/runs/27425310794
- Workflow run duration: about 14 seconds for the `Smoke-test Juice Shop` job (started `2026-06-12T15:24:44Z`, completed `2026-06-12T15:24:58Z`)
- Curl response excerpt:
  ```text
  {"version":"20.0.0"}
  Homepage HTTP status: 200
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: *
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Feature-Policy: payment 'self'
  X-Recruiting: /#/jobs
  Content-Type: application/json; charset=utf-8
  Content-Length: 20
  {"version":"20.0.0"}
  ```
