# Lab 1 — Submission

## Triage Report — OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Release link/date: [v20.0.0](https://github.com/juice-shop/juice-shop/releases/tag/v20.0.0) — May 13, 2026
- Image digest: `sha256:e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9`

### Environment
- Host OS: `macOS 26.3.1`
- Docker: `Docker version 29.4.3, build 055a478`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No

### Health Check
1.sofia@Faro-2 DevSecOps-Intro % docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```HTTP
NAMES        STATUS          PORTS
juice-shop   Up 37 seconds   127.0.0.1:3000->3000/tcp
```

2. sofia@Faro-2 DevSecOps-Intro % curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
```HTTP
HTTP 200
```

3. sofia@Faro-2 DevSecOps-Intro % curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
```HTTP
46
```

4. sofia@Faro-2 DevSecOps-Intro % curl -s http://127.0.0.1:3000/rest/admin/application-version | jq
```HTTP
{
  "version": "20.0.0"
}
```

5. Container uptime: Up 2 minutes

### Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes [ ] No — Account icon in the top right corner. Clicking reveals Login / Register forms.
- Product listing/search present: [x] Yes [ ] No - Home page displays a grid of products; search is available.
- Admin or account area discoverable: [x] Yes [ ] No — After login, account panel appears. Admin panel accessible at `/#/administration` (admin only).
- Client-side errors in console: [x] Yes [ ] No — Console shows `Failed to load resource: /socket.io/` error (does not affect functionality).
- Pre-populated local storage / cookies: On first visit `localStorage` is empty. After login, `token`, `bid`, `wishlist` appear. Cookies: `continueCode`, `cookieconsent_status`, `welcomebanner_status`.

### Security Headers (curl -I)
1. sofia@Faro-2 DevSecOps-Intro % curl -I http://127.0.0.1:3000 2>&1 | head -20
```HTTP
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 11:21:36 GMT
ETag: W/"26af-19eb144309f"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 11:34:07 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
2. **Missing:** `Content-Security-Policy`, `Strict-Transport-Security`.  
3. **Present:** `X-Content-Type-Options`, `X-Frame-Options`.

### Risks Observed (Top 3)

1. **Missing Content-Security-Policy** — A06:2025 Insecure Design. Without CSP, the browser cannot block execution of arbitrary scripts, making XSS attacks critically dangerous.
2. **Missing Strict-Transport-Security** — A06:2025 Insecure Design. HSTS prevents downgrade attacks to HTTP; its absence allows traffic interception.
3. **CORS Misconfiguration (`Access-Control-Allow-Origin: *`)** — A02:2025 Security Misconfiguration. Allowing any origin to interact with the API opens the door to CSRF-like attacks.

## PR Template Setup

1. PR Template Creation Process - did it manually on github
2. Template Content:
```HTTP
## Goal
Lab 1: Deploy OWASP Juice Shop, add triage report and PR template.

## Changes
- submissions/lab1.md
- .github/pull_request_template.md

## Testing
- docker ps → container running
- curl http://127.0.0.1:3000 → HTTP 200

## Artifacts
- [submissions/lab1.md](submissions/lab1.md)

## Checklist
- [ ] Clear PR title (feat(lab1): ...)
- [ ] No secrets or large temp files committed
- [ ] Submission file at submissions/lab1.md exists
```
3. Commit and push the template - did it manually on github
4. How Templates Improve Collaboration Workflow?
- PR templates transform the code review process from a chaotic exchange of messages into a structured workflow. This is especially valuable in educational projects where students are learning proper collaborative development practices.

### GitHub Community

Starred repositories:
- DevSecOps-Intro course repo
- simple-container-com/api

Following:
- @Cre-eD, @Naghme98, @pierrepicaud, + 3 classmates: @wannebetheshy, @Nopef, @lashmanovSergey

Why starring repositories matters in open source:
- Stars serve as bookmarks for personal use and public endorsement, helping projects gain visibility, attract contributors, and show support for maintainers.

How following developers helps in team projects and professional growth:
- Following allows you to see what colleagues are working on, track their insights and projects, which accelerates team productivity and personal development within the community.
