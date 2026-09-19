# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset

- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Windows 11
- Docker version: Docker version 29.1.3, build f52814d

### Deployment Details

- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: default `no`

### Health Check

- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`): 46 products
- Container uptime:

```
NAMES        STATUS         PORTS
juice-shop   Up 11 minutes   127.0.0.1:3000->3000/tcp
```

### Initial Surface Snapshot (from browser exploration)

- Login/Registration visible: [x] Yes [ ] No — notes: Account menu top-right, Login + Register forms functional
- Product listing/search present: [x] Yes [ ] No — notes: Grid view with search bar, 46 products loaded
- Admin or account area discoverable: [x] Yes [ ] No — notes: `/administration` hinted in page source, no access control visible
- Client-side errors in DevTools console: [ ] Yes [x] No — notes: console clean on landing
- Pre-populated local storage / cookies: token, bid, email keys present with placeholder values; welcomebanner_status = dismiss. In cookies was found language cookie with value en.

### Security Headers (Quick Look)

Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:

```
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
Last-Modified: Thu, 11 Jun 2026 18:32:39 GMT
ETag: W/"26af-19eb7f52f1f"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 19:20:21 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)

- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)

1. — No CSP, HSTS, or clickjacking protection. Any XSS payload injected will execute without browser-enforced restrictions. The X-Recruitment header leaks internal tech stack (Express).
2. — `/administration` path is referenced in client-side code with no server-side enforcement. The app trusts client-side visibility to hide admin functions. An attacker enumerating paths or reading page source lands directly on administrative controls — classic direct object reference pattern.
3. — tdoken and email keys in localStorage with placeholder values suggest stateless JWT-based auth persisted client-side. No HttpOnly/Secure flags possible in localStorage. Any XSS instantly steals session tokens.

### 1.4: Cleanup (when done)

```bash
docker stop juice-shop
# Keep the container around for future labs — Lab 4 (SBOM), Lab 5 (SAST/DAST), Lab 7 (image scan) all use it
# To remove: docker rm juice-shop
```

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
- [x] Title is clear (`feat(lab1): Triage Report: OWASP Juice Shop`)
- [x] No secrets/large temp files committed
- [x] `submissions/lab1.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template (open the PR from feature/lab1)

### Task 3 — GitHub Community Engagement (1 pt)

### Actions completed

1. [x] Starred [inno-devops-labs/DevSecOps-Intro](https://github.com/inno-devops-labs/DevSecOps-Intro)
2. [x] Starred [simple-container-com/api](https://github.com/simple-container-com/api)
3. Following professor and TAs on GitHub:
   - [x] [@Cre-eD](https://github.com/Cre-eD) (professor)
   - [x] [@Naghme98](https://github.com/Naghme98) (TA)
   - [x] [@pierrepicaud](https://github.com/pierrepicaud) (TA)

- Following 3 classmates:
  - [x] [@m1d0rfeed](https://github.com/m1d0rfeed)
  - [x] [@Meliman1000-7](https://github.com/Meliman1000-7)
  - [x] [@RC-5555](https://github.com/labRC-5555)

### Why stars matter

Starring repositories helps projects find their audience and contributors, while also showing maintainers that their work matters.

Following developers keeps you informed about their activity, lays the groundwork for collaboration, and exposes you to approaches that accelerate your professional growth.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): [<link to Actions run>](https://github.com/Maflock/DevSecOps-Intro/actions/runs/27378571404/job/80909140566)
- Workflow run duration: 29s
- Curl response excerpt:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 21:28:49 GMT
ETag: W/"26af-19eb89678fe"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 21:28:51 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
