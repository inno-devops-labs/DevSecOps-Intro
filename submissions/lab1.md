## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:... — get from `docker inspect juice-shop --format '{{.Image}}'`>
- Host OS: <Windows 11 Pro 24H2 IoT>
- Docker: <Docker version 29.4.0, build 9d7ad9f>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:6767:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:6767
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: <no>

### Health Check
- HTTP code on `/`: <200>
- API check (first 200 chars of ~`/rest/products`~ 'api/Products'):
  ```
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T10:10:24.965Z"
  ```
- Container uptime: <Up 8 hours>

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: <in the top right corner > ![login](embeddings/l1_login.png)
- Product listing/search present: [x] Yes [ ] No — notes: <search bar in the top, products in the main page>
- Admin or account area discoverable: [ ] Yes [x] No — notes: <admin area hidden, account area is visible, but does nothing then clicked>
- Client-side errors in DevTools console: [x] Yes [ ] No — notes: <UNSUPPORTED_OS, no supported format found > ![errors](embeddings/l1_errors.png)
- Pre-populated local storage / cookies: <language, welcomeBannerStatus, continueCode, welcomebanner_status> ![cookie](embeddings/l1_cookie.png)

### Security Headers (Quick Look)
Run: ` Invoke-WebRequest http://127.0.0.1:6767 -Method Head`. Paste output:
```
StatusCode        : 200
StatusDescription : OK
Content           : 
RawContent        : HTTP/1.1 200 OK
                    Access-Control-Allow-Origin: *
                    X-Content-Type-Options: nosniff
                    X-Frame-Options: SAMEORIGIN
                    Feature-Policy: payment 'self'
                    X-Recruiting: /#/jobs
                    Accept-Ranges: bytes
                    Cache-Contro…
Headers           : {[Access-Control-Allow-Origin, System.String[]], [X-Content-Type-Options, System.String[]], [X-Frame-Options, System.String[]], [Feature-Policy, System.String[]]…}
Images            : {}
InputFields       : {}
Links             : {}
RawContentLength  : 0
RelationLink      : {}
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Security Headers (OWASP A05/A06)** — Several security-related HTTP headers are missing, including Content-Security-Policy and Strict-Transport-Security. Missing headers can make the application more vulnerable to attacks such as XSS or protocol downgrade attacks. This is related to OWASP Top 10 A05: Security Misconfiguration.
2. **Public API Exposure (OWASP A01)** — Several API endpoints appear accessible without authentication. Public endpoints increase the application's attack surface and may expose data that should be protected if access controls are not properly implemented. This relates to OWASP A01: Broken Access Control.
3. **Client-Side Data Storage (OWASP A01)** — The application stores data in browser local storage. While the observed values are not sensitive, storing security-relevant information in local storage can increase the impact of cross-site scripting attacks. This is related to OWASP A01: Broken Access Control and general client-side security concerns.
```



---

## Task 2 — PR Template Setup (3 pts)

**Objective:** Create a `.github/PULL_REQUEST_TEMPLATE.md` in your fork. Every PR from `feature/labN` will auto-fill this template — this is the workflow you'll use for the entire semester.

### 2.1: Create the template

```bash
mkdir -p .github
# YOUR TASK: create .github/PULL_REQUEST_TEMPLATE.md
```

Required sections (the template must include all four):

1. **Goal** — what this PR delivers (1 sentence)
2. **Changes** — bullet list of artifacts added/modified
3. **Testing** — how you verified it works (commands + observed output)
4. **Artifacts & Screenshots** — links to files in this PR, image embeds where useful

Required checklist (the template must include all three items):

- [ ] Title is clear (`feat(labN): <topic>` style)
- [ ] No secrets/large temp files committed
- [ ] Submission file at `submissions/labN.md` exists

> **Hint:** GitHub auto-detects `.github/PULL_REQUEST_TEMPLATE.md` and pre-fills the PR description box. To test, push the branch and open a PR draft — the template should appear before you write a single word.

### 2.2: Document in `submissions/lab1.md`


## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts / Checklist / Personal Notes
- Checklist items: Title is clear (`feat(labN): <topic>`), No secrets/large temp files committed, `submissions/labN.md` exists
- Auto-fill verified: [x] Yes — PR description showed my template [pr](embeddings/l1_pr.png)


---

## Task 3 — GitHub Community Engagement (1 pt)

**Objective:** Explore GitHub's social features that support collaboration and discovery.

**Actions Required:**
1. **Star** the course repository
2. **Star** the [simple-container-com/api](https://github.com/simple-container-com/api) project — a promising open-source tool for container management
3. **Follow** your professor and TAs on GitHub:
   - Professor: [@Cre-eD](https://github.com/Cre-eD)
   - TA: [@Naghme98](https://github.com/Naghme98)
   - TA: [@pierrepicaud](https://github.com/pierrepicaud)
4. **Follow** at least 3 classmates from the course

**Add to `submissions/lab1.md`:**

A "GitHub Community" section with 1-2 sentences explaining:
- Why starring repositories matters in open source
- How following developers helps in team projects and professional growth

<details>
<summary>💡 GitHub Social Features</summary>

**Why Stars Matter:**
- Stars help you bookmark interesting projects for later reference
- Star count indicates project popularity and community trust
- Starred repos appear in your GitHub profile, showing your interests
- Stars encourage maintainers and help projects gain visibility

**Why Following Matters:**
- See what other developers are working on
- Discover new projects through their activity
- Build professional connections beyond the classroom
- Stay updated on classmates' work for future collaboration

</details>

---

## Bonus Task — Smoke-Test Workflow in GitHub Actions (2 pts)

> 🌟 **Genuinely challenging — not just wiring.** This task previews Lecture 4 (CI/CD Security). You'll write a real workflow that runs Juice Shop in CI and verifies it works.

**Objective:** Create `.github/workflows/lab1-smoke.yml` that, on every PR, pulls Juice Shop, runs it as a service, curls the homepage, and fails the build if Juice Shop doesn't respond healthy.

### B.1: Write the workflow

```yaml
# .github/workflows/lab1-smoke.yml
# YOUR TASK: Smoke-test Juice Shop in CI
# Requirements:
#   - Triggers on pull_request to main
#   - Uses ubuntu-latest runner
#   - permissions: { contents: read } at workflow level (Lecture 4, slide 7)
#   - Pulls bkimminich/juice-shop:v20.0.0 (pin the tag — recall Lecture 4 SHA-pinning rationale; we accept a tag here since this is your first workflow)
#   - Runs it as a service or via `docker run -d`
#   - Waits up to 60s for it to be ready (loop with `curl --silent --fail`)
#   - Fails the job if the homepage returns non-200 or never starts
#
# Hints:
#   - GitHub Actions `services:` block is one elegant way (https://docs.github.com/en/actions/using-jobs/running-jobs-in-a-container)
#   - Alternative: a single `steps:` job with `docker run -d` + a polling loop
#   - The polling loop pattern (Juice Shop v20: use /rest/admin/application-version, not /rest/products):
#       for i in $(seq 1 30); do
#         curl --silent --fail http://localhost:3000/rest/admin/application-version >/dev/null && exit 0
#         sleep 2
#       done
#       exit 1
```

### B.2: Verify it runs

1. Commit + push the workflow to `feature/lab1`
2. Open a draft PR
3. The Actions tab should show your workflow running. **It must succeed.**
4. Click the run, expand the smoke-test step, copy the part that shows the curl response

### B.3: Document in `submissions/lab1.md`

```markdown
## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): <link to your Actions run>
- Workflow run duration: <e.g. 45s>
- Curl response excerpt:
  ```
  <paste your "HTTP/1.1 200 OK ..." block>
  ```
```
