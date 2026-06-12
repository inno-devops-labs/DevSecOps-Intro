# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-AppSec%20Foundations-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Docker%20%2B%20GitHub-informational)

> **Goal:** Deploy OWASP Juice Shop (the course's canonical attack target), produce a triage report, and bootstrap the PR-driven submission workflow you'll use for every subsequent lab.
> **Deliverable:** A PR from `feature/lab1` to the course repo with `.github/PULL_REQUEST_TEMPLATE.md` and `submissions/lab1.md`. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- Deploying **OWASP Juice Shop** (Björn Kimminich's flagship vulnerable web app — Lecture 1, slide 4)
- Producing a **triage report** — the artifact every appsec finding starts as
- Bootstrapping a **PR template** + **submission workflow** for the rest of the course
- Engaging with the open-source community on GitHub (small, but a real DevSecOps habit)

> **You don't write Juice Shop.** You pull and run the official image. The skill is *operating* and *observing* — the same posture you'll use against real targets at work.

---

## Project State

**Starting point:** A GitHub account + Docker installed. This is Week 1.

**After this lab:**
- OWASP Juice Shop running locally on `127.0.0.1:3000`
- A triage report (`submissions/lab1.md`) documenting the deployment + attack surface
- A `.github/PULL_REQUEST_TEMPLATE.md` in your fork that every future PR uses
- (Bonus) A baseline GitHub Actions workflow that smoke-tests Juice Shop on every PR

---

## Setup

You need:
- **Docker** (Docker Desktop on macOS/Windows, or `docker-ce` on Linux). `docker --version` should print `Docker version 26+` (any 26.x/27.x/28.x is fine).
- **Git** ≥ 2.34
- **A GitHub account**
- **`curl`** + **`jq`** (`brew install jq` / `apt install jq` / built-in on most distros)

Fork the course repo, then clone **your fork**:

```bash
git clone https://github.com/<your-username>/DevSecOps-Intro.git
cd DevSecOps-Intro
git switch -c feature/lab1
```

---

## Task 1 — Deploy Juice Shop & Triage Report (6 pts)

**Objective:** Run Juice Shop locally, verify it's working, capture a triage report covering deployment details + initial attack-surface observations.

### 1.1: Deploy Juice Shop

The course pins to **v20.0.0** (released May 2026, Node 24, ~125 MB image — Lecture 1 mentioned this is the leanest the image has been since v8).

```bash
docker run -d --name juice-shop \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop:v20.0.0
```

> **Why `127.0.0.1:3000:3000` and not `-p 3000:3000`?** The former binds **only to localhost**. A bare `-p 3000:3000` exposes the container on every network interface — your laptop becomes a deliberately-vulnerable app on the public network. **One trailing space matters here.**

Wait ~20 seconds for the app to start, then verify it's healthy:

```bash
docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
# v20.0.0 moved /rest/products → /api/Products; verify product count
curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
# Sanity: confirm version
curl -s http://127.0.0.1:3000/rest/admin/application-version | jq
```

You should see HTTP 200 on the homepage, ~46 products from `/api/Products`, and `{"version": "20.0.0"}` from the admin endpoint.

### 1.2: Explore the Surface

Open `http://127.0.0.1:3000` in your browser. Note what you see:

- ✅ Is the landing page loading?
- 🔑 Is there a Login + Registration form? (Should be in the top-right Account menu.)
- 🛒 Are products listed?
- 🛠️ Open DevTools → Application → Local Storage. Anything pre-populated?
- 🌐 In Network tab, watch one product-detail click — note the `/api/Products/<id>/reviews` calls and whether they require auth.

### 1.3: Triage Report

Create `submissions/lab1.md` and **fill in the template below** with your real observations. Don't paraphrase — record what you actually saw.

```markdown
# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: <sha256:... — get from `docker inspect juice-shop --format '{{.Image}}'`>
- Host OS: <e.g. macOS 14.5 / Ubuntu 24.04>
- Docker version: <output of `docker --version`>

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [ ] Yes [ ] No (explain if No)
- Container restart policy: <default `no` or `--restart` flag?>

### Health Check
- HTTP code on `/`: <should be 200>
- API check (first 200 chars of `/rest/products`):
  ```
  <paste output>
  ```
- Container uptime: <output of `docker ps --filter name=juice-shop`>

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [ ] Yes [ ] No — notes: <...>
- Product listing/search present: [ ] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [ ] Yes [ ] No — notes: <...>
- Client-side errors in DevTools console: [ ] Yes [ ] No — notes: <...>
- Pre-populated local storage / cookies: <list what you saw>

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
<paste>
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [ ] `Content-Security-Policy`
- [ ] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **<risk name>** — <why it matters; map to one OWASP Top 10:2025 category>
2. **<risk name>** — <why; map to OWASP>
3. **<risk name>** — <why; map to OWASP>
```

### 1.4: Cleanup (when done)

```bash
docker stop juice-shop
# Keep the container around for future labs — Lab 4 (SBOM), Lab 5 (SAST/DAST), Lab 7 (image scan) all use it
# To remove: docker rm juice-shop
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

Add a section:

```markdown
## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)
```

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

---

## How to Submit

```bash
git add .github/PULL_REQUEST_TEMPLATE.md
git add .github/workflows/lab1-smoke.yml    # only if you did the bonus
git add submissions/lab1.md
git commit -m "feat(lab1): juice shop deploy + PR template + triage report"
git push -u origin feature/lab1
```

Open a PR from `your-fork:feature/lab1` → `course-repo:main`. The PR description should auto-fill with your template — that itself is part of the proof. Submit the PR URL in Moodle.

PR checklist (paste this into your PR body):

```text
- [x] Task 1 done — Juice Shop deployed, triage report in submissions/lab1.md
- [ ] Task 2 done — .github/PULL_REQUEST_TEMPLATE.md created
- [ ] Task 3 done — GitHub stars + follows complete
- [ ] Bonus done — lab1-smoke.yml runs green on this PR
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Juice Shop v20.0.0 container running on `127.0.0.1:3000` (proof: `docker ps` output in submission)
- ✅ Homepage returns HTTP 200; `/rest/products` returns a JSON list
- ✅ Triage report has all six sections filled in with **real** values (no template placeholders left)
- ✅ At least three security headers are correctly identified as present or missing
- ✅ Top 3 risks each mapped to an OWASP Top 10:2025 category (A01–A10)

### Task 2 (3 pts)
- ✅ `.github/PULL_REQUEST_TEMPLATE.md` exists in the fork
- ✅ Template includes all four required sections
- ✅ Template includes a 3-item checklist
- ✅ Auto-fill verified (PR description shows the template before any manual edits)

### Task 3 (1 pt)
- ✅ Starred course repo and simple-container-com/api
- ✅ Following professor, TAs, and 3+ classmates
- ✅ GitHub Community section in submission

### Bonus Task (2 pts)
- ✅ `.github/workflows/lab1-smoke.yml` exists and triggers on `pull_request`
- ✅ Workflow run is **green** on the submitted PR (run URL in submission)
- ✅ Workflow uses `permissions: { contents: read }` at workflow level
- ✅ Smoke test verifies HTTP 200 from Juice Shop within the timeout

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Deploy + Triage | **6** | Container running on localhost-only port + full triage report with real values + headers analysis + 3 risks mapped to OWASP Top 10:2025 |
| **Task 2** — PR Template | **3** | All 4 sections + 3-item checklist + auto-fill working on a real PR |
| **Task 3** — GitHub Community | **1** | Stars, follows, and written explanation |
| **Bonus Task** — CI Smoke Test | **2** | Green workflow run on the submitted PR with proper permissions block and timeout-bounded healthcheck |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — Official project page
- [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/) — The companion book (free, online)
- [Juice Shop v20.0.0 release notes](https://owasp.org/blog/2026/05/13/juice-shop-v20) — What's new
- [GitHub PR Template docs](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository) — File-location conventions
- [GitHub Actions services block](https://docs.github.com/en/actions/using-jobs/running-jobs-in-a-container) — For the bonus
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — Use this to map your top-3 risks

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`-p 3000:3000` exposes Juice Shop on every interface**, including your office WiFi. **Always** use `-p 127.0.0.1:3000:3000` for any deliberately-vulnerable app. Use `docker network inspect bridge` to verify.
- 🚨 **`docker ps` shows nothing** — the container exited. Check `docker logs juice-shop` for the actual error. Most common: another process on port 3000 (run `lsof -i :3000` or `ss -ltnp | grep 3000`).
- 🚨 **`/rest/products` returns 404 in v20.0.0** — Juice Shop's API moved. Use `/api/Products` (capital P, returns `{data: [...]}` envelope) for product listing. Use `/rest/admin/application-version` for a simple JSON health check.
- 🚨 **API returns empty/502 instead of JSON** — Juice Shop takes ~20s to fully start on a cold image. Wait, then re-curl.
- 🚨 **PR template doesn't auto-fill** — file must be exactly `.github/PULL_REQUEST_TEMPLATE.md` (capital + singular). Variants like `.github/PR_TEMPLATE.md` or `.github/pull_request_template.md` (lowercase) work too — but be consistent in your fork.
- 🚨 **Bonus workflow times out** — Juice Shop v20.0.0 needs ~20-30s in CI. Don't set your loop to 10s and quit.
- 🚨 **Bonus workflow uses `pull_request_target` instead of `pull_request`** — Lecture 4 covers why that's a critical-class PPE bug. For this lab: use `pull_request`, period.
- 🚨 **Forgetting to set the workflow's `permissions:` block** — defaults are write on many older repos. Explicitly set `contents: read` at workflow level.
- 💡 **Image digest:** `docker inspect juice-shop --format '{{.Image}}'` gives you the digest for the triage report. Pin to digest in real production work (Lecture 4 — SHA-pinning for actions, same principle for images).

</details>

<details>
<summary>🪜 Looking ahead</summary>

Juice Shop will be the target throughout the course. Future labs that re-use what you set up here:
- **Lab 3** (Secure Git) — sign your `feature/labN` commits
- **Lab 4** (SBOM/SCA) — generate an SBOM of the v20.0.0 image you ran today
- **Lab 5** (SAST/DAST) — scan Juice Shop source + run ZAP against the running container
- **Lab 7** (Container Security) — Trivy scan + Docker Bench on the same image
- **Lab 8** (Supply Chain) — rebuild + sign your own version with Cosign
- **Lab 10** (Vuln Management) — import every prior lab's findings on Juice Shop into DefectDojo

Get the deployment right today; it pays for the entire semester.

</details>
