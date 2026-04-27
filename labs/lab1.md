# Lab 1 — Setup OWASP Juice Shop & PR Workflow

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-AppSec%20Basics-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Run OWASP Juice Shop locally, complete a triage report, and standardize PR submissions.  
> **Deliverable:** A PR from `feature/lab1` to the course repo with `labs/submission1.md` containing triage report and PR template setup. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Launching **OWASP Juice Shop** for security testing
- Capturing a **triage report** covering version, URL, health check, exposure, risks, and next actions
- Bootstrapping a **repeatable PR workflow** with a template

> We **do not** copy Juice Shop code into the repo. You'll run the official Docker image and keep **only lab artifacts** in your fork.

---

## Tasks

### Task 1 — OWASP Juice Shop Deployment (5 pts)

**Objective:** Run Juice Shop locally and complete a Triage report capturing deployment, health check, exposure, and top risks.

#### 1.1: Deploy Juice Shop Container

```bash
docker run -d --name juice-shop \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop:v19.0.0
```

#### 1.2: Initial Verification

- Browse to `http://localhost:3000` and confirm the app loads
- Verify API responds: `curl -s http://127.0.0.1:3000/rest/products | head`

#### 1.3: Complete Triage Report

Create `labs/submission1.md` using this template:

```markdown
# Triage Report — OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: <link> — <date>
- Image digest (optional): <sha256:...>

## Environment
- Host OS: <e.g., macOS 14.5 / Ubuntu 22.04>
- Docker: <e.g., 24.0.x>

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [ ] Yes  [ ] No  (explain if No)

## Health Check
- Page load: attach screenshot of home page (path or embed)
- API check: first 5–10 lines from `curl -s http://127.0.0.1:3000/rest/products | head`

## Surface Snapshot (Triage)
- Login/Registration visible: [ ] Yes  [ ] No — notes: <...>
- Product listing/search present: [ ] Yes  [ ] No — notes: <...>
- Admin or account area discoverable: [ ] Yes  [ ] No — notes: <...>
- Client-side errors in console: [ ] Yes  [ ] No — notes: <...>
- Security headers (quick look — optional): `curl -I http://127.0.0.1:3000` → CSP/HSTS present? notes: <...>

## Risks Observed (Top 3)
1) <risk + 1‑line rationale>
2) <risk + 1‑line rationale>
3) <risk + 1‑line rationale>
```

In `labs/submission1.md`, document:
- Complete triage report using provided template
- Screenshots or API output demonstrating working deployment
- Environment details and security observations
- Analysis of top 3 security risks identified during assessment

---

### Task 2 — PR Template Setup (4 pts)

**Objective:** Standardize submissions so every lab PR has the same sections and checks.

#### 2.1: Create PR Template

Create `.github/pull_request_template.md` with:
- Sections: **Goal**, **Changes**, **Testing**, **Artifacts & Screenshots**
- Checklist (3 items): clear title, docs updated if needed, no secrets/large temp files

```bash
# Commit message example:
git commit -m "docs: add PR template"
```

#### 2.2: Verify Template Application

```bash
git checkout -b feature/lab1
git add labs/submission1.md
git commit -m "docs(lab1): add submission1 triage report"
git push -u origin feature/lab1
```

Verify that:
- PR description auto-fills with sections & checklist
- Fill in **Goal / Changes / Testing / Artifacts & Screenshots** and tick checkboxes
- Screenshots and API snippet are embedded in `labs/submission1.md`

In `labs/submission1.md`, document:
- PR template creation process and verification
- Evidence that template auto-fills correctly
- Analysis of how templates improve collaboration workflow

<details>
<summary>One-time Bootstrap Note</summary>

GitHub loads PR templates from the **default branch of your fork (`main`)**. Add the template to `main` first, then open your lab PR from `feature/lab1`.

</details>

---

### Task 6 — GitHub Community Engagement (1 pt)

**Objective:** Explore GitHub's social features that support collaboration and discovery.

**Actions Required:**
1. **Star** the course repository
2. **Star** the [simple-container-com/api](https://github.com/simple-container-com/api) project — a promising open-source tool for container management
3. **Follow** your professor and TAs on GitHub:
   - Professor: [@Cre-eD](https://github.com/Cre-eD)
   - TA: [@marat-biriushev](https://github.com/marat-biriushev)
   - TA: [@pierrepicaud](https://github.com/pierrepicaud)
4. **Follow** at least 3 classmates from the course

**Document in labs/submission1.md:**

Add a "GitHub Community" section (after Challenges & Solutions) with 1-2 sentences explaining:
- Why starring repositories matters in open source
- How following developers helps in team projects and professional growth

<details>
<summary>💡 GitHub Social Features</summary>

**Why Stars Matter:**

**Discovery & Bookmarking:**
- Stars help you bookmark interesting projects for later reference
- Star count indicates project popularity and community trust
- Starred repos appear in your GitHub profile, showing your interests

**Open Source Signal:**
- Stars encourage maintainers (shows appreciation)
- High star count attracts more contributors
- Helps projects gain visibility in GitHub search and recommendations

**Professional Context:**
- Shows you follow best practices and quality projects
- Indicates awareness of industry tools and trends

**Why Following Matters:**

**Networking:**
- See what other developers are working on
- Discover new projects through their activity
- Build professional connections beyond the classroom

**Learning:**
- Learn from others' code and commits
- See how experienced developers solve problems
- Get inspiration for your own projects

**Collaboration:**
- Stay updated on classmates' work
- Easier to find team members for future projects
- Build a supportive learning community

**Career Growth:**
- Follow thought leaders in your technology stack
- See trending projects in real-time
- Build visibility in the developer community

**GitHub Best Practices:**
- Star repos you find useful (not spam)
- Follow developers whose work interests you
- Engage meaningfully with the community
- Your GitHub activity shows employers your interests and involvement

</details>

---

## How to Submit

1. Create a branch for this lab and push it to your fork:

   ```bash
   git switch -c feature/lab1
   # create labs/submission1.md with your findings
   git add labs/submission1.md
   git commit -m "docs: add lab1 submission"
   git push -u origin feature/lab1
   ```

2. Open a PR from your fork's `feature/lab1` branch → **course repository's main branch**.

3. In the PR description, include:

   ```text
   - [x] Task 1 done — OWASP Juice Shop deployment + triage report
   - [x] Task 2 done — PR template setup + verification
   - [x] Task 6 done — GitHub community engagement
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Acceptance Criteria

- ✅ Branch `feature/lab1` exists with commits for each task
- ✅ File `labs/submission1.md` contains required triage report for Tasks 1, 2, and 6
- ✅ OWASP Juice Shop successfully deployed and documented
- ✅ File `.github/pull_request_template.md` exists on **main** branch
- ✅ GitHub community engagement completed (stars and follows)
- ✅ PR from `feature/lab1` → **course repo main branch** is open
- ✅ PR link submitted via Moodle before the deadline
- ✅ **No Juice Shop source code** copied into repo—only lab artifacts

---

## Rubric (10 pts)

| Criterion                                                | Points |
| -------------------------------------------------------- | -----: |
| Task 1 — OWASP Juice Shop deployment + triage report    |  **5** |
| Task 2 — PR template setup + verification               |  **4** |
| Task 6 — GitHub community engagement                     |  **1** |
| **Total**                                                | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission1.md`
- Include both command outputs and written analysis for each task
- Document deployment process and security observations
- Ensure screenshots and evidence demonstrate working setup

<details>
<summary>Security Notes</summary>

- Always bind to `127.0.0.1` to avoid exposing the app beyond localhost
- Pin specific Docker image versions for reproducibility
- Never commit application source code—only lab artifacts and reports

</details>

<details>
<summary>Deployment Tips</summary>

- Check GitHub Releases page for specific version dates and notes
- Verify API endpoints respond before completing triage report
- Document all observed security issues in the triage template
- Keep deployment commands simple and well-documented

</details>