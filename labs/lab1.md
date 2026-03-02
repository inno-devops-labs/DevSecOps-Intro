# Lab 1 — Setup OWASP Juice Shop & PR Workflow

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-AppSec%20Basics-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Run an OWASP Juice Shop locally, complete a triage report, and standardize PR submissions.
> **Deliverable:** A PR from `feature/lab1` to the course repo with `labs/submission1.md` containing triage report and PR template setup. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Launching a **Juice Shop App** for security testing.
- Capturing a **triage report** — version, URL, health check, exposure, risks, and next actions.
- Bootstrapping a **repeatable PR workflow** with a template.

These skills are essential for application security assessment and standardized security documentation workflows.

> We **do not** copy Juice Shop code into the repo. You'll run the official Docker image and keep **only lab artifacts** in your fork.

---

## Tasks

### Task 1 — OWASP Juice Shop Deployment (6 pts)

**Objective:** Run a Juice Shop locally and complete a Triage report to capture the deployment, quick health, exposure, and top risks.

#### 1.1: Deploy Juice Shop Container

1. **Container Deployment:**

   ```bash
   docker run -d --name juice-shop \
     -p 127.0.0.1:3000:3000 \
     bkimminich/juice-shop:v19.0.0
   ```

2. **Initial Verification:**

   - Browse to `http://localhost:3000` and confirm the app loads
   - Verify API responds: `curl -s http://127.0.0.1:3000/rest/products | head`

#### 1.2: Complete Triage Report

1. **Document Security Assessment:**

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

1. **Template Setup:**

   ```bash
   # Path: .github/pull_request_template.md
   # Commit message: docs: add PR template
   ```

2. **Template Requirements:**

   Include these sections and checklist:
   - Sections: **Goal**, **Changes**, **Testing**, **Artifacts & Screenshots**
   - Checklist (3 items): clear title, docs updated if needed, no secrets/large temp files

#### 2.2: Verify Template Application

1. **Create Lab Branch and PR:**

   ```bash
   git checkout -b feature/lab1
   git add labs/submission1.md
   git commit -m "docs(lab1): add submission1 triage report"
   git push -u origin feature/lab1
   ```

2. **Template Verification:**

   - Open PR and verify description auto-fills with sections & checklist
   - Fill in **Goal / Changes / Testing / Artifacts & Screenshots** and tick checkboxes
   - Ensure screenshots and API snippet are embedded in `labs/submission1.md`

In `labs/submission1.md`, document:
- PR template creation process and verification
- Evidence that template auto-fills correctly
- Analysis of how templates improve collaboration workflow

> ⚠️ **One-time bootstrap:** GitHub loads PR templates from the **default branch of your fork (`main`)**. Add the template to `main` first, then open your lab PR from `feature/lab1`.

---

## Acceptance Criteria

- ✅ Branch `feature/lab1` exists with commits for each task.
- ✅ File `labs/submission1.md` contains required triage report for Tasks 1-2.
- ✅ OWASP Juice Shop successfully deployed and documented.
- ✅ File `.github/pull_request_template.md` exists on **main** branch.
- ✅ PR from `feature/lab1` → **course repo main branch** is open.
- ✅ PR link submitted via Moodle before the deadline.
- ✅ **No Juice Shop source code** is copied into the repo—only lab artifacts.

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
   - [x] Task 1 done
   - [x] Task 2 done
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Rubric (10 pts)

| Criterion                                                | Points |
| -------------------------------------------------------- | -----: |
| Task 1 — OWASP Juice Shop deployment + triage report    |  **6** |
| Task 2 — PR template setup + verification               |  **4** |
| **Total**                                                | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission1.md`.
- Include both command outputs and written analysis for each task.
- Document deployment process and security observations.
- Ensure screenshots and evidence demonstrate working setup.

> **Security Notes**  
> 1. Always bind to `127.0.0.1` to avoid exposing the app beyond localhost.  
> 2. Pin specific Docker image versions for reproducibility.  
> 3. Never commit application source code—only lab artifacts and reports.

> **Deployment Tips**  
> 1. Check GitHub Releases page for specific version dates and notes.  
> 2. Verify API endpoints respond before completing triage report.  
> 3. Document all observed security issues in the triage template.  
> 4. Keep deployment commands simple and well-documented.