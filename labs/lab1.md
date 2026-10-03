# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-AppSec%20Foundations-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Docker%20%2B%20GitHub-informational)

> **Goal:** Run OWASP Juice Shop locally, write a triage report on what you see, and set up the PR workflow you will use for every lab.
> **Deliverable:** A PR from `feature/lab1` with `.github/PULL_REQUEST_TEMPLATE.md` and `submissions/lab1.md`. Submit the PR link via Moodle.
> **Used by:** Labs 4, 5, 7, 8 and 10 generate the SBOM of, scan, sign and triage this same image.

## Setup

- Docker 26 or newer (`docker --version`), Git 2.34 or newer, `curl`, `jq` (`brew install jq` or `apt install jq`), a GitHub account.
- Fork the course repo, clone your fork, create the branch:

<!-- verify:skip student fork clone -->
```bash
git clone https://github.com/<your-username>/DevSecOps-Intro.git
cd DevSecOps-Intro
git switch -c feature/lab1
```

## Task 1 — Deploy Juice Shop and write a triage report (6 pts)

### 1.1 Run it

You do not build Juice Shop; you run the official image and observe it, the same posture you take with a production system. The course pins `v20.0.0`.

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

`127.0.0.1:3000:3000` binds to localhost only. A bare `-p 3000:3000` publishes a vulnerable-by-design app on every interface, including the dorm Wi-Fi.

Wait about 20 seconds, then:

<!-- verify:wait 25 -->
```bash
docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
curl -s http://127.0.0.1:3000/rest/admin/application-version
curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
```

Expected: `HTTP 200`, `{"version":"20.0.0"}`, `46`, and one `bkimminich/juice-shop@sha256:...` line. That digest goes into your report.

### 1.2 Look around

Open http://127.0.0.1:3000 in a browser and note what you find: the login and registration forms (Account menu, top right), the product list, any admin or account area you can discover, errors in the DevTools console, anything pre-populated in Application → Local Storage or cookies. In the Network tab click one product and watch the requests (`/api/Products/<id>/reviews` and similar): do they need authentication?

Security headers:

```bash
curl -sI http://127.0.0.1:3000 | head -20
```

Decide which of these four are present: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`. Missing security headers fall under OWASP Top 10:2025 A02, Security Misconfiguration.

### 1.3 Report

Create `submissions/lab1.md` with a section `## Triage report` that contains:

- Asset: image tag, image digest, host OS, Docker version.
- Deployment: the run command, access URL, whether the port is bound to localhost only and why that matters, restart policy.
- Health: HTTP code on `/`, the version and product-count outputs, the `docker ps` line.
- Surface: the five things you looked for in 1.2 (login and registration, products, admin or account area, console errors, local storage and cookies), in your own words.
- Headers: the `curl -sI` output and which of the four headers are missing.
- Top 3 risks: a name, 2-3 sentences on why it matters, and one OWASP Top 10:2025 category (A01 to A10) for each.

Actual values only. A placeholder left in the report costs points.

### 1.4 Keep the container

<!-- verify:skip stops the container later blocks need -->
```bash
docker stop juice-shop   # do not `docker rm`: Labs 4, 5 and 7 reuse this image
```

## Task 2 — PR template (3 pts)

Create `.github/PULL_REQUEST_TEMPLATE.md` in your fork. GitHub pre-fills every new PR description with it.

Required sections: **Goal** (one sentence), **Changes** (bullet list), **Testing** (commands and observed output), **Artifacts & Screenshots**.

Required checklist items: title follows `feat(labN): <topic>`; no secrets or large temp files committed; `submissions/labN.md` exists.

Test it: push the branch and open a draft PR. The description box must show your template before you type anything.

**Submit:** a section `## PR template` in `submissions/lab1.md` with the file path, the section names, the checklist items, and a link to the draft PR (or a screenshot) showing the auto-filled description.

## Task 3 — GitHub community (1 pt)

1. Star the course repository and [simple-container-com/api](https://github.com/simple-container-com/api).
2. Follow the professor [@Cre-eD](https://github.com/Cre-eD) and the TAs [@Naghme98](https://github.com/Naghme98) and [@pierrepicaud](https://github.com/pierrepicaud).
3. Follow at least three classmates.

**Submit:** a section `## GitHub community` with 1-2 sentences on why stars matter to open-source maintainers and how following people helps in team projects.

## Bonus — Smoke test in GitHub Actions (2 pts)

A preview of Lecture 4 on CI/CD security. Write `.github/workflows/lab1-smoke.yml`:

```yaml
# YOUR TASK: smoke-test Juice Shop on every PR
# Requirements:
#   - on: pull_request to main; runs-on: ubuntu-latest
#   - permissions: { contents: read } at workflow level
#   - starts bkimminich/juice-shop:v20.0.0 (a services: block, or docker run -d in a step)
#   - polls http://localhost:3000/rest/admin/application-version with `curl --silent --fail`
#     for up to 60 seconds; the job fails if it never gets a 200
# Hints:
#   - services: https://docs.github.com/en/actions/using-jobs/running-jobs-in-a-container
#   - Juice Shop needs 20-30 seconds to start in CI; a 10-second loop fails
#   - use pull_request, not pull_request_target (Lecture 4 explains why)
#   - a tag pin is accepted in this first workflow; Lecture 4 covers pinning by digest
```

Push, open the draft PR, and make the run green.

**Submit:** a section `## Bonus: CI smoke test` with the workflow path, the run URL, the run duration, and the curl output excerpt from the job log.

## Acceptance criteria

- Task 1 (6): `docker ps` shows the v20.0.0 container bound to `127.0.0.1:3000`; version and product-count outputs pasted; digest is a `sha256:` value from `RepoDigests`; all six report items filled with actual values; at least three of the four headers correctly classified as present or missing; three risks, each mapped to an A01 to A10 category.
- Task 2 (3): template file exists with the four sections and the three checklist items; auto-fill shown on a real PR.
- Task 3 (1): stars and follows done; section written.
- Bonus (2): workflow triggers on `pull_request`, sets `permissions: contents: read` at workflow level, polls with a timeout, and the run on the submitted PR is green.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab1.md> (.github/PULL_REQUEST_TEMPLATE.md submissions/lab1.md, bonus: .github/workflows/lab1-smoke.yml, ...)
git commit -m "feat(lab1): juice shop deploy + PR template + triage report"
git push -u origin feature/lab1
```

Open a PR from `your-fork:feature/lab1` to `course-repo:main`. The description should auto-fill from your template. Submit the PR URL in Moodle.


## Common pitfalls

- `docker ps` shows nothing: the container exited. Run `docker logs juice-shop`; usually port 3000 is taken (`ss -ltnp | grep 3000` or `lsof -i :3000`).
- `/rest/products` returns 500 in v20: the product API is `/api/Products` (capital P, `{"data": [...]}` envelope). Use `/rest/admin/application-version` as the health check.
- Empty JSON or connection refused right after start: wait 20 seconds and retry.
- `docker inspect juice-shop --format '{{.Image}}'` prints the local image ID, not the registry digest. Use `RepoDigests` on the image, as in 1.1.
- The PR template does not appear: the file must be `.github/PULL_REQUEST_TEMPLATE.md` (lowercase `pull_request_template.md` also works; pick one).
- The bonus workflow times out: poll for 60 seconds, not 10.

## Resources

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/), the free companion book
- [Juice Shop v20.0.0 release](https://github.com/juice-shop/juice-shop/releases/tag/v20.0.0)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/), for mapping your three risks
- [Creating a pull request template](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository)
- [GitHub Actions service containers](https://docs.github.com/en/actions/using-jobs/running-jobs-in-a-container)
