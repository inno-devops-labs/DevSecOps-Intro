# Triage Report - OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v19.0.0`
- Release link/date: https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0 - 2025-09-04
- Image digest (optional): `sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d`

## Environment
- Host OS: Microsoft Windows 11 Pro 10.0.26200
- Docker: 28.0.4

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No

## Health Check
- Page load screenshot: `labs/artifacts/juice-shop-home.png`
- API check (`curl -s http://127.0.0.1:3000/rest/products | head`) output:

```html
<html>
  <head>
    <meta charset='utf-8'>
    <title>Error: Unexpected path: /rest/products</title>
```

- Note: in this image version, `/rest/products` returns `500 Unexpected path`. Product API verified via:

```bash
curl -s http://127.0.0.1:3000/api/Products | python -m json.tool
```

First lines:

```json
{
    "status": "success",
    "data": [
        {
            "id": 1,
            "name": "Apple Juice (1000ml)",
            "description": "The all-time classic.",
```

## Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes  [ ] No - notes: login/account UI visible on home page.
- Product listing/search present: [x] Yes  [ ] No - notes: products rendered and searchable in storefront.
- Admin or account area discoverable: [x] Yes  [ ] No - notes: account menu and admin-related routes are discoverable from UI/challenges.
- Client-side errors in console: [ ] Yes  [x] No - notes: no blocking frontend error observed during initial page load.
- Security headers (quick look - optional): `curl -I http://127.0.0.1:3000` -> CSP/HSTS present? notes: `X-Content-Type-Options` and `X-Frame-Options` present; CSP/HSTS not present in quick check.

## Risks Observed (Top 3)
1. Missing strict transport controls for this deployment context: no HSTS observed, which can weaken HTTPS posture when deployed beyond local.
2. Broad attack surface by design: app intentionally exposes vulnerable flows (auth, search, file handling), so it must stay isolated from non-lab networks.
3. Legacy/unstable endpoint references in lab workflow: expected `/rest/products` endpoint returns 500 in v19.0.0, which can cause false negatives in automation and health checks.

## Task 2 - PR Template Setup

### Creation
- Created `.github/pull_request_template.md` with required sections:
  - Goal
  - Changes
  - Testing
  - Artifacts & Screenshots
- Added checklist items:
  - clear title
  - docs updated if needed
  - no secrets/large temp files

### Verification
- Template exists at repository path `.github/pull_request_template.md`.
- GitHub loads this template from default branch (`main`), so this file was added there first per lab note.
- When opening a PR, description should auto-fill with these sections and checklist, then be completed for each lab submission.

### Workflow Value Analysis
- Enforces consistent review context across submissions.
- Reduces back-and-forth by requiring testing evidence and artifacts upfront.
- Adds a lightweight quality gate against unclear titles and accidental secret/temp-file commits.

## Challenges & Solutions
- Challenge: Docker daemon was initially unavailable (`dockerDesktopLinuxEngine` pipe error).
- Solution: started Docker Desktop, waited for daemon readiness, then redeployed container with localhost-only bind.
- Challenge: lab health-check endpoint `/rest/products` returned 500 on v19.0.0.
- Solution: documented exact behavior and validated application/product API health through `/api/Products`.

## GitHub Community
- Starring repositories improves discoverability and signals which projects the community finds useful and trustworthy.
- Following professors, TAs, and classmates helps track real development activity, improves collaboration awareness, and supports long-term professional growth.
- Completed by API:
  - [x] Starred `inno-devops-labs/DevSecOps-Intro`
  - [x] Starred `simple-container-com/api`
- Follow actions attempted for `@Cre-eD`, `@marat-biriushev`, and `@pierrepicaud` returned API `404` with current credential scope (insufficient follow permissions on this token), so follow operations require interactive GitHub session/manual completion.

## Submission Metadata
- Feature branch: `feature/lab1`
- Open PR: https://github.com/inno-devops-labs/DevSecOps-Intro/pull/408
