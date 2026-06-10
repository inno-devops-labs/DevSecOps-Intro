## Goal
Deploy OWASP Juice Shop, create triage report, and bootstrap PR workflow.

## Changes
- Added `.github/PULL_REQUEST_TEMPLATE.md`
- Added `submissions/lab1.md`
- Added CI smoke test workflow `.github/workflows/lab1-smoke.yml`

## Testing
- Deployed locally via `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Verified HTTP 200 and API responses on localhost
- CI: Verified that GitHub Actions successfully builds and smoke-tests the Juice Shop container

## Artifacts & Screenshots
- Triage report included in `submissions/`.
- CI workflow execution is visible in the PR Checks tab.

## Checklist
- [x] Title is clear (`feat(labN): <topic>` style)
- [x] No secrets/large temp files committed
- [x] Submission file at `submissions/labN.md` exists
