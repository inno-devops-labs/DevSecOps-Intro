## Goal
Deploy OWASP Juice Shop locally and perform an initial security assessment including health checks, API exploration, and risk identification.

## Changes
- Added `submissions/lab1.md` with deployment details, health check results, and top 3 OWASP Top 10:2025 risks
- Added `.github/PULL_REQUEST_TEMPLATE.md` for future PR consistency

## Testing
- Deployed locally via `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Verified HTTP 200 and API responses on localhost

## Artifacts & Screenshots
- Report included in `submissions/lab1.md`

## Checklist
- [x] Task 1 done — Juice Shop deployed, triage report in submissions/lab1.md
- [x] Task 2 done — .github/PULL_REQUEST_TEMPLATE.md created
- [ ] Task 3 done — GitHub stars + follows complete
- [x] Bonus done — lab1-smoke.yml runs green on this PR