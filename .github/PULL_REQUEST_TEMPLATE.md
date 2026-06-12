## Goal

This PR delivers Lab 1: OWASP Juice Shop deployment, triage report, and course PR workflow setup.

## Changes

- Added `submissions/lab1.md` with Juice Shop deployment and triage report.
- Added `.github/PULL_REQUEST_TEMPLATE.md` for future lab submissions.
- Documented testing commands, observations, security headers, risks, and GitHub community engagement.

## Testing

Commands used:

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
docker ps --filter name=juice-shop
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
curl -s http://127.0.0.1:3000/rest/admin/application-version | jq
curl -I http://127.0.0.1:3000 2>&1 | head -20
'''

