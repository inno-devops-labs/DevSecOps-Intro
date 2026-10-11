## Goal

This PR delivers Lab 1: OWASP Juice Shop deployment, triage report, and PR workflow setup.

## Changes

- Added `submissions/lab1.md`
- Added `.github/PULL_REQUEST_TEMPLATE.md`
- Documented Juice Shop deployment details, health checks, browser exploration, security headers, and observed risks

## Testing

Commands and observed outputs used to verify this PR:

### Container status

```bash
docker ps --filter name=juice-shop
```

Observed output:

```text
CONTAINER ID   IMAGE                            COMMAND                  CREATED          STATUS          PORTS                      NAMES
4cf4ae3bf6ab   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   57 minutes ago   Up 57 minutes   127.0.0.1:3000->3000/tcp   juice-shop
```

### Homepage health check

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
```

Observed output:

```text
HTTP 200
```

### Product API check

```bash
curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
```

Observed output:

```text
46
```

### Application version check

```bash
curl -s http://127.0.0.1:3000/rest/admin/application-version | jq
```

Observed output:

```json
{
  "version": "20.0.0"
}
```

### Security headers quick look

```bash
curl -I http://127.0.0.1:3000 2>&1 | head -20
```

Observed output:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 17:13:54 GMT
ETag: W/"26af-19ebcd37167"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 18:00:03 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

## Artifacts & Screenshots

- Submission file: `submissions/lab1.md`
- PR template: `.github/PULL_REQUEST_TEMPLATE.md`
- Screenshot evidence: Docker Desktop container view and OWASP Juice Shop browser page

## Checklist

- [ ] Title is clear (`feat(labN): <topic>` style)
- [ ] No secrets/large temp files committed
- [ ] Submission file at `submissions/labN.md` exists
