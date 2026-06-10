# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce` (from `docker inspect juice-shop --format '{{.Image}}'`)
- Host OS: Ubuntu 24.04 
- Docker version: `Docker version 29.4.0, build 9d7ad9f`

### Deployment Details
- Run command used:

  ```bash
  docker run -d --name juice-shop \
    -p 127.0.0.1:3000:3000 \
    bkimminich/juice-shop:v20.0.0
  ```
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No — container bound to localhost
- Container restart policy: default (`no`)

### Health Check
- HTTP code on `/`: `200`
API check (first 200 chars of `/api/Products`):

  ```json
  {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-10T01:28:01.171Z"...
  ```

- Product count from `/api/Products`: `46`
- Container uptime (sample):

  ```text
  juice-shop   Up 5 seconds   127.0.0.1:3000->3000/tcp
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: account menu has Login/Register
- Product listing/search present: [x] Yes [ ] No — notes: products displayed on landing page
- Admin or account area discoverable: Admin endpoints under `/rest/admin/` discovered via API probe, hidden admin endpoint discoverable via `/#/administration`
- Client-side errors in DevTools console: None observed during initial load
- Pre-populated local storage / cookies: Local storage contains `challenge_*` keys and UI state

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 | head -20`

Example output (trimmed):

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Wed, 10 Jun 2026 01:28:02 GMT
ETag: W/"26af-19eaf24c181"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Wed, 10 Jun 2026 01:28:41 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Missing headers observed:
- `Content-Security-Policy` — missing
- `Strict-Transport-Security` — missing (site served over HTTP)

### Top 3 Risks Observed (2-3 sentences each)
1. **Missing transport-layer protection** — The application is served over HTTP; sensitive tokens and session data can be exposed. Maps to OWASP Top 10:2025 A03 (Sensitive Data Exposure).

2. **Exposed admin endpoints** — Admin API surface under `/rest/admin/*` is discoverable and may be improperly protected; maps to A05 (Broken Access Control).

3. **Sensitive data in client storage** — Local storage contains challenge and state artifacts which could leak secrets if an XSS exists; maps to A06 (Security Misconfiguration / Sensitive Data Exposure).

---

## PR Template Setup

- File added: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist included: Title style, No secrets/large files, `submissions/labN.md` present
- Auto-fill verification: To verify, push `feature/lab1` and open a draft PR — the PR description should pre-fill with this template.

Template (example):

```markdown
## Goal
One-sentence description of what this PR delivers.

## Changes
- List files added or modified

## Testing
- Commands run and observed output

## Artifacts & Screenshots
- Links to submission files and images

- [ ] Title uses `feat(labN): <topic>` style
- [ ] No secrets/large temp files committed
- [ ] `submissions/labN.md` present
```

---

## GitHub Community

- Starred: DevSecOps-Intro (course repo), simple-container-com/api
- Followed: @Cre-eD, @Naghme98, @pierrepicaud, and three classmates

Why: Starring helps discovery and signals interest; following instructors and peers enables collaboration and timely updates.

---

## Bonus: CI Smoke Test (notes)

The smoke-test workflow (`.github/workflows/lab1-smoke.yml`) should:

- Trigger: `pull_request` on `main`
- Use `ubuntu-latest` runner
- Set `permissions: { contents: read }` at workflow level
- Pull `bkimminich/juice-shop:v20.0.0` and run it, then poll `/rest/admin/application-version` up to 60s
- Fail the job if the endpoint never returns HTTP 200

---

## Commands run (copyable)

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'
curl -s http://127.0.0.1:3000/rest/admin/application-version | jq
```

Replace host-specific fields (image digest, host OS, exact docker ps uptime) with the outputs from running these commands on your machine.

---

## Cleanup

```bash
docker stop juice-shop || true
# docker rm juice-shop  # optional
```
