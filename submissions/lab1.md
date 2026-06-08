# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: `sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`
- Host OS: Kali Linux (rolling), VirtualBox VM
- Docker version: `Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed`

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No — proof:
  ```
  $ docker ps --filter name=juice-shop
  PORTS: 127.0.0.1:3000->3000/tcp

  $ ss -ltnp | grep 3000
  LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("docker-proxy",pid=25324,fd=7))
  ```
- Container restart policy: default `no` (bcs without `--restart` flag)

### Health Check
- HTTP code on `/`: `200`
- API check (first 200 chars of `/rest/products`):
  I have a 500 error due to unexisted path, so I suppose there is another route? Like /rest/products/search or smth like that according to github, but anyway:
 ```
<html>
  <head>
    <meta charset='utf-8'> 
    <title>Error: Unexpected path: /rest/products</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 1      
 ```
- Version check: `curl -s http://127.0.0.1:3000/rest/admin/application-version` → `{"version":"20.0.0"}`
- Product count: `curl -s http://127.0.0.1:3000/api/Products | jq '.data | length'` → ~46
- Container uptime:
  ```
  CONTAINER ID   IMAGE                           COMMAND                  CREATED          STATUS          PORTS                      NAMES
  489503693cac   bkimminich/juice-shop:v20.0.0   "/nodejs/bin/node /j…"   10 minutes ago   Up 10 minutes   127.0.0.1:3000->3000/tcp   juice-shop
  ```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: Account menu (top-right) shows login and registration
- Product listing/search present: [x] Yes [ ] No — notes: product grid on the `/search` route
- Admin or account area discoverable: [x] Yes [ ] No — notes: Yes, but I find the route in the main.js file in the browser `/rest/admin`
- Client-side errors in DevTools console: [x] Yes [] No — notes: Only when I tried to open `/rest/products`
- Pre-populated local storage / cookies: only `language` key in cookies

### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
  % Total    % Received % Xferd  Average Speed  Time    Time    Time  Current
                                 Dload  Upload  Total   Spent    Left  Speed
  0   9903   0      0   0      0      0      0                              0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 08 Jun 2026 15:13:34 GMT
ETag: W/"26af-19ea7cbd7bd"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 08 Jun 2026 15:40:06 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff` — **present**
- [ ] `X-Frame-Options` — **present** (`SAMEORIGIN`)

### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Missing Content-Security-Policy** — The homepage response has no CSP header, so the browser will not restrict which scripts or resources can execute. This is can leads to XSS, CSS injections or XSLeaks in bad cases. A02:2025 Security Misconfiguration

2. **Blind SSRF** in profile section capable to fetch to the localhost network on the route `POST /profile/image/url ` A01:2025 Broken Access Control

3. **IDOR** in `GET /rest/basket/1`. We can see other users's shopping cart. A01:2025 Broken Access Control
---

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items:
  - [ ] Title is clear (`feat(labN): <topic>` style)
  - [ ] No secrets/large temp files committed
  - [ ] Submission file at `submissions/labN.md` exists
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

---

## GitHub Community

- Starred: `inno-devops-labs/DevSecOps-Intro`, `simple-container-com/api`
- Following: @Cre-eD, @Naghme98, @pierrepicaud, + 3 classmates: `jestersw`, `arsenez2006`, `semyonnadutkin`

Stars on GitHub are a simple and clear way to understand how trustworthy a resource is and whether it's truly useful. They also help other users find and promote the tool.

---

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on `main`
- Run URL (must be green): ``
- Workflow run duration: `60`
- Curl response excerpt:
  ```
  w
  ```
