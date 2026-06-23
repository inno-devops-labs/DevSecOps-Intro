# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
- Host OS: Ubuntu 24.04
- Docker version: Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [X] Yes [ ] No (explain if No)
- Container restart policy: no

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`): {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-06-11T11:43:13.936Z"
- Container uptime: 44 minutes

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [X] Yes [ ] No — notes: <...>
- Product listing/search present: [X] Yes [ ] No — notes: <...>
- Admin or account area discoverable: [X] Yes [ ] No — notes: <...>
- Client-side errors in DevTools console: [ ] Yes [X] No — notes: <...>
- Pre-populated local storage / cookies: 

    In local storage, I saw my token consisting of an array of three parts:
    - 0:"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
    - 1:"eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjQsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJjaGVwdWhvbmthMjM0NUBnbWFpbC5jb20iLCJwYXNzd29yZCI6IjYyN2YzOTEyY2U5NWY0YzRmZDA4MjY0ZGJhM2NiZjA5Iiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiIvYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyNi0wNi0xMSAxMzowODowMy4wODkgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyNi0wNi0xMSAxMzowODowMy4wODkgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNzgxMTgzMjk0fQ"
    - 2:"DcX2MBv-rV1dFnsn46pBexAvLJh0GZheJQftmE2_2zmmulLHJlLQ1prps-JN0CIKQOAO9a5Ad8LWI28XGkRbZUvG7zB4ucaK55G5nNZG9lth41YfQE3ueTWvTd2M7Crw_m0MfkTPThvQHKNjFe9wYPRQ8y_kgvD7GNQlRmLhLVo"

    Cookies:
    - cookieconsent_status: dismisal
    - language: en
    - welcomebanner_status: dismisal


### Security Headers (Quick Look)
Run: `curl -I http://127.0.0.1:3000 2>&1 | head -20`. Paste output:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0  9903    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 12 Jun 2026 07:45:13 GMT
ETag: W/"26af-19ebacacf02"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Fri, 12 Jun 2026 07:50:16 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```
Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [X] `Content-Security-Policy`
- [X] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`


### Top 3 Risks Observed (2-3 sentences each, in your own words)
1. **Secret questions and answers are transmitted to the client in clear text** — <An attacker can get the answer to the secret password and change the password for the user’s account and take over his account; A07>
2. **User is not locked out after multiple incorrect password attempts** — <An attacker can try passwords without hindrance. This allows attacker to find the password for any account; A07>
3. **Open directory ftp** — <The server allows an unauthorized user to view the contents of the ftp directory and download files; A01>

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## Github Community

- **Starring a repository** helps others find useful projects, increasing their visibility, and allows you to easily track and revisit repos that you find interesting or might need later.

- **Following developers** allows you to keep up with their work, learn from their coding techniques, and collaborate more effectively as a team. It also helps build a professional network and open up new opportunities in the open source community.