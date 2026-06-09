# Lab 1 — Submission

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
- Host OS: Windows 11
- Docker version: 28.1.1

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes [ ] No (explain if No)
- Container restart policy: no

### Health Check
- HTTP code on `/`: 200
- API check (first 200 chars of `/rest/products`):
```html
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
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-gradient(top, #fff, #ECE9E9);
  background-repeat: no-repeat;
  color: #555;
  -webkit-font-smoothing: antialiased;
}
h1, h2 {
  font-size: 22px;
  color: #343434;
}
h1 em, h2 em {
  padding: 0 5px;
  font-weight: normal;
}
h1 {
  font-size: 60px;
}
h2 {
  margin-top: 10px;
}
ul li {
  list-style: none;
}
#stacktrace {
  margin-left: 60px;
}
</style>
  </head>
  <body>
    <div id="wrapper">
      <h1>OWASP Juice Shop (Express ^4.22.1)</h1>
      <h2><em>500</em> Error: Unexpected path: /rest/products</h2>
      <ul id="stacktrace"><li> &nbsp; &nbsp;at /juice-shop/build/routes/angular.js:42:18</li><li> &nbsp; &nbsp;at /juice-shop/build/lib/utils.js:225:26</li><li> &nbsp; &nbsp;at Layer.handle [as handle
    </div>
  </body>
</html>
```

Container uptime:
```shell
NAMES        STATUS         PORTS
juice-shop   Up 8 minutes   127.0.0.1:3000->3000/tcp
```

### Initial Surface Snapshot (from browser exploration)
- Login/Registration visible: [x] Yes [ ] No — notes: login/registration page visible, it also has sign-in with google.
- Product listing/search present: [X] Yes [ ] No — notes: it has paginated product listing with keyword search.
- Admin or account area discoverable: [X] Yes [ ] No — notes: by guessing and manual fuzzing `/#/administration` endpoint was discovered, but it returns 403.
- Client-side errors in DevTools console: [ ] Yes [X] No — notes: no errors was discovered.
- Pre-populated local storage / cookies: local storage is empty. In cookies was found `language` cookie with value `en`. `cookieconsent_status` appeared after accepting in UI. All cookies has `HttpOnly=false`.

### Security Headers (Quick Look)
Headers:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 09 Jun 2026 21:07:56 GMT
ETag: W/"26af-19eae36a199"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Tue, 09 Jun 2026 21:22:51 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Which of these are MISSING? (cross-reference Lecture 1 OWASP Top 10:2025 — A06)
- [x] `Content-Security-Policy`
- [x] `Strict-Transport-Security`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options`

### Top 3 Risks Observed

1. Missing CSP Header: Without Content Security Policy (CSP), your site is vulnerable to XSS attacks because the browser will execute any malicious script injected into your pages. This allows attackers to steal user data, session cookies, or perform unauthorized actions on behalf of the user.
2. Insecure CORS settings: Using `Access-Control-Allow-Origin: *` is insecure because it allows any website to read your API's response, potentially exposing sensitive user data. It also disables credentials like cookies or authorization headers, which are often necessary for authenticated requests. This wildcard approach breaks security boundaries, making your application vulnerable to cross-site request forgery and data leaks.
3. Stacktrace exposing: Exposing stack traces reveals internal implementation details like file paths, function names, and library versions, giving attackers valuable information to exploit specific vulnerabilities. It also leaks sensitive logic about your application's architecture, making it easier for hackers to craft targeted attacks such as SQL injection or path traversal based on the revealed structure.

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: <list yours>
- Auto-fill verified: [ ] Yes — PR description showed my template (screenshot or link to draft PR)

## GitHub Community

### Actions completed
- [x] Starred [inno-devops-labs/DevSecOps-Intro](https://github.com/inno-devops-labs/DevSecOps-Intro)
- [x] Starred [simple-container-com/api](https://github.com/simple-container-com/api)
- Following professor and TAs on GitHub:
    - [x] [@Cre-eD](https://github.com/Cre-eD) (professor)
    - [x] [@Naghme98](https://github.com/Naghme98) (TA)
    - [x] [@pierrepicaud](https://github.com/pierrepicaud) (TA)
- Following 3 classmates:
    - [x] [@RC-5555](https://github.com/RC-5555)
    - [x] [@Jestersw](https://github.com/jestersw)
    - [x] [@0xsmk](https://github.com/0xsmk)

### Why stars matter

Starring repositories helps open source projects gain visibility, attract contributors, and shows maintainers that their work is valued. Following developers keeps you updated on their activity, fosters collaboration in team projects, and exposes you to best practices and new techniques that accelerate your professional growth.

## Bonus: CI Smoke Test

- Workflow file: `.github/workflows/lab1-smoke.yml`
- Trigger: `pull_request` on main
- Run URL (must be green): [<link to Actions run>](https://github.com/AskoRBINKAs/DevSecOps-Intro/actions/runs/27238144616/job/80435256342)
- Workflow run duration: 16s
- Curl response excerpt:
```
< HTTP/1.1 200 OK
< Access-Control-Allow-Origin: *
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< Feature-Policy: payment 'self'
< X-Recruiting: /#/jobs
< Content-Type: application/json; charset=utf-8
< Content-Length: 20
< ETag: W/"14-+EBpZnfu193JzIOBjXsY1+KveN8"
< Vary: Accept-Encoding
< Date: Tue, 09 Jun 2026 21:51:05 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
```