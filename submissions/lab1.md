# Lab 1 — OWASP Juice Shop rollout and workflow setup

## Triage report

I approached this as a short first-pass review of a service: confirm that it starts, note what is exposed without a login, and record the obvious hardening gaps before making any assumptions about it.

### Asset

- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: Microsoft Windows 11 Home, version `10.0.26100`
- Docker: client and server `29.2.1`

### Deployment

For this local check, I started the official pinned image with the following command:

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

- Access URL: `http://127.0.0.1:3000`
- Port binding: `127.0.0.1:3000->3000/tcp` (localhost only). This small detail matters: it keeps a deliberately vulnerable practice application off the local network and reachable only from this computer.
- Restart policy: `no`.

### Health

```text
juice-shop | Up 2 minutes | 127.0.0.1:3000->3000/tcp
HTTP 200
{"version":"20.0.0"}
PRODUCT_COUNT=46
```

In other words, the service came up normally, reported the expected version, and served the expected number of products.

### Surface observed

- The landing page calls the application **OWASP Juice Shop** and openly presents it as insecure. From the browser's point of view, it begins as an Angular application container (`<app-root>`), which then loads the interface.
- A quick unauthenticated request to `GET /api/Products` returned `200` and 46 catalogue records with names, descriptions, prices, and image filenames. The browser view matched this result: the **All Products** page rendered a product grid with images, names, prices, availability labels, and **Add to Basket** buttons. That makes sense for a public storefront: people can browse products before they sign in.
- The first visit shows a cookie-consent widget. Although the initial `curl -sI` response did not include `Set-Cookie`, the browser's Application panel showed three cookies for `127.0.0.1`: `cookieconsent_status=dismiss`, `language=en`, and `welcomebanner_status=dismiss`. These appear to store interface preferences rather than an authenticated user session; no login token was observed. Local Storage was empty when it was inspected.
- The Login form contained Email and Password fields, a **Remember me** checkbox, a **Forgot your password?** link, a local **Log in** button, and a **Log in with Google** button. Its **Not yet a customer?** link provides the route to registration. An attempt to sign in with Google Auth did not complete in this local session, while the local login request returned HTTP `201`.
- The account area, after sign-in, exposed User Profile settings (username, picture upload, and image URL), order and payment options, saved addresses, a digital wallet, recycle, and privacy/security options such as data export, data erasure, password change, 2FA configuration, and last-login IP. No separate Admin area was visible to this user.
- DevTools reported one form-related issue: a form field lacked both an `id` and a `name` attribute, which may prevent the browser from autofilling that field correctly. During sign-in, the Network tab showed successful XHR calls to `whoami?fields=email` and `whoami` with HTTP `200`, as well as the local `login` request with HTTP `201`; several static assets returned `304`, which indicates normal cache revalidation.
- The Console also showed two `Uncaught TypeError` messages: `Cannot read properties of undefined (reading 'startTime')`, both originating from anonymous code in the DevTools VM context. The screenshot alone does not establish whether this came from the application, DevTools, or a browser extension, but it is a visible error worth recording and investigating.

### Security headers

As a quick baseline, I ran `curl -sI http://127.0.0.1:3000` and received:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sun, 13 Sep 2026 14:22:44 GMT
ETag: W/"26af-1a09b26295d"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Sun, 13 Sep 2026 14:24:54 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

- Present: `X-Content-Type-Options: nosniff`; `X-Frame-Options: SAMEORIGIN`.
- Missing: `Content-Security-Policy`; `Strict-Transport-Security`. HSTS is normally delivered on an HTTPS site, so its absence on this plain-HTTP local response is expected, but it would need to be present once the application is deployed behind HTTPS.

### Top three risks

1. **No Content Security Policy — OWASP Top 10:2025 A02, Security Misconfiguration.** The server does not return `Content-Security-Policy`. In practical terms, this header is a useful browser-side safety net: it limits which scripts, frames, styles, and connections can load. Without it, an unsafe content path or script injection has fewer controls reducing its impact.

2. **Public product data with permissive CORS — OWASP Top 10:2025 A01, Broken Access Control.** The full catalogue is returned by `GET /api/Products` without credentials, and `Access-Control-Allow-Origin: *` permits any site to read it. A public catalogue can be perfectly reasonable; the important point is to make that choice deliberately and ensure the same rule is not accidentally inherited by account, administrative, or sensitive routes.

3. **No Strict-Transport-Security header — OWASP Top 10:2025 A02, Security Misconfiguration.** The observed response did not include `Strict-Transport-Security`. The header is not meaningful over this local HTTP connection, but it must be configured when the application is placed behind HTTPS so browsers remember to use encrypted connections.

## PR template

- Path: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections: `Goal`, `Changes`, `Testing`, `Artifacts & Screenshots`, and `Checklist`.
- Checklist items: PR title follows `feat(labN): <topic>`; no secrets or large temporary files are committed; `submissions/labN.md` exists.
- Draft PR evidence: this workspace does not have an authenticated GitHub browser session, so I cannot honestly add a PR link or screenshot here. After the branch is pushed and a draft PR is opened, GitHub should automatically insert the template above into the description.

## GitHub community

Giving a project a star is a simple way to show maintainers that people value their work, and it also helps new users discover it. Following instructors, TAs, and classmates makes it easier to stay aware of related work, coordinate reviews, and learn from each other's updates.

## Bonus: CI smoke test

- The workflow starts on pull requests to `main`, has only `contents: read`, launches `bkimminich/juice-shop:v20.0.0`, and checks the version endpoint every five seconds for up to 60 seconds. This gives the application enough time to initialise instead of failing the job too early.
- Run URL and duration: there is no remote run to link yet because this workspace has no authenticated GitHub browser session. On the local check, the endpoint answered `{"version":"20.0.0"}`; once the poll succeeds in GitHub Actions, the job will print `Juice Shop is ready: {"version":"20.0.0"}`.
