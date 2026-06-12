# Lab 1 - Submission

## PR Template Setup

- File: `.github/PULL_REQUEST_TEMPLATE.md`
- Sections included: Goal / Changes / Testing / Artifacts & Screenshots
- Checklist items: title format / no secrets / submission file exists
- Auto-fill verified: [x] Yes — PR description showed my template

## Triage Report: OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: `bkimminich/juice-shop:v20.0.0`
- Image digest: sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
- Host OS: Kali
- Docker version: 26.1.5

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only? [x] Yes
- Container restart policy: default (no)

### Health Check
- HTTP code on `/`: 200
- API check (`/api/Products` length): 46

### Initial Surface Snapshot
- Login/Registration visible: [x] Yes - в меню Account
- Product listing/search present: [x] Yes - главная страница
- Admin or account area discoverable: [x] Yes - /administration (после логина)
- Client-side errors in DevTools console: [x] Yes - Angular warnings, mixed content notices
- Pre-populated local storage / cookies: language preference, возможно welcomeBanner флаг

### Security Headers (Quick Look)
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 11 Jun 2026 14:54:25 GMT
ETag: W/"26af-19eb72d63d4"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 11 Jun 2026 14:55:04 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Отсутствующие заголовки:
- [x] `Content-Security-Policy` - ОТСУТСТВУЕТ
- [x] `Strict-Transport-Security` - ОТСУТСТВУЕТ (HTTP, не HTTPS)
- [ ] `X-Content-Type-Options: nosniff` - присутствует
- [x] `X-Frame-Options` - ОТСУТСТВУЕТ

### Top 3 Risks Observed

1. **Broken Access Control (A01:2025)** - endpoint `/rest/admin/application-version`
   доступен без авторизации, раскрывает версию приложения. Упрощает таргетированные атаки.

2. **Security Misconfiguration (A03:2025)** - отсутствуют заголовки CSP и X-Frame-Options.
   Приложение уязвимо к clickjacking и XSS без дополнительных браузерных защит.

3. **Injection (A05:2025)** - поиск товаров (`/rest/products/search?q=`) не фильтрует ввод,
   классический вектор для SQL injection и reflected XSS.


## GitHub Community

Starring repositories serves as a public bookmark and signals community trust -
the star count helps developers gauge project adoption and encourages maintainers.
Following classmates and instructors creates a lightweight activity feed that surfaces
new projects and keeps you aware of ongoing course work, which helps with collaboration
and professional networking beyond the classroom.