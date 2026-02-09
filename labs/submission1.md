# Lab 1 Submission

## Task 1 — Triage Report — OWASP Juice Shop

### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0 — (укажи дату со страницы релиза)
- Image digest (optional): sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d

### Environment
- Host OS: Windows (PowerShell / VS Code)
- Docker: Docker Desktop (version: вставь вывод `docker --version`)

### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No

### Health Check
- Page load (screenshot): `labs/screenshots/juice-shop-home.png`
- API check:
  - Note: endpoint `/rest/products` returned HTML error `Unexpected path: /rest/products`
  - Working endpoint used: `GET /api/Products`
```text
{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-02-09T14:06:56.365Z","updatedAt":"2026-02-09T14:06:56.365Z","deletedAt":null},{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange_juice.jpg","createdAt":"2026-02-09T14:06:56.365Z","updatedAt":"2026-02-09T14:06:56.365Z","deletedAt":null},{"id":3,"name":"Eggfruit Juice (500ml)","description":"Now with even more exotic flavour.","price":8.99,"deluxePrice":8.99,"image":"eggfruit_juice.jpg","createdAt":"2026-02-09T14:06:56.365Z","updatedAt":"2026-02-09T14:06:56.365Z","deletedAt":null}, ...]


Surface Snapshot (Triage)

Login/Registration visible: [x] Yes [ ] No — notes: “Account” menu visible in header

Product listing/search present: [x] Yes [ ] No — notes: “All Products” grid shown

Admin or account area discoverable: [x] Yes [ ] No — notes: Account icon/menu present

Client-side errors in console: [ ] Yes [x] No — notes: во время базового просмотра не заметил

Security headers (quick look — optional):

From curl -I http://127.0.0.1:3000:

Present: X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN

Not observed: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP)

Notes: сервис доступен по HTTP (не HTTPS), поэтому HSTS обычно не будет; отсутствие CSP повышает риск XSS в реальных приложениях.

Risks Observed (Top 3)

Intentional vulnerable application — Juice Shop специально содержит уязвимости (OWASP Top 10), поэтому его нельзя выставлять наружу.

Accidental network exposure — если случайно пробросить порт на 0.0.0.0:3000, уязвимое приложение станет доступно в локальной сети.

Missing CSP / HTTPS protections — отсутствует CSP и нет HTTPS, что снижает браузерные защиты и увеличивает последствия XSS/инъекций.

Next Actions

Всегда держать биндинг на 127.0.0.1

Использовать только для лабораторных работ

Удалить контейнер после работы: docker rm -f juice-shop

