# Triage Report — OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0 — 2 weeks ago
- Image digest (optional): sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d

## Environment
- Host OS: Kali Linux 2025.1
- Docker: 28.0.4

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No  (explain if No)

## Health Check
- Page load: <img width="1280" height="720" alt="image" src="https://github.com/user-attachments/assets/f4db8c69-cada-42cc-a3b8-09f4559451f0" />
- API check: {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2025-09-14T23:51:40.596Z","updatedAt":"2025-09-14T23:51:40.596Z","deletedAt":null}, ... ]}

## Surface Snapshot (Triage)
- Login/Registration visible: [X] Yes  [ ] No — notes: Login and Registration forms are visible on the homepage.
- Product listing/search present: [X] Yes  [ ] No — notes: Product catalog and search bar are present, API returns product data without login.
- Admin or account area discoverable: [X] Yes  [ ] No — notes: Account area is accessible after login.
- Client-side errors in console: [ ] Yes  [X] No — notes: No client-side errors observed in the browser console on homepage load.
- Security headers (quick look — optional): `curl -I http://127.0.0.1:3000` → CSP/HSTS present? [ ] Yes  [X] No —notes:
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Feature-Policy: payment 'self'
  No CSP or STS headers

## Risks Observed (Top 3)
1) Missing Content Security Policy (CSP)  
   the application does not restrict loading of external scripts/resources, increasing the risk of XSS.
2) Missing HTTP Strict Transport Security (HSTS)  
   browsers will not automatically enforce HTTPS, making traffic susceptible to MITM attacks.
3) Publicly exposed API endpoints  
   the REST API returns data without authentication, potentially exposing sensitive information.
