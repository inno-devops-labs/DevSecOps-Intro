# Triage Report — OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: https://github.com/juice-shop/juice-shop/releases — 2023
- Image digest (optional): not checked

## Environment
- Host OS: macOS
- Docker: Docker Desktop (latest)

## Deployment Details
- Run command used:
  docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only  
  [x] Yes  [ ] No

## Health Check
- Page load: application successfully loaded in browser  
  Screenshot: screenshots/juice-shop-home.png

- API check:
```bash
curl -s http://127.0.0.1:3000/api/Products | head
{"status":"success","data":[
{"id":1,"name":"Apple Juice (1000ml)","description":"The all-time classic.","price":1.99,"deluxePrice":0.99,"image":"apple_juice.jpg","createdAt":"2026-02-09T11:43:42.810Z","updatedAt":"2026-02-09T11:43:42.810Z","deletedAt":null},
{"id":2,"name":"Orange Juice (1000ml)","description":"Made from oranges hand-picked by Uncle Dittmeyer.","price":2.99,"deluxePrice":2.49,"image":"orange_juice.jpg","createdAt":"2026-02-09T11:43:42.810Z","updatedAt":"2026-02-09T11:43:42.810Z","deletedAt":null},
{"id":3,"name":"Eggfruit Juice (500ml)","description":"Now with even more exotic flavour.","price":8.99,"deluxePrice":8.99,"image":"eggfruit_juice.jpg","createdAt":"2026-02-09T11:43:42.810Z","updatedAt":"2026-02-09T11:43:42.810Z","deletedAt":null},
{"id":4,"name":"Raspberry Juice (1000ml)","description":"Made from blended Raspberry Pi, water and sugar.","price":4.99,"deluxePrice":4.99,"image":"raspberry_juice.jpg","createdAt":"2026-02-09T11:43:42.810Z","updatedAt":"2026-02-09T11:43:42.810Z","deletedAt":null}
```
## Surface Snapshot (Triage)

- Login/Registration visible: [x] Yes [ ] No  
    Notes: Login and registration buttons are visible in the UI
    
- Product listing/search present: [x] Yes [ ] No  
    Notes: Product catalog is displayed on the main page
    
- Admin or account area discoverable: [x] Yes [ ] No  
    Notes: Account section exists in the top menu
    
- Client-side errors in console: [ ] Yes [x] No  
    Notes: No visible errors during initial load
    
- Security headers (optional):  
    curl -I [http://127.0.0.1:3000](http://127.0.0.1:3000/)  
    Notes: No strict security headers observed (HSTS, CSP)
    

## Risks Observed (Top 3)

1. Intentionally vulnerable application — designed for security training
    
2. Missing security headers — could increase attack surface
    
3. Authentication and user input exposed — potential injection risks
    

---

## PR Template Setup

A pull request template was created in `.github/pull_request_template.md`  
The template includes Goal, Changes, Testing, and Artifacts sections with a checklist.  
Template was verified by opening a PR and confirming auto-filled structure.

---

## GitHub Community

Starring repositories helps discover and support useful open-source projects.  
Following developers and classmates improves collaboration and visibility in team projects.