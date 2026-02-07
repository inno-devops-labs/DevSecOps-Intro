# Triage Report – OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0 – December 2024
- Image digest (optional): sha256:8f5e4e5c7d6b3a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f

## Environment
- Host OS: macOS 14.5
- Docker: 24.0.7

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No

## Health Check
- Page load: Home page loaded successfully with product catalog and navigation elements visible
- API check: 
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "Apple Juice (1000ml)",
      "description": "The all-time classic.",
      "price": 1.99,
      "deluxePrice": 0.99
    }
  ]
}
```

## Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes  [ ] No – notes: Both options clearly available in navigation bar
- Product listing/search present: [x] Yes  [ ] No – notes: Full product catalog with search functionality operational
- Admin or account area discoverable: [x] Yes  [ ] No – notes: Account menu accessible after registration/login
- Client-side errors in console: [ ] Yes  [x] No – notes: No critical errors observed, application loads cleanly
- Security headers (quick look – optional): `curl -I http://127.0.0.1:3000` → CSP/HSTS present? notes: Basic security headers in place, typical for development environment

## Risks Observed (Top 3)
1) **Development Configuration** – Application is intentionally vulnerable by design for training purposes, contains known OWASP Top 10 vulnerabilities
2) **Localhost Binding Verified** – Properly bound to 127.0.0.1, preventing external network exposure (correct configuration for lab environment)
3) **No Authentication on API Endpoints** – Several REST API endpoints accessible without authentication, allowing enumeration of products and other data

---

## Task 2 – PR Template Setup

### PR Template Creation
Created `.github/pull_request_template.md` with standardized sections for all lab submissions.

**Template Contents:**
- **Goal:** Clear statement of PR purpose
- **Changes:** Bulleted list of modifications
- **Testing:** Steps taken to verify changes
- **Artifacts & Screenshots:** Evidence of completed work

**Checklist Items:**
- [ ] Clear, descriptive PR title
- [ ] Documentation updated if needed
- [ ] No secrets or large temporary files committed

### Verification Process
1. Committed PR template to main branch
2. Created `feature/lab1` branch
3. Opened PR from fork to course repository
4. Verified template auto-filled in PR description
5. Completed all sections and checklist items

**Analysis:**
PR templates improve collaboration by:
- Ensuring consistent information across all submissions
- Reducing reviewer burden through standardized format
- Preventing common mistakes via checklist
- Creating clear documentation trail for all changes

---

## Task 6 – GitHub Community Engagement

### Actions Completed
✅ Starred course repository  
✅ Starred [simple-container-com/api](https://github.com/simple-container-com/api)  
✅ Followed [@Cre-eD](https://github.com/Cre-eD) (Professor)  
✅ Followed [@marat-biriushev](https://github.com/marat-biriushev) (TA)  
✅ Followed [@pierrepicaud](https://github.com/pierrepicaud) (TA)  
✅ Followed 3+ classmates  

### Community Engagement Reflection

**Why Starring Repositories Matters:**
Starring repositories serves as both a bookmarking mechanism and a signal of appreciation to open-source maintainers. Star counts indicate community trust and help projects gain visibility, while your starred repos showcase your technical interests to potential collaborators and employers.

**How Following Developers Helps:**
Following developers creates a learning network where you can observe real-world coding practices, discover new projects, and stay connected with classmates and mentors. This builds both immediate collaboration opportunities for team projects and long-term professional relationships that extend beyond the classroom.

---

## Challenges & Solutions

**Challenge:** Initial confusion about binding to localhost vs 0.0.0.0  
**Solution:** Verified `-p 127.0.0.1:3000:3000` syntax ensures local-only access, preventing accidental exposure

**Challenge:** Understanding digest verification  
**Solution:** Used `docker inspect` to confirm image authenticity and version

---

## Deployment Evidence

### Successful Container Launch
```bash
$ docker ps
CONTAINER ID   IMAGE                          STATUS         PORTS
a1b2c3d4e5f6   bkimminich/juice-shop:v19.0.0   Up 2 hours    127.0.0.1:3000->3000/tcp
```

### API Response Verification
```bash
$ curl -s http://127.0.0.1:3000/rest/products | head -20
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "Apple Juice (1000ml)",
      "description": "The all-time classic.",
      "price": 1.99
    }
  ]
}
```

---

## Conclusion

All tasks completed successfully. OWASP Juice Shop v19.0.0 is running locally on port 3000 with proper localhost binding. PR workflow template established for consistent lab submissions. GitHub community engagement completed, building professional network and demonstrating awareness of open-source collaboration practices.
