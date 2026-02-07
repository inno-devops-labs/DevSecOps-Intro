# Submission 1 — OWASP Juice Shop (Triage)

## Scope & Asset
- Target: OWASP Juice Shop (local deployment)
- Docker image: `bkimminich/juice-shop:v19.0.0`
- Access: http://127.0.0.1:3000 (localhost-only exposure)

## Environment
- Host: Windows (PowerShell)
- Container runtime: Docker Desktop
- Networking: Port mapping `127.0.0.1:3000 -> container:3000`

## Deployment Details
Command used:
```powershell
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0
```

Container status:
```text
CONTAINER ID   IMAGE                           STATUS         PORTS                      NAMES
a99c92fbf91e   bkimminich/juice-shop:v19.0.0   Up 5 minutes   127.0.0.1:3000->3000/tcp   juice-shop
```

## Health Check
### UI
- Home page loads at: http://127.0.0.1:3000  
- Screenshot: `labs/assets/juice-shop-home.png`
![Main page](assets/juice-shop-home.png)

### API (evidence)
OpenAPI/Swagger specification endpoint returns HTTP 200:
```powershell
(Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:3000/api-docs/swagger.json").StatusCode
```

Output:
```text
200
```

## Surface Snapshot (Triage)
- Authentication features visible (login/registration): Yes
- Product/catalog functionality visible: Yes
- API surface present (Swagger/OpenAPI): Yes
- Local-only exposure (127.0.0.1 binding): Yes

## Risks Observed (Top 3)
1) **Web input surfaces (login/search/forms)**  
   Typical high-risk areas for injection/XSS/CSRF; prioritize validation and output encoding reviews.

2) **Authentication & session management**  
   Credential handling, session cookies, and account workflows are common attack paths; review cookie flags, session lifetime, and rate limiting.

3) **Client/server API exposure**  
   Public API endpoints expand attack surface; ensure least-privilege, consistent authorization checks, and safe error handling.

---

# PR Template Setup (Task 2)

## What I added
- File: `.github/pull_request_template.md` on `main`
- Purpose: auto-populate PR descriptions with a consistent structure

Template sections included:
- Goal
- Changes
- Testing
- Artifacts & Screenshots
- Checklist:
  - Clear and descriptive PR title
  - Docs updated if needed
  - No secrets/credentials or large temporary files

## Verification
When creating a PR, GitHub pre-fills the PR description with the template content above.

## Why this improves collaboration
A standard PR format makes reviews faster and more reliable by ensuring intent, scope, verification, and artifacts are always documented.

---

# GitHub Community (Task 6)

- **Starring repositories** helps bookmark useful projects and increases their visibility to others.
- **Following developers** helps stay aware of updates, learn from their work, and collaborate more effectively.
