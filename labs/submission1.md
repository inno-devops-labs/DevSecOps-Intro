# Triage Report — OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0 — 2025-12-17
- Image digest: sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d

## Environment
- Host OS: macOS 26.2 (Build 25C56)
- Docker: 29.2.0

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No

The container is bound exclusively to the loopback interface (`127.0.0.1`), ensuring it is not reachable from external networks. Port mapping confirms `3000/tcp -> 127.0.0.1:3000`.

## Health Check

### Page Load
- HTTP Status: **200 OK**
- Page title: `OWASP Juice Shop`
- The home page loads successfully, displaying the Juice Shop storefront with product listings.

### API Check
Output from `curl -s http://127.0.0.1:3000/api/Products | head`:

```json
{
    "status": "success",
    "data": [
        {
            "id": 1,
            "name": "Apple Juice (1000ml)",
            "description": "The all-time classic.",
            "price": 1.99,
            "deluxePrice": 0.99,
            "image": "apple_juice.jpg"
        },
        {
            "id": 2,
            "name": "Orange Juice (1000ml)",
            "description": "Made from oranges hand-picked by Uncle Dittmeyer.",
            "price": 2.99,
            "deluxePrice": 2.49,
            "image": "orange_juice.jpg"
        },
        {
            "id": 3,
            "name": "Eggfruit Juice (500ml)",
            "description": "Now with even more exotic flavour.",
            "price": 8.99,
            "deluxePrice": 8.99,
            "image": "eggfruit_juice.jpg"
        }
    ]
}
```

Application version confirmed via API: `{"version":"19.0.0"}`

## Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes  [ ] No — The app provides both login (`/#/login`) and registration (`/#/register`) pages accessible from the navigation bar.
- Product listing/search present: [x] Yes  [ ] No — The main page displays a full product catalog with search functionality in the top bar.
- Admin or account area discoverable: [x] Yes  [ ] No — The `/api-docs/` Swagger endpoint returns HTTP 200, exposing the full API documentation. The `/rest/admin/application-version` endpoint is publicly accessible without authentication, leaking version info.
- Client-side errors in console: [ ] Yes  [x] No — No critical errors observed on initial load.
- Security headers (quick look): `curl -I http://127.0.0.1:3000` reveals:

| Header | Value | Assessment |
|--------|-------|------------|
| `Access-Control-Allow-Origin` | `*` | **Weak** — wildcard allows any origin |
| `X-Content-Type-Options` | `nosniff` | Good — prevents MIME-type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Good — basic clickjacking protection |
| `Feature-Policy` | `payment 'self'` | Partial — only restricts payment API |
| `Content-Security-Policy` | *Not present* | **Missing** — no CSP header |
| `Strict-Transport-Security` | *Not present* | **Missing** — no HSTS header |
| `X-Recruiting` | `/#/jobs` | Informational leak (intentional by design) |

## Risks Observed (Top 3)

1. **Missing Content-Security-Policy (CSP) header** — Without CSP, the application is more susceptible to Cross-Site Scripting (XSS) attacks, as there are no browser-enforced restrictions on inline scripts or script sources.

2. **Wildcard CORS policy (`Access-Control-Allow-Origin: *`)** — Any origin can make authenticated cross-origin requests to the API, potentially enabling data exfiltration via malicious third-party sites if combined with credential leakage.

3. **Unauthenticated API information disclosure** — Sensitive endpoints such as `/rest/admin/application-version` (leaking exact version `19.0.0`) and `/api-docs/` (exposing full Swagger API documentation) are accessible without authentication, giving attackers a detailed map of the attack surface.

---

## Task 2 — PR Template Setup

### PR Template Creation

A pull request template was created at `.github/pull_request_template.md` containing standardized sections:

- **Goal** — Describes the purpose of the PR
- **Changes** — Lists specific modifications made
- **Testing** — Documents how the changes were verified
- **Artifacts & Screenshots** — Provides visual evidence and supporting files

The template also includes a checklist with three items to ensure quality:
1. Clear, descriptive PR title
2. Documentation updated if needed
3. No secrets or large temporary files committed

### Verification Process

To verify the template works:

```bash
git checkout -b feature/lab1
git add labs/submission1.md .github/pull_request_template.md
git commit -m "docs(lab1): add submission1 triage report and PR template"
git push -u origin feature/lab1
```

When opening a new PR from the `feature/lab1` branch, GitHub automatically pre-fills the PR description with the template sections and checklist.

### How Templates Improve Collaboration

PR templates enforce a consistent structure across all submissions, ensuring that reviewers always receive the same critical information (goal, changes, testing, evidence). This reduces back-and-forth during reviews, makes it easier to evaluate submissions against rubrics, and establishes professional habits for real-world software development workflows. Templates also serve as a reminder to check for common issues like secrets in commits.

---

## Task 6 — GitHub Community Engagement

### Actions Completed
1. Starred the course repository
2. Starred [simple-container-com/api](https://github.com/simple-container-com/api)
3. Followed the professor ([@Cre-eD](https://github.com/Cre-eD)) and TAs ([@marat-biriushev](https://github.com/marat-biriushev), [@pierrepicaud](https://github.com/pierrepicaud))
4. Followed at least 3 classmates from the course

### Why Starring Repositories Matters

Starring repositories serves as both a personal bookmarking system and a public signal of project quality in the open-source ecosystem. A higher star count increases a project's visibility in GitHub search results and recommendations, which attracts more contributors and users. For individuals, starred repos appear on your GitHub profile, demonstrating awareness of industry tools and best practices to potential employers and collaborators.

### How Following Developers Helps

Following developers on GitHub creates a professional network that extends beyond the classroom. Your activity feed surfaces what colleagues and industry leaders are working on, exposing you to new tools, patterns, and projects organically. In team-based courses and workplaces, following teammates makes it easier to stay updated on their contributions, discover opportunities for collaboration, and build the kind of developer community that accelerates both learning and career growth.
