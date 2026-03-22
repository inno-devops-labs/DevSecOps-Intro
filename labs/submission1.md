# Triage Report — OWASP Juice Shop

## Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: [link](https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0) — September 4, 2025
- Image digest (optional): sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d

## Environment
- Host OS: Arch Linux 6.18.3
- Docker: 29.1.4, build 0e6fee6c52

## Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No  (explain if No)

## Health Check
- Page load: ![Home Page](screenshots/juice-shop-home.png)
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
      "deluxePrice": 0.99,
      "image": "apple_juice.jpg",
      "createdAt": "2026-02-04T15:29:14.178Z",
      "updatedAt": "2026-02-04T15:29:14.178Z",
      "deletedAt": null
    }
  ]
}
```

## Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes  [ ] No — notes: The entry and registration icon is visible in the upper right corner.
- Product listing/search present: [x] Yes  [ ] No — notes: The main page shows 12 product items. There is a search button near the Account button.
- Admin or account area discoverable: [ ] Yes  [x] No — notes: The admin/user panel is not visible without authorization.
- Client-side errors in console: [ ] Yes  [x] No — notes: There are no errors when loading the page in the developer console.
- Security headers (quick look — optional): `curl -I http://127.0.0.1:3000` → CSP/HSTS present? notes: No,

  there are basic headers: X-Content-Type-Options, X-Frame-Options, Feature-Policy, but critical ones are missing: CSP, HSTS, X-XSS-Protection.

## Risks Observed (Top 3)
1) Implementation vulnerabilities - High risk due to potential issues with input fields like search and login that may not be properly handled.
2) Lack of HSTS header — Risk of downgrade attacks and traffic interception when switching to HTTPS in production
3) No protection from brute force — There are no restrictions on login attempts, which allows you to brute-force find passwords.

## PR Template Setup
### PR Template Creation Process
```bash
git checkout main # switch to main branch
mkdir -p .github # create folder for github templates
touch .github/pull_request_template.md
```

### Template filling
```markdown
## Goal


## Changes


## Testing


## Artifacts & Screenshots


## Checklist
- [ ] Clear PR title
- [ ] Doc updated is needed
- [ ] No secrets or temporary large files committed
```

### Commit and push the template
```bash
git add .github/pull_request_template.md # add to stage template file
git commit -m "chore: add PR template for standardized submissions"
git push
```

### Analysis: How Templates Improve Collaboration Workflow
PR templates transform the code review process from a chaotic exchange of messages into a structured, efficient workflow. They are especially valuable in educational projects where students are just learning the right practices for collaborative development.


## GitHub Community
### Why starring repositories matters in open source:
Starring repositories serves as both a bookmarking tool for personal reference and a public endorsement that helps projects gain visibility, attracting more contributors and showing appreciation to maintainers for their work.

### How following developers helps in team projects and professional growth:
Following developers enables you to stay updated on their projects and insights, fostering collaboration and knowledge sharing that accelerates team productivity and your own skill development in the tech community.