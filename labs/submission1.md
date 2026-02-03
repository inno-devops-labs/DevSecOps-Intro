# Lab 1

## Task 1

### Triage Report — OWASP Juice Shop

#### Scope & Asset
- Asset: OWASP Juice Shop (local lab instance)
- Image: bkimminich/juice-shop:v19.0.0
- Release link/date: [GitHub Releases](https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0) — 2023-11-22
- Image digest: <sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d>

#### Environment
- Host OS: Windows 10 Pro
- Docker: 28.3.2

#### Deployment Details
- Run command used: `docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0`
- Access URL: http://127.0.0.1:3000
- Network exposure: 127.0.0.1 only [x] Yes  [ ] No  (explain if No)

#### Health Check
- Page load: ![alt text](/assets-for-labs/image.png)
- API check: 
    ```
    [
        {
            "id": 1,
            "name": "Apple Juice",
            "description": "The all-time classic.",
            "price": 1.99,
            "image": "apple_juice.jpg"
        },
        {
            "id": 2,
            ...
        }
    ]
    ```

#### Surface Snapshot (Triage)
- Login/Registration visible: [x] Yes  [ ] No — notes: in the upper right corner
- Product listing/search present: [x] Yes  [ ] No
- Admin or account area discoverable: [ ] Yes [x] No
- Client-side errors in console: [ ] Yes  [x] No
- Security headers (quick look — optional): `curl -I http://127.0.0.1:3000` → CSP/HSTS present? notes: not present

#### Risks Observed (Top 3)
1) No brute-force protection: the login form has no CAPTCHA or delay on multiple attempts.
2) Lack of HTTP security headers: CSP and HSTS are not configured, which increases the risk of XSS and MITM attacks.
3) The possibility of registering arbitrary users: there is no email verification, which can lead to spam and fake accounts.

## Task 2

### Process
1. The file `.github/pull_request_template.md` has been created in the root of the repository in the main branch
2. Added sections: Goal, Changes, Testing, Artifacts & Screenshots
3. Added a three-point checklist

### Evidence
When creating a PR in GitHub, the form is automatically filled in with the suggested template.

### Workflow Improvement
PR templates standardize the review process, reduce the number of forgotten sections, and speed up verification.

## Task 3

## Why Star Repositories?
Asterisks on GitHub are a way to mark interesting projects, support developers, and save the repository for future use. It also helps projects to be more visible in the community.

## Why Follow Developers?
Subscribing to developers allows you to see their activity, study their code, find inspiration, and expand your professional network of contacts.