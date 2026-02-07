# Lab Submission

## Goal
Brief description of what this PR accomplishes and which lab requirements it addresses.

## Changes
- [ ] Created lab submission document with triage report
- [ ] Set up standardized PR template for future submissions
- [ ] Deployed and verified OWASP Juice Shop container
- [ ] Completed security analysis and risk assessment
- [ ] Documented GitHub community engagement activities

## Testing
- [ ] OWASP Juice Shop successfully runs on localhost:3000
- [ ] Security headers analyzed and documented
- [ ] Triage report includes all required sections:
  - [ ] Scope & Asset
  - [ ] Environment details
  - [ ] Deployment Details
  - [ ] Health Check results
  - [ ] Surface Snapshot (Triage)
  - [ ] Security Headers analysis
  - [ ] Top 3 Risks identified
  - [ ] GitHub Community section
  - [ ] Challenges & Solutions
- [ ] PR template auto-fills correctly when creating new PR
- [ ] All social engagement tasks completed (stars, follows)

## Artifacts & Screenshots
- `labs/submission1.md` - Complete triage report for Lab 1
- `.github/pull_request_template.md` - Standardized PR template for future submissions
- **Application verification:** OWASP Juice Shop v19.0.0 running successfully
- **Security analysis:** HTTP headers audit showing security controls and gaps
- **Community engagement:** GitHub stars and follows completed as required

## API Testing Evidence
```bash
# Container deployment
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v19.0.0

# Health check verification
curl -I http://127.0.0.1:3000

# API endpoint testing (showing intentional error for training)
curl -s http://127.0.0.1:3000/rest/products | head
```

## Security Findings Summary
1. **Missing CSP and HSTS headers** - Critical security controls absent
2. **Information disclosure in error messages** - Stack traces exposed
3. **Overly permissive CORS policy** - `Access-Control-Allow-Origin: *`
4. **Application bound to localhost only** - Proper network isolation

## Checklist
- [x] PR title clearly indicates lab number and content (Lab 1: OWASP Juice Shop Triage & PR Workflow)
- [x] Documentation updated where required (created submission1.md and PR template)
- [x] No secrets or large temporary files included
- [x] All required GitHub social actions completed (stars, follows)
- [x] Code follows repository structure guidelines

---

## Notes for Reviewers
- This PR contains only documentation and configuration files, no application code
- OWASP Juice Shop runs as a separate container, not included in this repository
- The 500 error from `/rest/products` endpoint is intentional (training application feature)
- Security analysis focuses on both implemented and missing security controls
- PR template designed to standardize future lab submissions

## Related Links
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- Course Repository: [link to course repo]
- Docker Image: bkimminich/juice-shop:v19.0.0
```