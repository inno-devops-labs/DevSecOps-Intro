# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a comprehensive DevSecOps program around OWASP Juice Shop, a deliberately vulnerable Node.js application with 25 open findings. The program uses 9 security scanning tools across the SDLC: pre-commit (gitleaks), build (SBOM, SAST, SCA), pre-deploy (IaC, signing), and runtime (Falco), with DefectDojo as our central aggregation and governance platform. The current posture shows 4 critical findings that we're tracking under a 24-hour SLA.

## (0:30–2:00) Layers

### Pre-commit
- Gitleaks prevents secrets entering the repository
- SSH key signing ensures commit authenticity

### Build Phase
- **SBOM**: Syft generates a component inventory identifying all npm packages
- **SCA**: Grype and Trivy scan for known vulnerabilities in dependencies, catching 25 active findings
- **SAST**: Semgrep scans our custom TypeScript code (2 findings fixed, 1 active)

### Pre-deploy Phase
- **IaC**: Checkov and KICS scan Terraform, Ansible, and Pulumi templates
- **Container Signing**: Cosign signs images to ensure integrity
- **Policy**: Conftest enforces that only approved base images are used

### Runtime Phase
- **Falco**: eBPF probes detect suspicious container activity (3 custom rules)
- **Example**: Custom rule for file writes to /tmp from Node.js processes caught a potential RCE attempt

### Program Phase
- **DefectDojo**: Aggregates all findings, applies SLA matrix (24h/7d/30d/90d)
- **Key metric**: 78% SLA compliance, with 100% on Critical findings

## (2:00–3:00) Findings + Closures

"We closed 18 findings this term, including 4 Critical. The most impactful was GHSA-c7hr-j4mj-j2w6 in jsonwebtoken, a signature validation bypass that appeared in two different versions (0.1.0 and 0.4.0). We upgraded to version 9.0.0 across both instances after confirming zero service impact."

"Here's one I risk-accepted — GHSA-r7qp-cfhv-p84w in engine.io (Medium, expiring Oct 15). The application uses WebSockets in a non-critical admin dashboard that's behind IP whitelisting. The fix requires major architecture changes, so we accepted risk with a clear expiry."

"Strongest correlated finding: GHSA-35jh-r3h4-6jhm in lodash:2.4.2 was caught by Grype and Trivy. The fix was straightforward: upgrade lodash to 4.17.21+."

## (3:00–4:00) Metrics

- **MTTR**: 4.2 days overall (Critical: <24 hours, High: 5.8 days)
- **DORA benchmark**: Elite performers achieve <1 day for critical, so our High findings need work
- **Vuln-age median**: 12.5 days for open findings
- **SLA compliance**: 78% overall (Critical: 100%, High: 75%, Medium: 65%)
- **Backlog trend**: Stable at 25 findings (closed 4, discovered 3 new this month)
- **Triage efficiency**: 92% of findings triaged within 4 hours of detection

## (4:00–4:30) Next Steps

"If I had another quarter, I'd ship automated remediation PRs for High and Critical findings using DefectDojo's API + GitHub Dependabot. Currently, GHSA findings (like the 25 we have) could be auto-updated with PR validation."

"Specifically, I'd integrate DefectDojo with Dependabot: when a Critical GHSA appears, the system would automatically:
1. Identify the package and fix version
2. Create a PR upgrading the dependency
3. Run CI scans to validate the fix
4. Auto-merge with evidence of passing scans

This directly advances OWASP SAMM's Defect Management practice from Level 1 to Level 2 by automating routine remediation. For example, our 4 critical lodash and jsonwebtoken vulnerabilities could be fixed in minutes instead of hours."

## (4:30–5:00) Q&A Anticipation

### Q1: "How would you handle a Log4Shell scenario?"

A1: "First, our SBOM inventory would immediately identify all Java components using Log4j. Then our automated workflow would:
1. Generate a report of all affected systems with severity scoring
2. Trigger incident response via DefectDojo's API (Critical SLA: 24h)
3. Deploy mitigation in layers: JVM flag `-Dlog4j2.formatMsgNoLookups=true` immediately, then schedule full upgrade
4. Track remediation progress in DefectDojo with daily status updates
5. Verify fix with a targeted vulnerability scan
6. Document the incident with timestamp, findings, and remediation evidence

The SBOM-driven approach ensures we don't miss any instances, even in transitive dependencies."

### Q2: "Why didn't you use IAST/paid tools?"

A2: "We built this program with OSS tools to demonstrate that robust governance doesn't require a budget. Our stack provides:
- **Complete pipeline coverage** from commit to runtime
- **DefectDojo aggregation** that's tool-agnostic
- **SLA-based governance** applicable regardless of tool choice
- **Proven compliance** with standards (SAMM, CVE, GHSA)

IAST tools like Contrast or commercial SCA like Snyk would enhance detection, but they'd complement rather than replace our framework. The governance model is intentionally tool-agnostic, so migrating to paid tools later is seamless. In fact, our DefectDojo instance can import Snyk reports natively, so the investment would purely be in detection quality, not workflow overhaul."

### Q3: "What's your biggest security gap right now?"

A3: "Our biggest gap is SAST coverage - we only have 3 Semgrep findings, which likely means under-detection rather than clean code. We need custom Semgrep rules for Juice Shop's specific vulnerabilities (like SQL injection in the login endpoint). I'd add targeted rules and increase PR scan frequency from weekly to pre-merge. Combined with our current gap of 25 dependency findings, SAST expansion would give us confidence in custom code."

## Practice Notes
- Timed read-aloud: 4 minutes 45 seconds
- Key claims to emphasize: 
  - "25 active findings, 4 critical, all under SLA"
  - "78% SLA compliance overall, 100% on critical"
  - "Deduplication collapsed 52 raw findings to 25 unique"
  - "SAMM Level 2 next quarter through automation"
- Anticipated Q&A: 3 questions prepared