# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a complete DevSecOps pipeline around OWASP Juice Shop — a deliberately vulnerable web application — to demonstrate how to shift security left across the entire SDLC. The stack includes SAST, SCA, IaC scanning, container signing, runtime detection, and a central vulnerability management platform. The goal was to mature from "scan and pray" to a data‑driven program with SLAs and measurable improvement.

## (0:30–2:00) Layers
**Pre‑commit:** We use `gitleaks` to catch secrets before they hit the repo, and Git‑signed commits to ensure integrity.  
**Build:** SBOM generation with Syft, then Grype for SCA and Semgrep for SAST. We also run Trivy on the final image.  
**Pre‑deploy:** IaC scanning with Checkov and KICS for Terraform, Ansible, and Pulumi. All images are signed with Cosign (using a local key) and verified before deployment.  
**Runtime:** Falco with eBPF monitors container behaviour — we have custom rules for file writes to `/tmp` and cryptominer‑like network patterns.  
**Program:** All findings are aggregated in DefectDojo, where we apply a severity‑based SLA (Critical: 24h, High: 7d, Medium: 30d, Low: 90d) and track MTTR and backlog.

## (2:00–3:00) Findings + Closures
Over the course of the semester, we imported 157 raw findings from 9 different scanners. After deduplication and triage, we currently have 4 Critical, 13 High, and 8 Medium active findings in Juice Shop.  
One example of risk acceptance: we accepted a Medium‑severity finding about missing `readOnlyRootFilesystem` because Juice Shop needs to write temporary files — but we set an expiry date of 2026‑12‑01 and added monitoring.  
The strongest correlated finding was a high‑severity SQL injection caught by both Semgrep and ZAP — the fix was a parameterised query, and we closed it within 2 days.

## (3:00–4:00) Metrics
**MTTR** (Mean Time to Remediate): for Critical findings, we average 2 days; for High, 5 days. This is above the DORA Elite benchmark of <1 day, but we're improving.  
**Vuln‑age median** (open findings): 14 days.  
**SLA compliance**: 78% of findings closed within their SLA window.  
**Backlog trend**: stable — we close about as many as we open each week.

## (4:00–4:30) Next Steps
If I had another quarter, I'd mature our **Defect Management** practice (OWASP SAMM) by integrating Falco runtime alerts directly into DefectDojo via a custom parser, and automating the closure of findings that are no longer exploitable based on runtime context. This would reduce false positives and improve our MTTR even further.

## (4:30–5:00) Q&A Anticipation

**Q1: How would you handle a Log4Shell scenario today?**  
> We have SBOMs for every build. The moment a new CVE like Log4Shell drops, I'd run `grype` against our SBOM database to instantly identify which images and versions are affected. Then we'd prioritise patching based on severity and exploitability (EPSS), and use Cosign to sign the new images before redeployment. DefectDojo would track the findings and SLAs.

**Q2: Why didn't you use IAST or paid tools?**  
> This was a proof‑of‑concept with open‑source tools to demonstrate the full pipeline without licensing barriers. In production, I'd advocate for IAST (e.g., Contrast) to reduce false positives, but the core methodology — SBOM, signing, runtime monitoring, and centralised vuln management — remains the same regardless of the tooling.

---
**Time estimate:** 4 minutes 50 seconds when read aloud at a moderate pace.
