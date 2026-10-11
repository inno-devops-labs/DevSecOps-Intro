# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps program around OWASP Juice Shop, a deliberately vulnerable Node.js web application, as the target. I applied security controls at every stage, from pre-commit to runtime, using open-source tools and centralized everything in DefectDojo for vulnerability management.

## (0:30–2:00) Layers

### Pre-commit
- **SSH-signed commits**: non-repudiation for every change
- **gitleaks** pre-commit hook: blocks hardcoded secrets before they hit the repo

### Build
- **SBOM** with Syft: CycloneDX format for dependency inventory
- **SCA** with Grype and Trivy: 386 total vulnerabilities found across 7 scanners
- **SAST** with Semgrep: 22 findings from OWASP Top 10 rules

### Pre-deploy
- **IaC security** with Checkov and KICS: scanning Terraform, Ansible, and Pulumi
- **Container hardening**: Trivy on the image and Kubernetes manifests
- **Cosign signing**: signed the image and SBOM attestation

### Runtime
- **Falco eBPF**: runtime detection with custom rules
- **Conftest + Rego**: policy-as-code for K8s manifest admission

### Program
- **DefectDojo**: central hub for all 386 findings with dedup and SLA tracking

## (2:00–3:00) Findings + Closures

We imported 386 raw findings across 7 scanners into DefectDojo.

The strongest correlated finding was **SQL injection in the search endpoint** — caught by both Semgrep (SAST) and ZAP (DAST). The fix was simple: parameterized queries.

## (3:00–4:00) Metrics

- **MTTR**: N/A — first baseline run, no findings closed yet
- **Vuln-age median**: 0 days — all findings are newly discovered
- **Backlog**: stable
- **SLA compliance**: N/A — no closed findings yet

SLA matrix is configured:
- Critical: 24 hours
- High: 7 days
- Medium: 30 days
- Low: 90 days

## (4:00–4:30) Next Steps

If I had another quarter, I would ship **automated SBOM attestation** as part of the release pipeline and move to SLSA Build Level 3 by enforcing signed provenance and reproducible builds.

This corresponds to maturing the **Secure Build** and **Environment Management** practices in OWASP SAMM from Level 1 to Level 2.

## (4:30–5:00) Q&A Anticipation

**Q1: How would you handle a Log4Shell scenario?**

With the SBOM we generated in Lab 4, I would instantly query the CycloneDX file in DefectDojo to check if any dependency matches Log4j 2.x. The answer would come in minutes, not weeks. I'd then prioritize the patch based on the SLA matrix so critical severity gets fixed within 24 hours.

**Q2: Why didn't you use IAST or paid tools?**

IAST tools require commercial licenses and agent installation in the runtime, which adds complexity. For this program, I deliberately used open-source tools to demonstrate that a fully functional DevSecOps pipeline is possible without expensive SaaS. In a real org, I would add IAST for deeper coverage once the foundational controls are solid.