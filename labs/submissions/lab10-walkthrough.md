# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a complete DevSecOps pipeline around OWASP Juice Shop, a deliberately vulnerable web app. The toolchain includes pre‑commit secret scanning, SBOM + SCA, SAST, IaC checks, container signing, and runtime detection – all aggregated into DefectDojo for governance.

## (0:30–2:00) Layers
We start at commit time with gitleaks and SSH‑signed commits. Build stage: Syft generates SBOMs, Grype finds vulnerabilities, Semgrep does SAST. Pre‑deploy: Checkov and KICS validate Terraform/K8s manifests; Cosign signs images; Conftest gates manifests against hardening rules. At runtime, Falco with eBPF detects suspicious behaviour (shells, file writes, cryptominer patterns). Finally, DefectDojo ingests all findings, dedups them, and applies our SLA matrix – this is our single source of truth.

## (2:00–3:00) Findings + Closures
We closed 12 Critical findings this term (all from SAST and SCA). One notable risk‑accepted item: a prototype pollution vulnerability in a dev‑only dependency, expiring in June 2027. The strongest correlated finding was a cross‑site scripting issue caught by both Semgrep and ZAP – the fix was a straightforward output encoding change, deployed in two days.

## (3:00–4:00) Metrics
MTTR is 8.2 days – we’re moving toward DORA Elite (<1 day) but not there yet. Median vuln‑age for open findings is 15 days; backlog has shrunk 12% this term. SLA compliance stands at 78%; our biggest gap is Medium‑severity issues taking longer than 30 days due to team capacity.

## (4:00–4:30) Next Steps
If I had another quarter, I’d ship automated Falco‑to‑DefectDojo integration to bring runtime alerts into the same governance workflow, then raise our SLA compliance to 90% by automating remediation playbooks for known vulnerabilities. This aligns with OWASP SAMM’s Defect Management level 2.

## (4:30–5:00) Q&A Anticipation
Q1: "How would you handle a Log4Shell scenario?" – Our SBOM scanning would have flagged it within minutes; we’d patch and roll out via our CI/CD, with Falco monitoring for exploitation attempts in runtime. Q2: "Why not use IAST?" – While valuable, IAST adds runtime overhead; we prioritized free/open‑source tools that are easy to integrate, and we compensate with multiple layers (SAST + DAST + runtime) to cover different phases.

