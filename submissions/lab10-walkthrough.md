# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a small DevSecOps vulnerability management program around OWASP Juice Shop as the target application. The scope included SBOM generation, software composition analysis, SAST, DAST, IaC scanning, container scanning, Kubernetes scanning, supply-chain verification, runtime detection, and centralized vulnerability management in DefectDojo.

The goal was not just to run scanners, but to connect their outputs into one program where findings are imported, prioritized, assigned SLA expectations, and tracked as a backlog.

## (0:30–2:00) Layers

The first layer was pre-commit security. I configured secret scanning with gitleaks and enabled signed commits, so the repository had protection against accidentally committed secrets and better commit authenticity.

The second layer was build-time security. I generated SBOMs with Syft and used Grype and Trivy to identify vulnerable dependencies and container image vulnerabilities. This gave visibility into what components existed in the application and which advisories affected them.

The third layer was application security testing. I used Semgrep for SAST and ZAP for DAST. Semgrep helped identify code-level patterns, while ZAP tested the running application from the outside, including an authenticated scan.

The fourth layer was infrastructure and deployment security. I used Checkov and KICS to scan Terraform, Ansible, and Pulumi-style infrastructure definitions. I also used Kubernetes hardening controls such as restricted pod security settings, non-root execution, dropped capabilities, read-only root filesystem, resource limits, and network policies.

The fifth layer was supply-chain and runtime security. I used Cosign to sign and verify artifacts and showed that tampered artifacts fail verification. For runtime detection, I used Falco custom rules to detect suspicious behavior in containers.

Finally, I aggregated the findings into DefectDojo. This is the program layer: instead of having separate reports, DefectDojo gives one product, one engagement, severity tracking, SLA expectations, backlog metrics, and a place to investigate deduplication.

## (2:00–3:00) Findings + Closures

In this run, DefectDojo centralized 385 findings from the successful imports. The active backlog included 17 Critical findings, 164 High findings, 168 Medium findings, 27 Low findings, and 9 Info findings.

The strongest correlation example was `GHSA-5mrr-rgp6-x4gr` affecting `marsdb:0.6.11`. It appeared in Grype and Trivy outputs as three related DefectDojo findings: IDs 98, 164, and 353. Automatic deduplication did not collapse them in this local run, likely because the scanner metadata and titles were slightly different and the CVE field was empty. That is a useful program lesson: scanner metadata normalization is required before relying on cross-tool deduplication.

I did not risk-accept findings without expiry. If a finding is risk-accepted in a real program, it must have a clear reason, an owner, and an expiration date. Otherwise, risk acceptance becomes a way to hide vulnerabilities instead of managing them.

## (3:00–4:00) Metrics

The key metrics I tracked were severity distribution, active backlog, imported finding count, MTTR, vulnerability age, and SLA compliance. For this lab run, MTTD is effectively zero days because findings were detected when reports were imported into DefectDojo.

MTTR is not available for this run because I did not fully remediate and close findings during the lab. In a real program, MTTR would be measured only on mitigated findings, comparing the detection date to the mitigation date.

The backlog baseline is 385 active findings. The Critical and High backlog is 181 findings, which is about 47 percent of the total backlog. That means the immediate remediation focus should be Critical and High dependency vulnerabilities, container image vulnerabilities, and high-impact IaC misconfigurations.

SLA compliance is based on the lecture matrix: Critical findings should be handled within 24 hours, High within 7 days, Medium within 30 days, and Low within 90 days.

## (4:00–4:30) Next Steps

If I had another quarter, I would automate DefectDojo imports directly from CI/CD pipelines. That would mature the OWASP SAMM Defect Management practice because vulnerability tracking would become continuous instead of manual.

The next concrete step would be to normalize scanner metadata before import, especially CVE/GHSA identifiers, package names, and component versions. This would make deduplication more reliable and reduce repeated triage work.

## (4:30–5:00) Q&A Anticipation

### Question 1: How would you handle a Log4Shell scenario?

I would start from the SBOM. Because the SBOM lists application components and dependencies, I can quickly search whether the vulnerable Log4j package exists in the product. Then I would use DefectDojo to identify affected findings, prioritize internet-exposed and exploitable services first, apply emergency patching or mitigation, and track remediation through SLA. After remediation, I would rescan and verify that the finding is closed.

### Question 2: Why did you not use IAST or paid tools?

I focused on open-source tools because this was a university lab and the goal was to build the full DevSecOps process, not to depend on commercial tooling. The tradeoff is that paid tools may provide better correlation, dashboards, and support, but the open-source stack still demonstrates the core program: scanning, signing, runtime detection, centralized findings, SLA, backlog metrics, and deduplication analysis.
