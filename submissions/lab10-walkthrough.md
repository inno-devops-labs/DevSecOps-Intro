# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a comprehensive DevSecOps program around the OWASP Juice Shop application, treating it as our core product.
My focus was on securing the entire software supply chain—from code commits to runtime execution—using a combination of SAST, SCA, IaC scanning, policy-as-code, and eBPF-based runtime detection, all unified within DefectDojo.

## (0:30–2:00) Layers
To build defense-in-depth, I layered security controls across all CI/CD phases.
- **Pre-commit**: I implemented Gitleaks to block hardcoded secrets from ever entering the repository, and enforced SSH-signed commits to guarantee code provenance.
- **Build**: I generated an SBOM using Syft, and scanned it with both Grype and Trivy to catch vulnerable dependencies (SCA). I also ran Semgrep to catch custom code flaws (SAST).
- **Pre-deploy**: I used Checkov to scan our Terraform and Kubernetes manifests for misconfigurations. Before deployment, we signed our container images with Cosign and used Conftest (Rego) as an admission gate to block non-compliant or unsigned workloads.
- **Runtime**: I deployed Falco using modern eBPF to monitor system calls, creating custom rules to detect anomalies like unexpected writes to `/tmp` and outbound connections to cryptominer pools.
- **Program Management**: Finally, I aggregated all these reports into DefectDojo. I configured an SLA matrix (Critical 24h, High 7d) to automatically track compliance and calculate MTTR.

## (2:00–3:00) Findings + Closures
During this implementation, we successfully identified and triaged over 150 vulnerabilities.
- We caught 5 Critical and 47 High findings, primarily in legacy dependencies flagged by Trivy, which we prioritized based on the EPSS score and CVSS severity.
- Here's one I risk-accepted: The famous runc vulnerability (`CVE-2024-21626`). I set it to expire on 2026-07-30 because we are waiting on a patched base image from the vendor, but we mitigated the immediate risk by dropping all capabilities from the container via Conftest policies.
- The strongest correlated finding was a hardcoded credential issue caught by both Semgrep (SAST) and ZAP (DAST) independently. Combining these signals in DefectDojo proved that the vulnerability was actually exploitable in production, allowing us to prioritize the fix.

## (3:00–4:00) Metrics
By bringing all our data into DefectDojo, I established baseline program metrics.
- Our current **Vuln-age median** is less than a day since we just onboarded the tool, but our SLA compliance is currently at 100%.
- Moving forward, our target **MTTR** (Mean Time to Remediate) for Critical vulnerabilities is <24 hours, aiming to eventually hit DORA Elite metrics of <1 day.
- Currently, our backlog trend spiked because of the initial scan onboarding, but with automated Jira ticketing integrated with DefectDojo, we expect a downward trend over the next quarter.

## (4:00–4:30) Next Steps
If I had another quarter, I would ship an automated remediation pipeline where Dependabot automatically opens PRs for the SCA findings.
This directly ties to the OWASP SAMM ladder progression, moving us from simply detecting vulnerabilities (Defect Management Level 1) to automatically managing and remediating them (Maturity Level 2).

## (4:30–5:00) Q&A Anticipation

**1. "How would you handle a Log4Shell scenario in this pipeline?"**
Because we generate an SBOM (Software Bill of Materials) at the build stage using Syft and store it alongside our artifacts, I wouldn't need to re-scan our entire infrastructure to find Log4j. I could simply query our SBOM database or DefectDojo to instantly see which microservices contain the vulnerable package version, allowing us to patch and deploy within hours instead of days.

**2. "Why didn't you use paid, commercial enterprise tools?"**
I purposefully used open-source and CNCF-graduated tools like Trivy, Falco, and DefectDojo because they integrate seamlessly into CI/CD pipelines without licensing friction. While commercial tools (like IAST or advanced ASPM platforms) offer out-of-the-box dashboards, chaining these OSS tools together proves that world-class security can be achieved by engineering strong pipelines, not just by buying expensive software.
