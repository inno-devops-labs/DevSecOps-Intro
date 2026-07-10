# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps program around OWASP Juice Shop version 20 as a stable, intentionally vulnerable target. The scope covered signed source changes, SBOM generation, application and infrastructure scanning, image signing and verification, deployment policy gates, runtime detection, and centralized vulnerability management in DefectDojo.

## (0:30–2:00) Layers

At the pre-commit layer, Gitleaks checked for exposed secrets, while SSH-signed commits provided verifiable author identity. At build time, Syft generated a CycloneDX SBOM, Grype and Trivy analyzed dependencies and container packages, and Semgrep detected insecure source-code patterns.

Before deployment, Checkov and KICS scanned Terraform, Ansible and Pulumi. Conftest evaluated Kubernetes manifests with Rego policies, while Cosign signed the image by digest and verified that the deployment referred to the expected immutable artifact.

At runtime, Falco used the modern eBPF probe to detect shell execution, sensitive-file access and custom suspicious behavior. DefectDojo was the program layer: I created one Product and one CI/CD Engagement, imported seven reports covering six scan types, and applied SLAs of 24 hours for Critical, 7 days for High, 30 days for Medium and 90 days for Low findings.

## (2:00–3:00) Findings + Closures

We closed zero Critical findings during this initial collection period because the engagement was created as a baseline rather than as a completed remediation cycle. I did not risk-accept any findings; in a production program, every risk acceptance would require an owner, business justification and explicit expiry date.

The strongest available cross-tool correlation was `CVE-2026-45447` in `libssl3t64` version `3.5.5-1~deb13u2`. Grype created finding `9` and Trivy created finding `226`. DefectDojo did not merge them because the two parsers produced different titles and hash codes, even though the vulnerability, component and version matched. The authenticated ZAP report was unavailable, so I could not honestly claim a Semgrep–ZAP correlation; instead, I documented that missing evidence and used the strongest correlation supported by the collected data.

## (3:00–4:00) Metrics

The active backlog was 275 findings: 12 Critical, 119 High, 128 Medium, 7 Low and 9 Informational. Approximate MTTD was 0.80 days, and median open-finding age was also approximately 0.80 days.

MTTR and SLA compliance were not measurable because no findings had been closed. Reporting either value as zero would be misleading. The DORA Elite comparison of recovery in less than one day therefore cannot be applied to this dataset yet; the next reporting period needs actual remediation and retest timestamps.

The backlog trend was stable at plus zero findings against the initial baseline of 275. EPSS data was available for 104 findings, so prioritization should combine severity with exploit probability, exposure, reachability and fix availability instead of sorting only by CVSS severity.

## (4:00–4:30) Next Steps

If I had another quarter, I would ship automatic ownership routing, remediation-ticket synchronization and mandatory retest evidence before closure. This advances the OWASP SAMM Defect Management practice and gives measurable targets: High-severity MTTR below seven days and at least 90% of closures within SLA.

## (4:30–5:00) Q&A Anticipation

**How would you handle a Log4Shell scenario?** I would query the CycloneDX SBOMs for affected `log4j-core` versions and transitive dependency paths, map affected components to deployed image digests, and prioritize internet-facing workloads. I would block vulnerable versions at the policy gate, rebuild and re-sign affected images, deploy the corrected digests, rescan them, and use Falco or network telemetry to look for JNDI exploitation indicators. Closure would require deployment and retest evidence proving that the vulnerable component was removed.

**Why did you not use IAST or paid tools?** The main constraints were educational budget, reproducibility and transparency. The open-source stack produced inspectable reports, APIs and policy logic without vendor lock-in. In production, I would evaluate IAST or commercial correlation only if it demonstrated measurable gains in coverage, false-positive reduction, integration cost or MTTR rather than selecting it only from a feature list.
