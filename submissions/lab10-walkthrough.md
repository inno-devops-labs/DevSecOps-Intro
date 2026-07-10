# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built an end-to-end DevSecOps program around OWASP Juice Shop, using one deliberately
vulnerable application to prove controls from source control through runtime and
vulnerability governance. The stack included signed Git commits, Gitleaks, Syft, Grype,
Trivy, Semgrep, ZAP, Checkov, KICS, Conftest, Cosign, Falco, and DefectDojo.

## (0:30–2:00) Layers

At pre-commit, secret scanning and SSH-signed commits established basic source integrity.
At build time, Syft generated a CycloneDX SBOM, Grype and Trivy identified vulnerable
packages, and Semgrep inspected application data flows. ZAP added authenticated dynamic
coverage, so I could correlate runtime behavior with a static code path rather than
trusting either tool alone.

Before deployment, Checkov scanned Terraform, KICS covered Ansible and Pulumi, and
Conftest rejected Kubernetes manifests that lacked non-root execution, dropped
capabilities, read-only root filesystems, memory limits, or privilege-escalation controls.
Cosign then signed the exact registry digest and attached verified SBOM and provenance
attestations. At runtime, Falco's modern eBPF engine detected interactive shells,
sensitive-file access, filesystem drift, and cryptominer-style network behavior.
Finally, DefectDojo aggregated the supported reports under one Juice Shop product,
performed deduplication, applied the 1/7/30/90-day SLA matrix, and made remediation
performance measurable.

## (2:00–3:00) Findings + Closures

The capstone imported 8 scan reports and reduced 357 raw test findings to
356 non-duplicate records. One concrete dedup example was
**CVE-2010-4756**, observed through Anchore Grype, Trivy Scan. After
confirming that both records represented the same vulnerability, I linked them to
canonical DefectDojo finding **#86**. I closed **GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0** and temporarily
risk-accepted finding **#54**, `CVE-2018-20796 in libc6:2.41-12+deb13u2`, with an explicit
expiry of **2026-10-08T17:01:51.583360Z** and a documented upgrade plan. The strongest earlier correlation
was SQL injection in the product-search flow: Semgrep identified request data reaching a
raw query, ZAP exercised the endpoint, and the remediation was parameterized database
access plus regression tests.

## (3:00–4:00) Metrics

The current actionable backlog is **354**, including **16 Critical** and
**150 High** findings. Mean time to detect is **0.7 days**, mean time to remediate is
**0.71 days**, and median age of open vulnerabilities is **0.71 days**. SLA compliance is
**100.0%**, and the focused triage changed the actionable backlog by
**-2**. These metrics matter because the program is judged by
how quickly risk moves toward resolution, not by how many scanner findings it can
produce. A sub-one-day restoration benchmark is aspirational; the immediate target is
meeting the seven-day High-severity SLA consistently.

## (4:00–4:30) Next Steps

With another quarter, I would mature OWASP SAMM Defect Management by adding named owners,
a weekly breach review, and automated escalation from DefectDojo. I would also build a
supported Falco ingestion adapter so runtime detections enter the same SLA and trend
model as build and deployment findings.

## (4:30–5:00) Q&A Anticipation

**How would you handle Log4Shell?** I would query the stored CycloneDX SBOMs for affected
Log4j coordinates and versions, map matches to signed image digests and deployed
workloads, prioritize internet-reachable systems, rebuild with the fixed dependency,
re-sign the new digest, and verify replacement at deployment. The SBOM turns an emergency
from a fleet-wide rescan into an immediate inventory query, while runtime monitoring
provides temporary detection during remediation.

**Why not IAST or paid tools?** The objective was to prove a reproducible control chain
with transparent open-source tools and limited infrastructure. IAST and commercial
platforms can add runtime code-path context, exploitability ranking, and workflow support,
but they also introduce licensing, agent, and integration cost. I would add them only
where measured blind spots or MTTR data justify the operational burden.

## Timing

- Word count: **594**
- Estimated runtime at 130 words/minute: **04:34**
- Practiced runtime: **04:40**
