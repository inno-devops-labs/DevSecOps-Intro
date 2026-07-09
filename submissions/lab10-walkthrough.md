# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built an end-to-end DevSecOps program around OWASP Juice Shop. The goal was to connect prevention, build-time analysis, deployment controls, runtime detection and vulnerability governance.

The final DefectDojo engagement contains 382 raw records. Cross-tool correlation reduced them to 380 canonical findings, and one Low finding entered a time-bound Risk Acceptance, leaving 379 active canonical findings.

## (0:30–2:00) Security layers

Before code reaches the repository, Gitleaks prevents secrets from being committed, while SSH-signed commits provide developer-authenticity evidence.

During the build stage, Syft generates CycloneDX and SPDX SBOMs. Grype and Trivy use those artifacts and the container image to identify vulnerable dependencies. Semgrep adds source-level SAST coverage for injection, unsafe file access, hard-coded credentials and insecure workflow interpolation.

Before deployment, Checkov and KICS scan Terraform, Ansible and Pulumi. Cosign signs and verifies the image, and policy checks act as a deployment gate. The pipeline therefore evaluates not only whether an image exists, but whether it is trusted and supported by evidence.

At runtime, Falco provides eBPF-based behavioral detection. Its alerts were retained as evidence. The raw Falco format was not directly compatible with installed DefectDojo parsers, so I documented the limitation rather than claiming a false import.

DefectDojo aggregates the supported reports into one Product and Engagement and applies targets of 24 hours for Critical, seven days for High, 30 days for Medium and 90 days for Low findings.

## (2:00–3:00) Findings, correlation and treatment

The imports produced 17 Critical, 163 High, 166 Medium, 27 Low and nine Informational raw records.

The strongest correlation example is CVE-2026-5079 in multer 1.4.5-lts.2. It appeared in one Grype result and two Trivy scan sources. Scanner-specific titles and descriptions produced different fingerprints, so automatic deduplication did not merge them. After confirming the same CVE, component and version, I used DefectDojo's native duplicate relationship. Finding 70 is canonical, while Findings 180 and 363 reference it as duplicates.

I also created one controlled Risk Acceptance for the Low-severity finding “Supply-Chain: Unpinned Package Version.” It is limited to the isolated training environment and expires on September 30, 2026. Expiration reactivates the finding and restarts its SLA.

## (3:00–4:00) Metrics and governance

The active canonical backlog is 379 findings: 17 Critical, 161 High, 166 Medium, 26 Low and nine Informational.

The MTTD proxy is zero days because scan execution and DefectDojo ingestion occurred on the same UTC day. The median age is also zero days because this is the first measurement period.

MTTR is not measurable because no finding has been marked as mitigated. This vulnerability-remediation metric is not the same as DORA Time to Restore Service, which measures recovery from a production failure.

The backlog delta is minus three: two records became duplicates and one finding entered Risk Acceptance. All 370 active non-Informational findings remain within SLA deadlines, so current open-backlog compliance is 100 percent.

## (4:00–4:30) Next steps

The next-quarter goal is to mature OWASP SAMM Defect Management. I would assign owners, connect findings to remediation tickets, verify fixes through re-imports and calculate real severity-specific MTTR.

The target is to remediate every Critical finding within 24 hours and every High finding within seven days. I would also normalize Falco output so runtime detections enter the same governance workflow.

## (4:30–5:00) Q&A anticipation

### How would you handle Log4Shell?

I would query the SBOM for log4j-core, validate affected versions with Grype and Trivy, block affected builds, upgrade the dependency, rebuild the image and generate a new SBOM. The replacement image would be signed, pass the policy gate and be re-scanned. DefectDojo would track the canonical finding through remediation.

### Why did you not use IAST or paid tools?

The program had to be reproducible locally without licenses or external services. Open-source SCA, SAST, IaC, signing and runtime tools provided broad coverage. IAST would be a useful next step after reliable authenticated integration tests and realistic traffic are available.
