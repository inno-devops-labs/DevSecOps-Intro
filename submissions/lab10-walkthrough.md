# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:35) Context

I created a complete DevSecOps workflow for OWASP Juice Shop. The objective was to connect preventive controls, build-stage security testing, deployment validation, runtime monitoring and centralized vulnerability management.

The resulting DefectDojo engagement contains 382 raw records. Cross-scanner correlation reduced this number to 380 canonical findings. One Low-severity issue was then placed under a time-limited Risk Acceptance, leaving 379 active canonical findings.

## (0:35–2:30) Security layers

Before code is committed, Gitleaks checks for exposed secrets, while SSH-signed commits provide evidence that changes were made by an authenticated developer.

At the build stage, Syft creates SBOMs in CycloneDX and SPDX formats. Grype and Trivy analyze both these SBOMs and the container image for vulnerable dependencies. Semgrep extends coverage to source code by detecting issues such as injection risks, unsafe file operations, embedded credentials and insecure workflow interpolation.

Before deployment, Checkov and KICS inspect Terraform, Ansible and Pulumi configurations. Cosign is used to sign and verify the image, while policy checks serve as a deployment gate. As a result, the pipeline validates not only that an image was produced, but also that it is trusted and backed by security evidence.

During runtime, Falco performs behavioral monitoring through eBPF. Its alerts were preserved as supporting evidence. Because the raw Falco log format was not accepted by the available DefectDojo parsers, I documented that limitation instead of presenting it as a successful import.

DefectDojo consolidates the supported scan reports into a single Product and Engagement. It also applies remediation targets of 24 hours for Critical findings, seven days for High, 30 days for Medium and 90 days for Low.

## (2:30–3:00) Findings, correlation and treatment

The original imports contained 17 Critical, 163 High, 166 Medium, 27 Low and nine Informational records.

The clearest deduplication example is CVE-2026-5079 affecting `multer 1.4.5-lts.2`. The issue appeared once in Grype and twice in Trivy results. Because the scanners generated different titles, descriptions and fingerprint data, DefectDojo did not merge them automatically. After confirming that the CVE, component and affected version matched, I linked the records through DefectDojo’s built-in duplicate relationship. Finding 70 remains the canonical issue, while Findings 180 and 363 are marked as its duplicates.

I also created a controlled Risk Acceptance for the Low-severity issue named “Supply-Chain: Unpinned Package Version.” The exception applies only to the isolated training environment and expires on September 30, 2026. Once the acceptance expires, the finding is reactivated and its SLA begins again.

## (3:00–4:35) Metrics and governance

The current canonical backlog contains 379 active findings: 17 Critical, 161 High, 166 Medium, 26 Low and nine Informational.

The MTTD proxy is zero days because the scans and DefectDojo ingestion took place on the same UTC date. The median vulnerability age is also zero days because this is the first reporting period.

MTTR cannot yet be calculated because no finding has been marked as mitigated. This vulnerability-remediation metric is different from DORA Time to Restore Service, which measures recovery after a production outage or failure.

The backlog decreased by three records: two were converted into duplicates and one was moved into Risk Acceptance. All 370 active non-Informational findings are still within their SLA windows, giving the current open backlog a compliance rate of 100 percent.

## (4:35–5:00) Next steps

The next-quarter objective is to improve the OWASP SAMM Defect Management practice. I would assign clear owners, connect findings to remediation tickets, confirm fixes through re-imports and begin measuring severity-specific MTTR.

The goal is to resolve every Critical finding within 24 hours and every High finding within seven days. I would also convert Falco output into a normalized format so runtime detections can be managed through the same governance process.

## (5:00–5:30) Q&A anticipation

### How would you handle Log4Shell?

I would first search the SBOM for `log4j-core` and confirm affected versions using Grype and Trivy. Builds containing vulnerable versions would be blocked. The dependency would then be upgraded, the image rebuilt and a new SBOM generated. The replacement image would be signed, validated by policy checks and scanned again. DefectDojo would preserve the canonical finding and track it until remediation is confirmed.

### Why did you not use IAST or paid tools?

The program needed to run locally and remain reproducible without commercial licenses or external services. Open-source SCA, SAST, IaC scanning, image-signing and runtime-monitoring tools already provided broad coverage. IAST would be a logical future addition once reliable authenticated integration tests and realistic application traffic are available.
