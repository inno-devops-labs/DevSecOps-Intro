# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps training program around OWASP Juice Shop and used it as a single application target to practice secure source control, SBOM generation, SCA, SAST, DAST, IaC scanning, container hardening, runtime detection, signing, attestation, and vulnerability management. The capstone aggregated those outputs into DefectDojo so the work looked like a security program, not a pile of isolated tool runs.

## (0:30–2:00) Layers
At the developer layer, I used SSH-signed commits and pre-commit secret scanning to tighten source control hygiene. In build and analysis, I generated a CycloneDX SBOM, scanned dependencies with Trivy and prior SBOM-based tooling, and ran Semgrep for application code findings. Before deployment, I scanned infrastructure with Checkov and KICS, hardened Kubernetes manifests with Conftest policies, and signed the Juice Shop container plus attestations with Cosign. At runtime, I used Falco with modern BPF on Colima to catch terminal shells in containers, sensitive file access, `/tmp` drift, and a miner-like process pattern. At the program layer, I imported the available scan outputs into DefectDojo and used its engagement view as the single backlog for prioritization and reporting.

## (2:00–3:00) Findings + Closures
In the capstone DefectDojo engagement I aggregated `146` findings, including `5` Critical and `56` High issues. The largest source was infrastructure policy debt from Checkov and KICS, followed by container-image findings from Trivy. I did not mark any items as risk accepted in this run because the dataset was created as a clean local import snapshot; if I were carrying a real backlog, I would only risk-accept issues with a clear business reason, an explicit owner, and an expiry date.

## (3:00–4:00) Metrics
Because the engagement was imported on the same day, MTTD was effectively `0` days and the median vulnerability age was also `0` days. MTTR is not established yet because there were no mitigated findings in this capstone snapshot. The useful signal here is the severity mix and the backlog concentration: `82` Medium, `56` High, and `5` Critical findings, which tells me the next maturity step is prioritization and closure discipline rather than adding even more scanners.

## (4:00–4:30) Next Steps
If I had another quarter, I would improve the Defect Management practice by normalizing unsupported report formats and restoring missing scan inputs so cross-tool deduplication becomes reliable. I would also add runtime-finding ingestion for Falco so build-time and runtime issues live in the same response workflow.

## (4:30–5:00) Q&A Anticipation
### 1. How would you handle a Log4Shell scenario?
The first move would be to query the SBOM-backed inventory to identify which artifacts actually contain the affected library, instead of guessing based on package names or repo ownership. Then I would use the centralized vulnerability backlog to prioritize exposed internet-facing workloads first, verify whether container images and deployment manifests still reference the affected builds, and track remediation or compensating controls through the same engagement until closure.

### 2. Why didn’t you use IAST or paid enterprise tools?
For this course repo I optimized for tools that I could run locally, explain clearly, and reproduce end to end without a paid platform dependency. The goal was to prove I understand the workflow and governance model; once that foundation is in place, swapping or adding enterprise-grade scanners is much easier than trying to build process discipline after the fact.
