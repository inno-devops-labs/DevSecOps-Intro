# 5-Minute DevSecOps Program Walkthrough - Juice Shop

## 0:00-0:30 - Context

I built a DevSecOps program around OWASP Juice Shop, using it as a deliberately vulnerable target to exercise controls from source code through runtime. The program includes signed Git workflow, secret scanning, SBOM/SCA, SAST, DAST evidence, IaC scanning, container hardening, Cosign verification, Falco runtime detection, and DefectDojo governance.

## 0:30-2:00 - Layers

At the pre-commit layer, I used gitleaks and signed commits to reduce secret leakage and improve source provenance before code reaches CI.

At build time, I generated a CycloneDX SBOM with Syft, scanned it with Grype, and compared results against Trivy's all-in-one image scan. This gives both an attestation-ready inventory and a fast vulnerability signal.

At the code and application layer, Semgrep found issues such as Sequelize SQL injection patterns, hard-coded JWT secrets, path traversal through `sendFile`, and unsafe redirect behavior. ZAP authenticated DAST found runtime issues including SQL Injection and missing browser security headers.

At pre-deploy, Checkov and KICS caught IaC weaknesses, while Kubernetes hardening and Conftest policies enforced non-root execution, dropped Linux capabilities, read-only filesystems, and resource controls.

At supply-chain and runtime layers, Cosign verification established image integrity evidence, and Falco detected shell execution, sensitive file reads, `/tmp` drift, and a simulated cryptominer network pattern.

Finally, DefectDojo turned these tool outputs into a managed backlog with severity, SLA, deduplication, and risk acceptance.

## 2:00-3:00 - Findings + Closures

The capstone imported 390 raw findings into DefectDojo. After one duplicate and one risk-accepted item, the active backlog is 388 findings: 18 Critical, 164 High, 169 Medium, 29 Low, and 8 Info.

I risk-accepted one informational libc finding, `CVE-2018-20796 in libc6:2.41-12+deb13u2`, expiring on `2026-10-07`. The reason is limited severity and an operational decision to revisit it during the next base-image refresh rather than interrupt Critical/High remediation.

The strongest correlated finding is SQL injection: Semgrep found tainted Sequelize query paths in routes such as `routes/login.ts` and `routes/search.ts`, while ZAP reported SQL Injection dynamically in the authenticated scan. The fix direction is parameterized queries and removing string-built SQL paths.

## 3:00-4:00 - Metrics

The DefectDojo engagement starts with MTTR not yet measurable because no findings were mitigated during this capstone import. Mean time to detect is 0 days because the imported findings were created and detected on `2026-07-09`.

The open vulnerability age median is 0 days, because this is a fresh governance baseline. SLA compliance is currently 100%: all 388 active findings are still within their configured SLA on the import date.

The backlog trend is rising by 388 active findings versus the empty baseline. That is expected for the first import, but the next review should focus on burning down the 18 Critical and 164 High findings first.

## 4:00-4:30 - Next Steps

If I had another quarter, I would mature OWASP SAMM Defect Management. The target would be zero Critical findings past SLA and a measured High-severity MTTR under 7 days, backed by weekly DefectDojo review and owner assignment.

## 4:30-5:00 - Q&A Anticipation

**How would you handle a Log4Shell scenario?**

I would start with the SBOM, because it answers which services include the affected package without rescanning source manually. Then I would re-run Grype and Trivy against the stored SBOM/image, import updated results into DefectDojo, prioritize internet-exposed or runtime-observed workloads, and use the SLA matrix to drive emergency remediation.

**Why didn't you use IAST or paid tools?**

The goal was to build an auditable open-source DevSecOps program that a small team can reproduce locally. IAST and commercial platforms can improve runtime code-path fidelity, but the foundation here is portable: source scanning, SBOM, container/IaC policy, signing, runtime detection, and vulnerability management. Once those controls are stable, adding IAST would be an incremental signal rather than the core program.
