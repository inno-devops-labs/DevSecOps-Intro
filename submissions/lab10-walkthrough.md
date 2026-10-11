# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps vulnerability-management program around OWASP Juice Shop as the target application. The goal was not only to run scanners, but to centralize their findings in DefectDojo, apply SLA-based triage, and produce a governance report that shows the state of the security backlog.

The scope covered SCA, SAST, DAST evidence, IaC scanning, container scanning, supply-chain verification, and runtime/admission-control evidence from the previous labs.

## (0:30–2:00) Layers

The program is built in layers.

At the source and pre-commit level, the course flow covered Git hygiene, signed work, and secret-awareness practices. This reduces the chance of introducing sensitive material or unreviewed changes before CI even starts.

At the build and CI level, I generated SBOM and SCA evidence with Syft, Grype, and Trivy. This gives visibility into vulnerable packages and components in the application and container image.

At the application-security level, I used Semgrep for SAST and ZAP for DAST evidence. Semgrep produced code-level findings such as injection and unsafe framework usage. ZAP evidence was generated in the earlier lab, but the JSON report was not accepted by the DefectDojo ZAP parser because that parser expected XML in this run, so I documented the failed import honestly.

At the infrastructure and pre-deploy level, I used Checkov and KICS for IaC scanning. These tools identified configuration risks such as public exposure, insecure defaults, and weak infrastructure patterns.

At the container and Kubernetes level, I imported Trivy image results and attempted Trivy Operator results. Runtime and admission-control evidence from Falco and Conftest was documented as part of the program context, even where a native DefectDojo parser was not available.

The final program layer is DefectDojo. It acts as the central triage hub: findings are imported, grouped by source, assigned severity, connected to SLA expectations, and reported as a single backlog instead of scattered scanner outputs.

## (2:00–3:00) Findings + Closures

The current DefectDojo baseline contains 385 active findings.

The severity distribution is 17 Critical, 164 High, 168 Medium, 27 Low, and 9 Informational findings. The largest sources were Trivy and Grype for dependency/container findings, Checkov for infrastructure-as-code findings, and Semgrep for code-level findings.

No findings were closed during this baseline run. I intentionally treated this as the initial vulnerability-management baseline: first centralize the findings, then assign owners, then close or risk-accept based on SLA.

No findings were risk-accepted. This is important because risk acceptance should not be used as a shortcut. If a finding is accepted later, it must have a clear reason, owner, and expiry date.

One useful correlation example was a secret exposure in `juice-shop/lib/insecurity.ts`, visible across Trivy scan contexts. Even though DefectDojo did not mark it as a duplicate in this dataset, seeing the same class of issue across scanning stages increases confidence that it should be reviewed and remediated.

## (3:00–4:00) Metrics

The key number is the backlog: 385 active findings after the initial import.

MTTR is not yet measurable because no findings have been mitigated in this baseline. MTTD is also only partially measurable because the imported historical scanner files do not preserve the original vulnerability-introduction timestamps. For the lab baseline, all findings were centralized in DefectDojo during one import session.

The vulnerability age median is 0 days at baseline import time because this is the first DefectDojo ingestion point. The backlog trend is +385 findings compared with the empty initial product.

SLA exposure is now explicit: 17 Critical findings require 24-hour treatment, 164 High findings require 7-day treatment, 168 Medium findings require 30-day treatment, and 27 Low findings require 90-day handling or formal acceptance.

The important part was not running nine scanners; it was turning their output into an owned backlog with SLA, state, and measurable risk.

## (4:00–4:30) Next Steps

If I had another quarter, I would mature the OWASP SAMM Defect Management practice.

The concrete target would be to assign owners for every Critical and High finding, close or formally risk-accept all Critical findings, and reduce the High backlog by at least 30%. I would also improve ingestion coverage by converting ZAP reports to XML and adding a custom parser or documented workflow for Falco runtime alerts.

## (4:30–5:00) Q&A Anticipation

### Question 1: How would you handle a Log4Shell scenario?

I would start from the SBOM and SCA layer. The first question is whether the affected component exists anywhere in the application, container image, or transitive dependency tree. If it exists, I would import or update the finding in DefectDojo, mark affected assets as Critical, assign the 24-hour SLA, and track remediation through owner assignment, patch verification, and re-scan evidence. The key is that SBOM answers "do we have it?" quickly, while DefectDojo answers "who owns it and is it fixed on time?"

### Question 2: Why did you not use IAST or paid tools?

For this lab, I focused on open-source tools that fit the course pipeline and can be reproduced locally: Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Cosign, Falco, Conftest, and DefectDojo. IAST and paid platforms could improve runtime context and prioritization, but they are not required to demonstrate the core DevSecOps workflow: discover, triage, remediate, report, and improve. I would consider them later after the basic vulnerability-management loop is already working.
