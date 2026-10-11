# 5-Minute DevSecOps Program Walkthrough - Juice Shop

## (0:00-0:30) Context

I built a DevSecOps program around OWASP Juice Shop as the target application, using it as a deliberately vulnerable system to exercise the full detection-to-governance loop. The scope covered SBOM/SCA, SAST, DAST evidence, IaC scanning, Kubernetes hardening, image signing/verification, runtime Falco alerts, and DefectDojo aggregation with SLA tracking.

## (0:30-2:00) Layers

The program is layered like a delivery pipeline. At source-control time, the goal is to prevent obvious mistakes from entering history, so earlier labs used signed commits and secret-leak prevention. At build time, Syft generated the SBOM, Grype scanned that SBOM, and Trivy scanned the image directly so I could compare decoupled inventory scanning with an all-in-one scanner.

Before deployment, Semgrep covered application code patterns, Checkov and KICS covered Terraform, Ansible, and Pulumi, and Cosign verified that the image/SBOM provenance story was not just a spreadsheet claim. At the Kubernetes layer, Conftest enforced pod security expectations such as non-root execution, dropped capabilities, read-only root filesystem, resource limits, and digest-pinned images.

At runtime, Falco detected suspicious behavior such as an interactive shell, sensitive file reads, writes to `/tmp`, and a simulated cryptominer-style network command. Finally, DefectDojo turned all those scanner outputs into one product, one engagement, one SLA matrix, and one backlog that can be managed.

## (2:00-3:00) Findings + Closures

The DefectDojo import created 388 raw findings and 338 active non-duplicate findings after dedupe. The current high-priority backlog is 12 Critical and 119 High findings, with the strongest immediate remediation theme being vulnerable JavaScript dependencies in Juice Shop.

No findings were closed during this capstone period, so I did not manufacture MTTR. Instead, I made that explicit: MTTR is not established until the team starts closing findings through the workflow. I also did not risk-accept anything; if we accept risk later, each acceptance needs an expiry date, owner, reason, and compensating control.

The clearest dedupe proof is `CVE-2021-23337`: DefectDojo marked Lab 7 Trivy finding `354` as a duplicate of Lab 4 Trivy finding `163`. A useful cross-tool lesson is that the same CVE also appeared from Anchore Grype, but the default Grype and Trivy parser hashes did not collapse it automatically, so parser configuration matters.

## (3:00-4:00) Metrics

The current MTTD is 0 days because findings were imported into DefectDojo on the same reporting day. MTTR is not established because there were no mitigated findings yet. The median vulnerability age is also 0 days on import day.

Backlog trend is +338 active non-duplicate findings versus the previous baseline of 0 centrally tracked findings. SLA compliance is currently 100% because the SLA clock starts on `2026-07-03`, with Critical due in 24 hours, High in 7 days, Medium in 30 days, and Low in 90 days. The dedupe run reduced the raw imported backlog by 50 findings, or about 12.9%.

## (4:00-4:30) Next Steps

If I had another quarter, I would mature OWASP SAMM Defect Management by moving from "find everything" to "close the right things predictably." The measurable goal would be to remediate or formally risk-accept all Critical findings within 24 hours, reduce the High backlog by 50%, and add parser-compatible ingestion for Falco and ZAP so those signals enter the same governance loop.

## (4:30-5:00) Q&A Anticipation

**How would you handle a Log4Shell scenario?** I would start with the SBOM rather than guessing from source repos. The CycloneDX SBOM gives an inventory of packages and versions for the image, then Grype/Trivy can rescan that inventory as CVE intelligence changes. A Log4Shell-style response becomes: identify affected components, map them to running artifacts, prioritize internet-exposed products, open DefectDojo findings with a Critical SLA, and track closure or time-boxed risk acceptance.

**Why did you not use IAST or paid tools?** The course goal was to build the operating model with reproducible open-source tools first. Paid tools can improve coverage and workflow polish, but they do not replace the basics: inventory, scanning, policy gates, runtime detection, deduplication, ownership, SLAs, and metrics. I would add IAST or commercial SCA after the team can already act on the findings it has.
