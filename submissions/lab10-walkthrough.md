# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00-0:30) Context

I built a DevSecOps program around OWASP Juice Shop as the target application, using it as a deliberately vulnerable product so each control had something real to detect. The scope covered SBOM/SCA, SAST/DAST evidence from earlier labs, IaC scanning, image verification, runtime Falco alerts, and final aggregation in DefectDojo.

## (0:30-2:00) Layers

At pre-commit, I treated developer identity and secret hygiene as the first layer: signed commits and secret scanning reduce ambiguity before code reaches CI. At build time, Syft/Grype and Trivy gave package inventory and vulnerability findings, while Semgrep and ZAP from earlier work connected static source issues to reachable runtime behavior.

Before deployment, Checkov and KICS caught Terraform, Ansible, and Pulumi misconfiguration patterns, while Cosign and Conftest shifted trust and hardening checks into release gates. At runtime, Falco watched the container boundary and produced alerts for shell access, sensitive-file reads, `/tmp` drift, and cryptominer-like egress. DefectDojo then turned those separate signals into one product backlog with severity, SLA dates, dedup decisions, and program metrics.

## (2:00-3:00) Findings + Closures

The current DefectDojo import has 368 active unique findings after dedup: 18 Critical, 151 High, 161 Medium, 29 Low, and 9 Info. I manually deduped `CVE-2026-45447` across Grype and two Trivy imports, using finding `301` as the canonical record and marking the repeated findings as duplicates.

I have not closed findings yet because this lab focused on program setup, but the first remediation lane is clear: handle Critical runtime or exploitable dependency issues first, then burn down High IaC secrets and package vulnerabilities. I did not stop at scanner output; I turned it into a governed backlog with owners, SLA pressure, and runtime evidence.

## (3:00-4:00) Metrics

MTTD is 0 days because the scan-to-import loop happened on the same day, July 3, 2026. MTTR is not available yet because no findings have been mitigated in DefectDojo; that is the next program measurement, not something to invent.

Open vulnerability age median is 0 days, backlog trend is +368 active unique findings from the pre-capstone baseline, and current SLA compliance is 100% because all findings were created inside their SLA windows. The important next measurement is not just volume; it is whether Critical findings close inside 24 hours and High findings close inside 7 days.

## (4:00-4:30) Next Steps

If I had another quarter, I would mature OWASP SAMM Defect Management by assigning owners and remediation due dates to every Critical and High finding. The target would be 80% Critical closure within 24 hours and 50% High closure within 7 days, with risk acceptance requiring an explicit expiry date.

## (4:30-5:00) Q&A Anticipation

1. "How would you handle a Log4Shell scenario?"

I would start from the SBOM and DefectDojo inventory, search for the vulnerable component across all imported products, and create a high-priority campaign from affected findings. Then I would use CI gates to block new vulnerable builds, runtime detection to watch for exploitation patterns, and the SLA matrix to force Critical remediation inside 24 hours.

2. "Why didn't you use IAST or paid tools?"

The goal was to build a reproducible open-source program first: Syft, Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Cosign, Falco, Conftest, and DefectDojo are enough to prove the workflow. IAST or paid correlation tools could improve precision later, but I wanted the baseline to be transparent, portable, and understandable without vendor lock-in.
