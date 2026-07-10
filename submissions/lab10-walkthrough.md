# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a local DevSecOps security program around OWASP Juice Shop as the
target application. The scope covered source code, dependencies, container
images, infrastructure as code, Kubernetes configuration, image-signature
verification and runtime detection.

Instead of leaving each scanner result in a separate JSON file, I used
DefectDojo 2.58.2 to turn the outputs into one governed vulnerability backlog.

## (0:30–2:00) Layers

The first layer is pre-commit security. Gitleaks checks the repository for
secrets before they reach the remote, while signed commits provide evidence
of who created a change.

The build layer generates a CycloneDX SBOM with Syft. Grype and Trivy scan
the dependencies and operating-system packages, and Semgrep analyzes the
application source code for insecure patterns.

Before deployment, Checkov and KICS scan Terraform, Ansible and Pulumi.
Cosign verifies that the container image is signed, and policy checks can
stop an unsigned or non-compliant artifact from being deployed.

At runtime, Falco uses kernel-level event monitoring to identify suspicious
container behavior. Its output is different from a vulnerability report, so I
kept it as runtime evidence instead of forcing it into an incompatible
DefectDojo parser.

The final layer is the program layer. DefectDojo aggregates the reports,
deduplicates scanner overlap, applies SLA deadlines and provides one backlog
for triage, Risk Acceptance and remediation metrics.

## (2:00–3:00) Findings and decisions

Nine reports were imported through seven scan types. They produced 397 raw
findings. After deduplication, there were 348 unique primary findings and 347
remained active after one temporary Risk Acceptance.

A concrete correlation example was CVE-2026-45447 in libssl3t64. It appeared
in the Grype SBOM scan and in two Trivy tests. I reviewed the component,
version and vulnerability identifier, then linked the three source records to
DefectDojo finding 119 as the single primary item.

I risk-accepted one Low ZAP finding: a missing X-Content-Type-Options header
on the Socket.IO endpoint. The reason was that Juice Shop is intentionally
vulnerable and isolated for training. The acceptance expires on December 15,
2026, and the remediation recommendation remains to add the `nosniff`
response header.

No vulnerability was falsely presented as remediated. There are currently no
closed findings, so MTTR is reported as unavailable rather than as zero.

## (3:00–4:00) Metrics

The active primary backlog contains 12 Critical, 121 High, 172 Medium, 29 Low
and 13 Info findings.

I applied an SLA matrix of 24 hours for Critical, seven days for High, 30 days
for Medium and 90 days for Low. Because the findings existed before the SLA
was assigned, I backfilled dates for 384 applicable findings and verified all
calculated deadlines.

The open-finding SLA status is currently 100 percent within deadline: 334
active primary findings covered by the SLA are not overdue. Closed-finding
SLA compliance is not yet available because no finding has been mitigated.
That result needs context because the dataset was imported today.

MTTD is zero days because ingestion happened on the scan-aggregation date.
Median vulnerability age is also zero days. MTTR is not available because
the closed-finding sample size is zero.

Normalization reduced 397 raw scanner records to 347 active primary
findings, a difference of 50 records or 12.59 percent. This is not yet a
time-based backlog trend: it represents deduplication and one accepted risk,
not remediation.

## (4:00–4:30) Next steps

With another quarter, I would mature the OWASP SAMM Defect Management
practice. The target would be to close or formally disposition every Critical
finding within 24 hours and every High finding within seven days.

I would also enrich CVE records with EPSS and reachability data so remediation
priority reflects both technical severity and exploitation likelihood.

## (4:30–5:00) Q&A anticipation

### How would you handle a Log4Shell scenario?

I would first query the CycloneDX SBOM to identify every artifact containing
Log4j and its exact version. I would then confirm runtime reachability,
prioritize exposed applications, patch or rebuild the affected images, sign
the replacements with Cosign and verify the signatures before deployment.
DefectDojo would track the finding, affected assets, SLA deadline and closure
evidence in one place.

### Why did you not use IAST or paid tools?

The objective was to build a reproducible local program with open-source
tools that covered the major SDLC layers. IAST and commercial platforms could
add runtime code-path context, better correlation and enterprise support, but
they also introduce licensing, deployment and integration cost. I would add
them only where they solve a measured coverage gap that the current SAST,
DAST, SCA and runtime controls cannot address.
