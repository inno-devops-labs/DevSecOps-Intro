# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: `2.58.2-alpine`
- Platform: `linux/arm64`
- Deployment method: Docker Compose
- Local URL: `http://localhost:8080`

The initial deployment failed because the Compose configuration used the
latest DefectDojo images together with the source code from version 2.58.2.
The problem was fixed by pinning the images to:

```text
defectdojo/defectdojo-django:2.58.2-alpine
defectdojo/defectdojo-nginx:2.58.2-alpine
```

After pinning the images, the initializer completed successfully and the UI
returned HTTP 200.

The generated administrator password was retrieved from the initializer logs.
It was changed after the first login and is intentionally not stored in the
repository.

### Product + Engagement

- Product ID: `1`
- Product name: `OWASP Juice Shop`
- Product description: `DevSecOps-Intro capstone product`
- Engagement ID: `1`
- Engagement name: `Course Semester Run`
- Engagement type: `CI/CD`
- Engagement status: `In Progress`
- Target start: `2026-09-01`
- Target end: `2026-12-15`

### Imports completed

| Lab | Scan type | File | Findings imported |
|---:|---|---|---:|
| 4 | Anchore Grype | `grype-from-sbom.json` | 104 |
| 4 | Trivy Scan | `trivy.json` | 113 |
| 5 | Semgrep JSON Report | `semgrep.json` | 22 |
| 5 | ZAP Scan | `auth-report.json` | 12 |
| 6 | Checkov Scan | `checkov-terraform/results_json.json` | 80 |
| 6 | KICS Scan | `kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan | `trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `trivy-k8s.json` | 0 |
| **Total raw imports** | | | **397** |
| **After deduplication** | | | **348 unique primary findings** |
| **Active after Risk Acceptance** | | | **347 active primary findings** |

Nine reports were imported using seven DefectDojo scan types:

1. Anchore Grype
2. Trivy Scan
3. Semgrep JSON Report
4. ZAP Scan
5. Checkov Scan
6. KICS Scan
7. Trivy Operator Scan

The Trivy Kubernetes report was imported successfully but contained no
findings supported by the selected parser.

### ZAP report conversion

The Lab 5 ZAP report was generated in JSON format, while the DefectDojo
`ZAP Scan` parser in version 2.58.2 expected XML.

The first import attempt returned:

```text
Internal error: Wrong file format, please use xml.
```

The report was converted into the following ZAP XML structure:

```text
OWASPZAPReport
└── site
    └── alerts
        └── alertitem
            └── instances
                └── instance
```

The converted report contained four sites, 12 alerts and 42 request/response
instances. The corrected import returned HTTP 201 and created 12 findings.

### Reports documented but not imported

#### Falco

The Lab 9 file `falco/logs/falco.log` contains runtime security alerts.
It is not a vulnerability scan in a standard format supported by the
installed DefectDojo parsers. The file was therefore documented as runtime
detection evidence instead of being imported through an unrelated parser.

#### Cosign

The Lab 8 `verify-original.json` output represents verification of a signed
container image. Cosign proves supply-chain authenticity and integrity but
does not produce vulnerability findings. It was therefore treated as
security evidence rather than imported as a vulnerability scan.

### Dedup example

The vulnerability `CVE-2026-45447` in component `libssl3t64` version
`3.5.5-1~deb13u2` was detected by two source tools and in three imported
tests:

| Finding ID | Test | Source tool | Final state |
|---:|---|---|---|
| 12 | Lab 4 — Grype from SBOM | Anchore Grype | Duplicate of finding 119 |
| 119 | Lab 4 — Trivy filesystem/image | Trivy Scan | Primary finding |
| 336 | Lab 7 — Trivy container image | Trivy Scan | Duplicate of finding 119 |

Deduplication result:

- CVE/ID: `CVE-2026-45447`
- Number of source tools: `2`
- Source tools: Anchore Grype and Trivy
- Number of source findings: `3`
- DefectDojo primary finding ID: `119`
- Duplicate findings: `12` and `336`

DefectDojo initially deduplicated the two Trivy findings automatically.
Because the Grype parser generated a different scanner-specific hash, the
cross-parser relationship was explicitly reviewed and linked to the same
primary finding.

Final deduplication totals:

| State | Count |
|---|---:|
| Total imported findings | 397 |
| Unique primary findings | 348 |
| Duplicate findings | 49 |
| Active primary findings | 347 |
| Inactive findings | 50 |

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop was scanned through seven DefectDojo scan types, producing
397 raw findings and 348 unique findings after deduplication. The current
active backlog contains 347 primary findings, including 12 Critical and 121
High findings. No findings have yet been remediated, so MTTR and
closed-finding SLA compliance cannot be calculated from a valid sample; all
334 active primary findings covered by the SLA matrix are currently within
their deadlines.

### SLA matrix

A dedicated DefectDojo SLA configuration named `Lab 10 SLA Matrix` was
created and assigned to Product ID 1.

| Severity | SLA | Enforcement |
|---|---:|---|
| Critical | 24 hours | Enabled |
| High | 7 days | Enabled |
| Medium | 30 days | Enabled |
| Low | 90 days | Enabled |

The configuration has SLA ID `3`.

Because the findings existed before the SLA configuration was assigned, SLA
start and expiration dates were backfilled for all applicable findings.

Backfill result:

- Findings processed: `397`
- Findings updated: `384`
- Info findings skipped because no Info SLA was required: `13`
- Failed updates: `0`

Example expiration dates for findings discovered on `2026-07-10`:

| Severity | SLA expiration |
|---|---|
| Critical | `2026-07-11` |
| High | `2026-07-17` |
| Medium | `2026-08-09` |
| Low | `2026-10-08` |

### Findings by severity — active primary only

| Severity | Count |
|---|---:|
| Critical | 12 |
| High | 121 |
| Medium | 172 |
| Low | 29 |
| Info | 13 |
| **Total** | **347** |

Critical and High findings account for 133 active primary findings and are
the first remediation priority under the SLA policy.

### Findings by source tool

The table shows all findings attributed to each parser before removing
duplicates from the source totals.

| Tool | Total | Active | Mitigated | False Positive | Risk Accepted | Duplicates |
|---|---:|---:|---:|---:|---:|---:|
| Anchore Grype | 104 | 103 | 0 | 0 | 0 | 1 |
| Trivy Scan | 163 | 115 | 0 | 0 | 0 | 48 |
| Semgrep JSON Report | 22 | 22 | 0 | 0 | 0 | 0 |
| ZAP Scan | 12 | 11 | 0 | 0 | 1 | 0 |
| Checkov Scan | 80 | 80 | 0 | 0 | 0 | 0 |
| KICS Scan | 16 | 16 | 0 | 0 | 0 | 0 |
| **Total** | **397** | **347** | **0** | **0** | **1** | **49** |

The Trivy total combines the Lab 4 filesystem/image test and the Lab 7
container-image test. The two KICS imports are also combined in one
source-tool row.

### Program metrics

- **MTTD:** `0 days`
- **MTTR:** `N/A`
- **MTTR sample size:** `0 closed findings`
- **Vulnerability-age median:** `0 days`
- **Raw scanner-record baseline:** `397 findings`
- **Current normalized active primary backlog:** `347 findings`
- **Normalized backlog change:** `-50 records`, or `-12.59%`
- **Time-based backlog trend:** `N/A — only one measurement period exists`
- **Open-finding SLA status:** `100% currently within SLA`
- **Closed-finding SLA compliance:** `N/A — no mitigated findings`
- **Active primary findings within SLA:** `334`
- **Active primary findings over SLA:** `0`

#### Metric methodology and limitations

MTTD is zero days because the reports were imported into DefectDojo on the
same calendar day as the capstone aggregation. This measures ingestion delay,
not the age of the vulnerabilities in the upstream packages.

MTTR is reported as `N/A` rather than zero because no finding has been marked
as mitigated. Reporting zero would incorrectly imply immediate remediation.

The median open vulnerability age is zero days because all findings were
created in DefectDojo on `2026-07-10` and the metrics were collected on the
same day.

The comparison between 397 raw imported findings and 347 active primary
findings represents normalization of scanner output, not a time-based backlog
trend. The reduction comes from 49 duplicate relationships and one
risk-accepted item; it does not represent 50 remediated vulnerabilities.
A genuine backlog trend cannot yet be calculated because only one measurement
period exists.

The open-finding SLA status is 100% within deadline as of `2026-07-10`: all
334 active primary findings with Critical, High, Medium or Low severity are
still within their configured deadlines. Closed-finding SLA compliance is
reported as `N/A` because no findings have been mitigated. The 13 Info findings
are excluded because the assignment does not define an SLA for Info severity.

### CVSS and EPSS triage

The first prioritization dimension is technical severity. Critical and High
findings receive the shortest SLA deadlines and form the initial remediation
queue.

The second dimension is exploit likelihood and real-world exposure. Where
EPSS data is available, the remediation order should follow this matrix:

| CVSS severity | EPSS likelihood | Priority |
|---|---|---|
| High/Critical | High | Immediate remediation |
| High/Critical | Low | Validate reachability and remediate within SLA |
| Medium/Low | High | Escalate because exploitation is likely |
| Medium/Low | Low | Normal backlog or documented acceptance |

The current local import dataset does not contain a complete and consistently
populated EPSS value for every finding. Therefore no invented EPSS percentage
is reported. The next automation step is to enrich CVE findings with EPSS and
use it together with reachability and asset exposure.

### Risk-accepted items

| Finding | Severity | Source | Reason | Expiry date |
|---|---|---|---|---|
| `393` — X-Content-Type-Options Header Missing | Low | ZAP Scan | Juice Shop is intentionally vulnerable and is running only in an isolated local training environment. The acceptance is temporary and must not be used for a production deployment. | `2026-12-15` |

Risk Acceptance details:

- Decision: `Accept`
- Security recommendation: `Fix`
- Active: `false`
- Risk accepted: `true`
- Mitigated: `false`

Recommended remediation remains to configure the application or reverse proxy
to return:

```text
X-Content-Type-Options: nosniff
```

The explicit expiry prevents the accepted risk from becoming a permanent,
unreviewed exception.

### Next-quarter goal — OWASP SAMM

The next-quarter goal is to mature the OWASP SAMM **Defect Management**
practice. The current program has 347 active primary findings, including 133
Critical or High findings, but no closed-finding sample and therefore no real
MTTR baseline.

The concrete target is to remediate or formally disposition every Critical
finding within 24 hours and every High finding within seven days, while
recording mitigation dates in DefectDojo. This will create a valid MTTR
dataset, allow closed-within-SLA measurement, and replace the current
same-day ingestion metrics with remediation-outcome metrics.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: `4 minutes 32 seconds`
- Two anticipated Q&A questions covered: `yes`
- Strongest claim in the script: “I reduced 397 scanner records to 348 unique findings, linked the same OpenSSL CVE across Grype and Trivy, and converted the resulting backlog into an enforceable SLA program.”
