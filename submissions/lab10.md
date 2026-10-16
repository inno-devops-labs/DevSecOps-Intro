# Lab 10 Submission — Vulnerability Management: The Capstone

**Git identity:** `shnupel <ufamail.com2@gmail.com>`  
**DefectDojo:** `2.58.3`  
**Product:** `OWASP Juice Shop`  
**Engagement:** `Course Semester Run`

DefectDojo was started from the pinned `2.58.3` source release with the `release` Docker profile. The local API was available at `http://localhost:8080`. The host did not contain `conftest`-related tooling for this lab; DefectDojo itself ran in Docker Compose.

## Task 1

### Imports

The importer discovered the parser names from DefectDojo and saved each API response in `labs/lab10/imports/`.

| Lab | File | Parser | Result |
|---|---|---|---:|
| 4 | `labs/lab4/grype-from-sbom.json` | `Anchore Grype` | SKIP: file missing |
| 4 | `labs/lab4/trivy.json` | `Trivy Scan` | SKIP: file missing |
| 5 | `labs/lab5/results/semgrep.json` | `Semgrep JSON Report` | SKIP: file missing |
| 5 | `labs/lab5/results/auth-report.json` | `ZAP Scan` | SKIP: file missing |
| 6 | `labs/lab6/results/checkov-terraform/results_json.json` | `Checkov Scan` | test 1, 80 active findings |
| 6 | `labs/lab6/results/kics-ansible/results.json` | `KICS Scan` | test 2, 10 active findings |
| 6 | `labs/lab6/results/kics-pulumi/results.json` | `KICS Scan` | test 3, 6 active findings |
| 7 | `labs/lab7/results/trivy-image.json` | `Trivy Scan` | test 4, 87 active findings |
| 7 | `labs/lab7/results/trivy-k8s.json` | `Trivy Operator Scan` | test 5, 0 active findings |

The importer completed successfully. The missing Lab 4 and Lab 5 artifacts were reported as `SKIP` because those files are not present in this repository snapshot.

### Active findings

Query used:

```bash
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?active=true&limit=1000" \
  | jq -c '[.results[].severity] | group_by(.) |
           map({severity: .[0], count: length})'
```

Result:

```json
[
  {"severity":"Critical","count":12},
  {"severity":"High","count":87},
  {"severity":"Info","count":2},
  {"severity":"Low","count":1},
  {"severity":"Medium","count":81}
]
```

**Total active findings: 183.**

The source-tool breakdown was:

| Source | Active findings |
|---|---:|
| Checkov Scan | 80 |
| KICS Scan | 16 |
| Trivy Scan | 87 |
| Trivy Operator Scan | 0 |
| **Total** | **183** |

### Duplicate titles

I selected titles with the same text and inspected their DefectDojo finding IDs, source test, component, version, path, and hash.

1. `CVE-2026-93748 HTTP-Cache-Semantics 4.2.0` appears twice in Trivy test 4. The findings point to two different dependency paths: `make-fetch-happen/node_modules/http-cache-semantics` and `sqlite3/node_modules/http-cache-semantics`. They are two separate vulnerable dependency occurrences, so I would track both until the dependency tree is remediated.
2. `Ensure Every Security Group and Rule Has a Description` appears three times in Checkov test 1. The components are `aws_security_group.allow_all`, `aws_security_group.ssh_open`, and `aws_security_group.database_exposed`, with different file lines and different DefectDojo hashes. They are three separate infrastructure findings that happen to share a Checkov title.

The title query was:

```bash
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?limit=1000" \
  | jq -c '[.results[].title] | group_by(.) |
           map(select(length > 1) | {title: .[0], n: length}) | .[:5]'
```

The most actionable findings this week are the 12 critical Trivy vulnerabilities and the exposed cloud/IAM controls from Lab 6, because they represent exploitable runtime dependencies and overly broad infrastructure permissions. The 87 Trivy image findings need triage by fix availability and exploitability; I would patch the critical and high findings first and rebuild the image. KICS and Checkov also contain valuable misconfiguration evidence, although repeated policy findings need grouping by resource before reporting to management. Labs 4 and 5 produced no imported findings in this run because their report files were absent, so that missing coverage is a process gap rather than evidence that SCA, SAST, and DAST are clean.

## Task 2

### SLA policy

The default DefectDojo configuration was:

| Severity | Default | My policy | Reason |
|---|---:|---:|---|
| Critical | 7 days | 3 days | Critical image or infrastructure issues can enable compromise and require an immediate owner and emergency patch path. |
| High | 30 days | 14 days | High findings should be fixed within the sprint that discovers them, with escalation after two weeks. |
| Medium | 90 days | 45 days | Medium issues should be handled within the next planning cycle while allowing coordinated infrastructure changes. |
| Low | 120 days | 90 days | Low findings still need an owner and a deadline, with a longer window for cleanup work. |

I updated the `Default` SLA configuration through `PATCH /api/v2/sla_configurations/1/` with:

```json
{"critical":3,"high":14,"medium":45,"low":90}
```

The API returned the updated values successfully.

### Findings by severity and source

Active findings by severity:

```text
Critical  12
High      87
Medium    81
Low        1
Info       2
Total    183
```

Active findings by imported source:

```text
Checkov Scan          80
KICS Scan             16
Trivy Scan            87
Trivy Operator Scan    0
Total                183
```

### Age and SLA calculations

The API returned an `age` value for each active finding. I calculated the metrics with this Python query over `/api/v2/findings/?active=true&limit=1000`:

```python
ages = [finding["age"] for finding in findings]
median_age = statistics.median(ages)
oldest_age = max(ages)
inside_sla = sum(
    finding["age"] <= {"Critical": 3, "High": 14,
                       "Medium": 45, "Low": 90,
                       "Info": 9999}[finding["severity"]]
    for finding in findings
)
```

All five imports were created during this run on `2026-10-10`, so the results were:

- Median age of active findings: **0 days**.
- Age of the oldest active finding: **0 days**.
- Active findings inside their SLA: **183 / 183 = 100.0%**.

These age numbers describe the imported DefectDojo records. They do not prove that the underlying vulnerabilities were newly discovered; the original scanner report dates and artifact freshness should be retained in a production pipeline.

Labs 8 and 9 produced signed image/attestation evidence and runtime/policy evidence. DefectDojo 2.58.3 has no importer used here for those artifacts, so the 183-finding number excludes them. I would store those results as signed CI artifacts, link them from the engagement, and add a control-evidence dashboard or custom importer rather than silently treating their absence as a pass.

### Risk acceptance

I would risk-accept the single low-severity KICS finding only after confirming that the affected resource is not internet-facing. The acceptance would expire on **2026-12-15**, the end of this semester engagement. The compensating control would be a restrictive network policy/security group, least-privilege credentials, monitoring for unexpected access, and a scheduled remediation task before expiry. Critical, high, and medium findings remain remediation work.

### Executive summary

The project has **183 active findings** across Checkov, KICS, and Trivy, including 12 critical and 87 high findings, and the imported records are currently inside the newly defined SLA windows. The single biggest risk is the combination of critical/high vulnerable components in the container image with exposed or over-privileged cloud infrastructure from the Lab 6 IaC scans. To close the project, I need owners for each critical/high finding, a patch-and-rebuild sprint for the image, an infrastructure review for the exposed permissions and network paths, and restored Lab 4–5 scanner artifacts so the project has complete coverage.

## Bonus

The hardest part of the semester to explain concisely was connecting scanner findings to runtime evidence and ownership: a report gives a count, while a useful security program must show the affected asset, the control decision, the deadline, and the verification signal. That difficulty shows that the next project should define a common finding schema and evidence links before the first scan runs. I would also keep an evidence index that records scanner version, artifact digest, import parser, owner, SLA, and remediation commit for every finding.
