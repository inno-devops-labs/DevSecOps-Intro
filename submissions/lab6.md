# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 129
- Passed: 49
- Failed: 80

| Severity | Count |
|----------|------:|
| (n/a in Checkov CE) | — |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23  | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |

### Pulumi scan
Checkov 3.x has no native `pulumi` framework — it can only scan Pulumi via a pre-rendered state
JSON (`pulumi preview --json`) or the Python-SAST framework. The rendered-state fallback file was
not present in the plumbing — `labs/lab6/vulnerable-iac/pulumi/` ships Python source only
(`__main__.py`, `Pulumi.yaml`, `Pulumi-vulnerable.yaml`, `requirements.txt`) — so Checkov cannot
meaningfully evaluate these cloud resources. Per the lab's own guidance, **Pulumi is scanned with
KICS in Task 2**, which natively understands Pulumi source. This is the tool-specialization
trade-off the lab highlights: Checkov leads on Terraform, KICS covers the broader format set.

### Module-leverage analysis (Lecture 6 slide 17)
The single highest-leverage fix is tightening the shared **IAM policy module**. Four of the top
five rules — CKV_AWS_289, CKV_AWS_355, CKV_AWS_288 and CKV_AWS_290 (14 findings combined) — all
stem from the same root cause: IAM policy documents that grant unconstrained access via
`"Action": "*"` and/or `"Resource": "*"` instead of being scoped. If the IAM module replaced its
wildcard statements with least-privilege, resource-scoped actions as the default, all four rules
would stop firing across every resource that consumes the module, collapsing roughly 14 findings
into a single module-level change.

---

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Findings |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **One thing Checkov did better on the Terraform sample:** Checkov has a native Terraform graph
  engine, so it resolved 129 checks into precise CKV_AWS_* IDs that map directly to CIS controls,
  each with a human-readable description and resource location. That made module-level triage
  trivial — the wildcard-IAM cluster was immediately visible as one root cause across four rules,
  something a generic Rego engine would not group as cleanly.
- **One thing KICS did better on the Ansible sample:** KICS natively parses Ansible playbooks (and
  Pulumi), formats for which Checkov 3.x has no first-class framework. It surfaced hardcoded
  credentials and an unpinned package version straight out of the playbook YAML — findings Checkov
  would have skipped entirely because it cannot evaluate Ansible at all, demonstrating KICS's
  broader format coverage.
- **A finding only one tool caught:** The hardcoded secrets (Generic Password / Password in URL /
  Generic Secret) in the Ansible playbook were found only by KICS — Checkov never scanned that
  format, so for Ansible the two tools are not even comparable; KICS is the only option here.

---

## Bonus: Custom Checkov Policy

### Policy file (labs/lab6/policies/my-custom-policy.yaml)
\`\`\`yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure RDS instances have storage encryption enabled"
  category: "ENCRYPTION"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "storage_encrypted"
  operator: "equals"
  value: true
\`\`\`

### Rule fires
Output of `jq '.[].results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`
(trimmed to the relevant fields):
\`\`\`json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances have storage encryption enabled",
  "check_result": {
    "result": "FAILED",
    "evaluated_keys": ["storage_encrypted"]
  },
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "file_line_range": [5, 37],
  "severity": "HIGH"
}
\`\`\`
The policy correctly flags `aws_db_instance.unencrypted_db`, which sets `storage_encrypted = false`
(database.tf line 15).

### Why this rule matters
Unencrypted RDS storage exposes the entire database — including automated backups, snapshots and
read replicas — to anyone who obtains the underlying volume or a leaked snapshot, which is exactly
how several breaches have leaked customer data from databases that were assumed "internal" but were
not encrypted at rest. Enabling `storage_encrypted` enforces AES-256 encryption at the volume level
and directly satisfies the CIS AWS Foundations Benchmark control for RDS encryption at rest, as well
as NIST 800-53 SC-28 ("Protection of Information at Rest"). Enforcing it as a hard policy catches the
gap at PR time, before an unencrypted instance ever reaches production — and Checkov ships no
built-in rule that fails the plan on missing RDS storage encryption, so this fills a real gap.
