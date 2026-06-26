# Lab 6 — Submission

IaC security scanning on the provided `vulnerable-iac/` samples. I used **Checkov 3.2.510** on the Terraform,
and **KICS** (Docker, `checkmarx/kics:latest`) on the Ansible and Pulumi. Didn't touch the vulnerable files,
just scanned them.

## Task 1: Checkov on Terraform (+ a note on Pulumi)

### Terraform scan
- Resources scanned: **16**
- Passed: **34**
- Failed: **57** (plus **2** hardcoded secrets from Checkov's secrets scanner — the AWS key in `main.tf:8`
  and the DB password in `database.tf:48`)

| Severity | Count |
|----------|------:|
| Critical | n/a |
| High | n/a |
| Medium | n/a |
| Low | n/a |

> Honest note: Checkov **CE leaves `severity` null** in the JSON unless you pass a Prisma/Bridgecrew API key —
> all 57 failed checks came back `severity: null`, so I couldn't fill a real severity table. That's actually fine
> for this lab because slide 17's triage is by **rule frequency**, which I do have:

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policy allows permissions-management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy uses `"*"` as the resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group rule should have a description |
| CKV_AWS_288 | 3 | IAM policy allows data exfiltration |
| CKV_AWS_290 | 3 | IAM policy allows write access without constraints |

(33 distinct rules failed in total. `CKV_AWS_382` — egress to `0.0.0.0/0` — also had 3.)

### Pulumi scan (with Checkov)
Checkov **has no Pulumi framework** — running `checkov -d .../pulumi` only fired the **secrets** scanner
(1 hit: a hardcoded password in `Pulumi-vulnerable.yaml:19`). It found zero of the actual IaC misconfigs because
it literally can't read Pulumi resources. That's exactly why the lab hands Pulumi to KICS (see Task 2), and it's a
nice live example of "tool ecosystems specialize" — Checkov is great at Terraform, blind to Pulumi.

| Tool | Pulumi IaC findings | Pulumi secret findings |
|------|--------------------:|-----------------------:|
| Checkov | 0 (no framework) | 1 |
| KICS (Task 2) | 4 | 1 |

### Module-leverage analysis (slide 17)
**Four of my top-5 rules (CKV_AWS_289, 355, 288, 290) are all the same root cause: IAM policies using
`Action: "*"` / `Resource: "*"`.** They fire across `admin_policy` (8 fails), `service_policy` (6),
`s3_full_access` (4) and the privilege-escalation policy. So the single highest-leverage fix is to replace those
wildcard policies with least-privilege, scoped statements (specific actions, specific ARNs) — one disciplined IAM
module would clear ~14 findings at once. The other obvious hotspot is RDS: `unencrypted_db` alone trips **10**
checks and `weak_db` another **6**, so a hardened RDS module (encryption on, not public, backups, deletion
protection, monitoring/logs) would knock out ~16 more.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Top KICS queries — Ansible
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Top KICS queries — Pulumi (CRITICAL 1 / HIGH 2 / MEDIUM 1 / INFO 2 = 6)
| Query | Severity |
|-------|----------|
| RDS DB Instance Publicly Accessible | CRITICAL |
| DynamoDB Table Not Encrypted | HIGH |
| Passwords And Secrets - Generic Password | HIGH |
| EC2 Instance Monitoring Disabled | MEDIUM |
| DynamoDB Table Point In Time Recovery Disabled | INFO |
| EC2 Not EBS Optimized | INFO |

### Checkov vs KICS — when to use which?
- **Checkov did better on the Terraform** — 57 findings across 33 rules, with genuinely fine-grained IAM
  reasoning (separate checks for data-exfiltration, write-without-constraints, privilege escalation). KICS's
  Terraform catalog is broad but wouldn't have sliced the IAM wildcard problem that many ways.
- **KICS did better on the Ansible** — Checkov has **no Ansible framework at all**, so KICS was the *only* tool
  that could scan the playbooks; it caught the hardcoded passwords, the password-in-URL git creds, and the
  unpinned package version. (Honest caveat: KICS mostly caught the **secrets** here and missed a lot of the SSH /
  SELinux / 0777-permission hardening issues the README claims — so its Ansible depth was shallower than I
  expected. Still, it's the tool that works for this format.)
- **Same resource type, only one tool caught it:** RDS. Checkov flagged the Terraform RDS instances
  (CKV_AWS_* encryption/public-access checks), but it was **KICS** that flagged *"RDS DB Instance Publicly
  Accessible"* on the **Pulumi** RDS — Checkov scored that resource as 0 because it can't parse Pulumi.

---

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure RDS instances require IAM database authentication"
  category: "IAM"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "iam_database_authentication_enabled"
  operator: "equals"
  value: true
```

### Rule fires
`checkov -d .../terraform --external-checks-dir labs/lab6/policies`, then
`jq '... select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure RDS instances require IAM database authentication",
    "resource": "aws_db_instance.unencrypted_db",
    "file": "/database.tf:5",
    "result": "FAILED",
    "severity": "HIGH"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure RDS instances require IAM database authentication",
    "resource": "aws_db_instance.weak_db",
    "file": "/database.tf:40",
    "result": "FAILED",
    "severity": "HIGH"
  }
]
```
Both RDS instances fail because neither sets `iam_database_authentication_enabled` (it defaults to off).

### Why this rule matters
This sample hardcodes DB passwords (`SuperSecretPassword123!`, `password123`) right in the Terraform — the exact
thing IAM database authentication is meant to kill. Turning it on lets apps connect with short-lived IAM tokens
instead of static passwords, which gives you central revocation and CloudTrail logging of every connection
(CIS AWS Foundations / the "no long-lived credentials" least-privilege principle). Checkov ships no built-in for
it, so this is precisely the kind of org-specific gap a custom Policy-as-Code rule is for.
