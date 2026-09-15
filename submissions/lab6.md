# Lab 6 — Submission

## Task 1

### Checkov results by framework

| Framework | Passed | Failed |
|-----------|--------|--------|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rules by frequency

| Count | Rule ID | What it checks |
|-------|---------|----------------|
| 4 | CKV_AWS_289 | IAM policy does not allow permissions management or resource exposure without constraints |
| 4 | CKV_AWS_355 | IAM policy document does not use `*` as a resource for restrictable actions |
| 3 | CKV_AWS_23 | Every security group and rule has a description |
| 3 | CKV_AWS_288 | IAM policy does not allow data exfiltration |
| 3 | CKV_AWS_290 | IAM policy does not allow write access without constraints |

### Highest-leverage fix

**File:** `iam.tf` — resource `aws_iam_policy.admin_policy`

Fixing this one resource clears **9 findings** — CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, CKV_AWS_290, CKV_AWS_286, CKV_AWS_287, CKV_AWS_62, CKV_AWS_63, and CKV2_AWS_40. All of them fire because the policy document uses `"Action": "*"` and `"Resource": "*"` together. The reason fixing it once is not the same as fixing it five times is that the five rules are five different perspectives on the same underlying policy document — they're all reading the same string. Removing the wildcard from `admin_policy` satisfies all five checks in that single resource at the same time; fixing each rule individually in separate PRs would just touch the same line five times.

### Sorting without severities

Since open-source Checkov leaves `severity` null on every finding, I'd sort the backlog by frequency (which rule fires most) combined with the blast radius of the resource — how many other resources inherit this policy, and what those resources can do. In a real organisation that's essentially what buying severities from a vendor gives you: a pre-computed priority based on their read of the CVSS score and the typical impact. The practical implication is that vendor severities are generic — they reflect the worst-case scenario for that check type, not your actual environment. A `Critical` on an S3 bucket that holds only public marketing assets is less urgent than a `Medium` on an IAM policy attached to your production deployment role. Frequency and blast radius get you closer to real priority than a vendor label does.

---

## Task 2

### KICS severity breakdown

These numbers are **queries** (distinct rules), not individual file-level findings.

**kics-ansible:**

| Severity | Queries |
|----------|---------|
| HIGH | 3 |
| LOW | 1 |

**kics-pulumi:**

| Severity | Queries |
|----------|---------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

Terminal totals (individual findings): Ansible 10, Pulumi 6.

### Top 5 Ansible queries by files touched

| Files | Query | Severity |
|-------|-------|----------|
| 6 | Passwords And Secrets — Generic Password | HIGH |
| 2 | Passwords And Secrets — Password in URL | HIGH |
| 1 | Passwords And Secrets — Generic Secret | HIGH |
| 1 | Unpinned Package Version | LOW |

(Only 4 distinct queries total in the Ansible scan.)

### What one tool found that the other didn't

**KICS found, Checkov didn't: `RDS DB Instance Publicly Accessible` in Pulumi**  
Checkov 3.x has no Pulumi framework — it wants rendered Terraform state, not Python or YAML manifests. KICS parses the `Pulumi-vulnerable.yaml` directly as a structured document and maps it to its own query set. The same `publicly_accessible: true` setting in Pulumi is invisible to Checkov entirely.

**Checkov found, KICS didn't: IAM privilege escalation policies in Terraform**  
KICS scanned only Ansible and Pulumi in this lab. Even if pointed at the Terraform files, KICS does not have rules at the depth of Checkov's IAM analysis — checks like CKV_AWS_286 (privilege escalation) or CKV_AWS_289 (permissions management without constraints) require understanding the semantic meaning of IAM action sets, which Checkov handles through a dedicated IAM module. KICS' IAM coverage is shallower.

### Pipeline decision and gap

I'd run both in CI but gate on different things: Checkov on every Terraform PR (it's fast, zero Docker overhead), and KICS on Ansible and Pulumi where Checkov can't reach. The gap is that neither tool covers all three formats equally — Checkov misses Pulumi semantics and KICS misses deep IAM analysis. The practical answer is to accept the overlap and treat findings from either tool as a blocker, while acknowledging that the gap means some classes of misconfiguration will only be caught by one of the two. Long-term, the gap shrinks by pinning both tools to the same version in CI and running their outputs into a common findings store (Lab 10 does exactly this).

---

## Bonus

### Custom policy

**File:** `labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  id: "CKV_CUSTOM_1"
  name: "Ensure RDS instance is not publicly accessible"
  category: "NETWORKING"
  severity: "HIGH"

definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "publicly_accessible"
  operator: "is_false"
```

In plain English: every `aws_db_instance` must have `publicly_accessible` set to `false`.

### JSON showing it firing

```json
[
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf"
  }
]
```

`aws_db_instance.weak_db` passes (it has `publicly_accessible = false`). `aws_db_instance.unencrypted_db` fails (`publicly_accessible = true`).

### Fix and confirmation

Change `publicly_accessible = true` to `publicly_accessible = false` in `database.tf` for `unencrypted_db`. After that change, the check moves from `failed_checks` to `passed_checks` — confirmed by the `weak_db` entry already passing with the same `false` value.

### Why this rule is mine

Checkov already ships CKV_AWS_17 (RDS instance is not publicly accessible) as a built-in check. The reason to write it as a custom policy is to embed it in an organisation's own policy library with a custom ID that maps to an internal control number — so a finding like `CKV_CUSTOM_1` links directly to an audit finding or a security standard reference that the team owns, rather than to a generic vendor ID. In a real team this would come from a CIS benchmark finding or a pen test report that called out an RDS instance exposed to the internet: the custom policy encodes that lesson as a permanent guardrail tied to the incident rather than relying on everyone remembering to enable the right vendor check.
