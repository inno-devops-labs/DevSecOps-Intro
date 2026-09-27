# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

Tools: Checkov 3.3.20 (Terraform), KICS latest (Ansible + Pulumi). Target: `labs/lab6/vulnerable-iac/`.

## Task 1

### Passed / failed per framework

| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

(The `secrets` framework runs alongside `terraform`; hence `results_json.json` is a JSON **array**, one object per framework. The two `secrets` hits are `CKV_SECRET_6` in `database.tf` and `CKV_SECRET_2` in `main.tf` — the hardcoded DB password and the hardcoded AWS key.)

### Top five rules by frequency

| Count | Rule | What it checks |
|------:|------|----------------|
| 4 | `CKV_AWS_289` | IAM policy must not allow permissions-management / resource exposure without constraints |
| 4 | `CKV_AWS_355` | IAM policy must not use `"*"` as a statement's `Resource` for restrictable actions |
| 3 | `CKV_AWS_23` | Every security group **and rule** must have a `description` |
| 3 | `CKV_AWS_288` | IAM policy must not allow data exfiltration (wildcard read actions) |
| 3 | `CKV_AWS_290` | IAM policy must not allow write access without constraints |

Four of the top five are IAM-policy checks, all firing on the same wildcard (`Action="*"`, `Resource="*"`) anti-pattern in `iam.tf`.

### The single highest-leverage change
**The wildcard IAM policy pattern in `iam.tf`.** The worst single resource is **`aws_iam_policy.admin_policy` (9 findings on that one resource)**, whose statement is literally `Action = "*"`, `Resource = "*"`. But the same anti-pattern repeats across **four** resources — `admin_policy`, `privilege_escalation`, `s3_full_access`, `service_policy` — which is why `CKV_AWS_289` and `CKV_AWS_355` each fire 4× and `288`/`290` 3×: roughly **14 IAM findings** trace to one pattern. Replacing that pattern with a single **least-privilege policy module** (scoped `Action` list + scoped `Resource` ARNs) clears them everywhere in one change.

> *(For contrast, the single resource with the most findings overall is `aws_db_instance.unencrypted_db` in `database.tf` with **12**, but those are 12 independent attributes — encryption, public access, backups, deletion protection — not one shared fix.)*

**Why fixing it once ≠ fixing it five times:** patching each of the four IAM policies by hand is four separate edits that drift apart and re-introduce the wildcard the next time someone copies a policy. Consolidating them behind one reviewed least-privilege module fixes the class at its source: the rule then can't regress because there's a single definition, and any new resource that uses the module inherits the fix. Frequency, not count, points you at the root.

### The null-severity column
Every `severity` field is null because open-source Checkov gates severities behind the paid tier. In a real backlog I'd sort by **blast radius / exploitability** — internet-reachable + data-exposing findings first (public S3 ACL, `0.0.0.0/0` DB ports, wildcard-admin IAM, hardcoded live credentials) — using rule frequency as the tie-breaker for "one module away from fixed everywhere." That tells me a vendor's `severity` field is convenience, not magic: it's just someone else's opinion of impact pre-computed, and I can reconstruct the same ordering from what the resource exposes and how many places share the flaw. Worth paying for at scale to save triage time; not a prerequisite for triaging well.

## Task 2

### Severity breakdowns (both scans)

**Ansible** — as **queries** (`.queries` array): HIGH 3, LOW 1 (4 distinct queries). As **findings** (terminal total): HIGH 9, LOW 1 — **TOTAL 10**. The gap is because one query ("Generic Password") matches 6 files/lines.

| Severity | Ansible (queries) | Ansible (findings) | Pulumi (queries) | Pulumi (findings) |
|----------|------------------:|-------------------:|-----------------:|------------------:|
| Critical | 0 | 0 | 1 | 1 |
| High | 3 | 9 | 2 | 2 |
| Medium | 0 | 0 | 1 | 1 |
| Low | 1 | 1 | 0 | 0 |
| Info | 0 | 0 | 2 | 2 |
| **Total** | **4 queries** | **10 findings** | **6 queries** | **6 findings** |

For Pulumi the query and finding counts happen to coincide (6 = 6); for Ansible they differ (4 queries vs 10 findings). **The numbers above are labelled queries vs findings explicitly.**

### Top five Ansible queries by files touched

| Files | Severity | Query |
|------:|----------|-------|
| 6 | HIGH | Passwords And Secrets - Generic Password |
| 2 | HIGH | Passwords And Secrets - Password in URL |
| 1 | HIGH | Passwords And Secrets - Generic Secret |
| 1 | LOW | Unpinned Package Version |

(Only four queries fired on the Ansible sample, so the "top five" is those four.)

### One finding in each direction, by parsing ability

- **KICS found, Checkov did not: "RDS DB Instance Publicly Accessible" (CRITICAL) in the Pulumi sample.** Checkov 3.x ships **no Pulumi framework** — it wants rendered Terraform state, not Pulumi Python/YAML — so it cannot parse `pulumi/` at all and reports nothing there. KICS has first-class Pulumi YAML support and a Rego query for public RDS, so it surfaces it. The difference is purely what each tool can *parse*.
- **Checkov covered, KICS (on Pulumi) did not: the wildcard-IAM-policy class** — data exfiltration / write-without-constraints / permissions-management (`CKV_AWS_288/289/290/355`) on the Terraform IAM policies. KICS's Pulumi/Ansible scans surfaced no equivalent fine-grained IAM-statement analysis, because Checkov parses Terraform HCL natively and runs a deep IAM policy-document graph against it, whereas KICS's query set for the Pulumi representation doesn't decompose the policy statement the same way. Each tool is blind exactly where its parser/query-catalog stops.

### Pipeline decision and the gap
I'd run **both, each on the framework it actually parses**: Checkov as the Terraform gate (native HCL + ~2,500 policies + a deep IAM graph), and KICS for Ansible and Pulumi, which Checkov silently cannot read. A single scanner would give false confidence — pointing Checkov at Pulumi produces zero findings that look like a pass. For the gap between them, I'd normalise both outputs (Checkov JSON + KICS SARIF/JSON) into one aggregator — this is exactly what **Lab 10 does in DefectDojo** — dedupe overlapping findings, and treat every "found by only one tool" result as a coverage question, not noise: it usually means the other tool couldn't parse that format, not that the risk isn't there.

## Bonus

### The policy in one sentence
Every `aws_s3_bucket` must carry `Owner`, `Environment` and `CostCenter` tags — our org's mandatory-tagging standard for spend attribution and incident-response ownership.

Policy file `labs/lab6/policies/my-custom-policy.yaml`:
```yaml
metadata:
  id: "CKV_CUSTOM_1"
  name: "S3 buckets must carry Owner, Environment and CostCenter tags (org tagging standard)"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"
definition:
  and:
    - cond_type: "attribute"
      resource_types: ["aws_s3_bucket"]
      attribute: "tags.Owner"
      operator: "exists"
    - cond_type: "attribute"
      resource_types: ["aws_s3_bucket"]
      attribute: "tags.Environment"
      operator: "exists"
    - cond_type: "attribute"
      resource_types: ["aws_s3_bucket"]
      attribute: "tags.CostCenter"
      operator: "exists"
```

### It firing
```json
[
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_s3_bucket.public_data",      "file_path": "/main.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_s3_bucket.unencrypted_data", "file_path": "/main.tf" }
]
```

### The passing change (confirmed)
Add the three tags to the bucket, e.g. on `aws_s3_bucket.public_data` in `main.tf`:
```hcl
  tags = {
    Name        = "Public Data Bucket"
    Owner       = "team-appsec"
    Environment = "prod"
    CostCenter  = "CC-1042"
  }
```
Re-running Checkov with `--external-checks-dir labs/lab6/policies` on a copy with this change: `CKV_CUSTOM_1` moves to **passed_checks** for `aws_s3_bucket.public_data`, while the untouched `aws_s3_bucket.unencrypted_data` still fails — confirming the rule keys on exactly those three tags.

### Why this rule is mine, not Checkov's
Checkov can't ship "require `Owner`/`Environment`/`CostCenter`" because those keys and their meaning are specific to *our* FinOps and on-call model — a generic scanner has no way to know our cost-allocation taxonomy or that untagged buckets are what broke our last cost-attribution audit. It encodes an **internal standard** (mandatory ownership tags after an audit finding that orphaned, untagged buckets couldn't be traced to a team during an incident), which is exactly the class of rule policy-as-code exists to capture: organisation-specific, not universal cloud hygiene.
