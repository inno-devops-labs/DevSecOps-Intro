# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

> **Note on lab issues:**
> 1. Checkov 3.x outputs JSON arrays, not objects. The provided `jq` commands fail with `Cannot index array with string "results"`. Fixed by using `jq '[.[] | ...]'`.
> 2. The Checkov open-source version does not populate the `severity` field (returns `null`), so the Severity table cannot be filled.
> 3. Task 1 lacks Pulumi commands, and the `pulumi-state-rendered.json` fallback file is missing from the repository, making the Pulumi scan impossible here.

### Terraform scan
- Total checks: 129
- Passed: 49
- Failed: 80

| Severity | Count |
|----------|------:|
| Critical | N/A (null) |
| High | N/A (null) |
| Medium | N/A (null) |
| Low | N/A (null) |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |

### Pulumi scan
| Severity | Count |
|----------|------:|
| N/A | N/A |

*(Pulumi Checkov scan skipped due to missing `pulumi-state-rendered.json` and lack of native Pulumi source support in Checkov 3.x).*

### Module-leverage analysis (Lecture 6 slide 17)
Looking at the top-5 Terraform rules, 4 of them (CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, CKV_AWS_290) are related to overly permissive IAM policies. If the base IAM policy module restricted the use of wildcards (`*`) for resources and actions by default, this single fix would immediately resolve 14 vulnerabilities.


## Task 2: KICS on Ansible

> **Note on lab issues:**
> The `jq` commands provided in the instructions attempt to read from `labs/lab6/results/kics/results.json`. However, the Docker commands output the results to `results/kics-ansible/` and `results/kics-pulumi/`. The `jq` path had to be corrected to point to `kics-ansible/results.json` to work.

### Severity breakdown (Ansible)
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
*(Note: This counts unique triggered rules based on the lab's `jq` query. The total number of affected files/findings is 9 High and 1 Low).*

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |


### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **One thing Checkov did better for the Terraform sample:** Checkov has deep, native understanding of AWS architectures and provides specialized, graph-based rules (like cross-resource checks for IAM), making it incredibly powerful for cloud-native IaC like Terraform.
- **One thing KICS did better for the Ansible sample:** KICS natively parsed Ansible playbooks and Pulumi YAML configurations without needing state translation, effectively finding hardcoded secrets and unpinned packages in configuration management tools where Checkov struggles or requires workarounds.

---

## Bonus: Custom Checkov Policy

### Policy file
```yaml
metadata:
  name: "Ensure RDS instances have deletion protection enabled"
  id: "CKV2_CUSTOM_1"
  category: "BACKUP_AND_RECOVERY"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "deletion_protection"
  operator: "equals"
  value: true
```

### Rule fires
Output of `jq '.[] | .results.failed_checks[]? | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
{
  "check_id": "CKV2_CUSTOM_1",
  "bc_check_id": null,
  "check_name": "Ensure RDS instances have deletion protection enabled",
  "check_result": {
    "result": "FAILED",
    "entity": {
      "aws_db_instance": {
        "weak_db": { ... }
      }
    }
  },
  "resource": "aws_db_instance.weak_db",
  "severity": "HIGH"
}
```
*(Note: JSON output truncated for readability. It successfully fired on both `aws_db_instance.unencrypted_db` and `aws_db_instance.weak_db`).*

### Why this rule matters
This custom policy prevents accidental or malicious deletion of production databases by enforcing AWS RDS deletion protection. A real-world example of this risk was the GitLab database outage in 2017, where an admin accidentally deleted critical database files; having strict deletion protection controls enforced at the IaC level adds a necessary layer of defense against irrecoverable data loss and helps comply with standard availability frameworks like SOC2.

