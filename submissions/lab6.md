# Lab 6 — Submission

## Task 1

### Checkov results by framework

| Framework | Passed | Failed |
| --------- | ------ | ------ |
| terraform | 49     | 78     |
| secrets   | 0      | 2      |

### Top 5 rules by frequency
| Count | Rule ID     | What it checks                                                                                                 |
| ----: | ----------- | -------------------------------------------------------------------------------------------------------------- |
|     4 | CKV_AWS_289 | IAM policies do not grant permissions-management or resource-exposure actions without appropriate restrictions |
|     4 | CKV_AWS_355 | IAM policies avoid using `*` as the resource for actions that can be restricted to specific resources          |
|     3 | CKV_AWS_23  | Security groups and their rules include descriptions                                                           |
|     3 | CKV_AWS_288 | IAM policies do not grant permissions that could enable data exfiltration                                      |
|     3 | CKV_AWS_290 | IAM policies do not grant unrestricted write permissions without appropriate constraints                       |


### Highest-leverage fix

**File:** `iam.tf` — resource `aws_iam_policy.admin_policy`

Addressing this single resource removes **9 findings**: CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, CKV_AWS_290, CKV_AWS_286, CKV_AWS_287, CKV_AWS_62, CKV_AWS_63, and CKV2_AWS_40. These checks are all triggered by the combination of `"Action": "*"` and `"Resource": "*"` in the same policy document.

The reason one change can resolve several findings at once is that these rules represent different security checks against the same underlying IAM policy. They are all evaluating the same wildcard configuration from different perspectives. Removing the wildcard permissions from `admin_policy` therefore addresses all of those checks within the same resource, whereas fixing each rule separately would repeatedly modify the same part of the policy.

### Sorting without severities

Because the open-source version of Checkov reports `severity` as null for every finding, I would prioritise the backlog using both finding frequency and resource blast radius. The latter means considering how many resources receive the policy and what those resources are permitted to do.

In a real organisation, this is similar to what vendor-provided severity ratings attempt to provide: a predefined priority based on an assessment of potential impact, such as a CVSS score. However, vendor severities are necessarily generic because they describe the typical or worst-case impact of a check rather than the exact environment where the finding occurs.

For example, a `Critical` finding on an S3 bucket containing only public marketing material may require less immediate attention than a `Medium` finding affecting an IAM policy used by a production deployment role. Looking at frequency and blast radius therefore provides a more environment-specific way to determine remediation priority than relying only on a generic severity label.

---

## Task 2

### KICS severity breakdown

These values represent **queries** (distinct rules), rather than individual findings for each affected file.

**kics-ansible:**

| Severity | Queries |
| -------- | ------- |
| HIGH     | 3       |
| LOW      | 1       |

**kics-pulumi:**

| Severity | Queries |
| -------- | ------- |
| CRITICAL | 1       |
| HIGH     | 2       |
| MEDIUM   | 1       |
| INFO     | 2       |

The terminal totals for individual findings are 10 for Ansible and 6 for Pulumi.

### Top 5 Ansible queries by files touched

| Files | Query                                    | Severity |
| ----- | ---------------------------------------- | -------- |
| 6     | Passwords And Secrets — Generic Password | HIGH     |
| 2     | Passwords And Secrets — Password in URL  | HIGH     |
| 1     | Passwords And Secrets — Generic Secret   | HIGH     |
| 1     | Unpinned Package Version                 | LOW      |

There are only 4 distinct queries in the Ansible scan.

### What one tool found that the other didn't

**KICS found, Checkov didn't: `RDS DB Instance Publicly Accessible` in Pulumi**

Checkov 3.x does not provide a Pulumi framework. It works with rendered Terraform state rather than directly analysing Python or YAML Pulumi manifests. KICS, on the other hand, can parse `Pulumi-vulnerable.yaml` as a structured document and apply its own queries to it. As a result, the `publicly_accessible: true` configuration in the Pulumi resource can be detected by KICS but is not visible to Checkov in this scan.

**Checkov found, KICS didn't: IAM privilege escalation policies in Terraform**

For this lab, KICS was run only against Ansible and Pulumi. Even if the Terraform files were included, KICS does not provide the same depth of IAM analysis as Checkov. Checks such as CKV_AWS_286 for privilege escalation and CKV_AWS_289 for unrestricted permissions management require understanding the semantic meaning of IAM action combinations, which Checkov handles using its dedicated IAM analysis.

### Pipeline decision and gap

I would use both tools in CI, but apply them to the formats where they provide the most useful coverage: Checkov on every Terraform pull request and KICS for Ansible and Pulumi. Checkov is also fast enough for Terraform checks without the additional Docker overhead.

The main limitation is that neither tool provides equally comprehensive coverage across all three formats. Checkov does not analyse Pulumi semantics directly, while KICS does not provide the same depth of IAM analysis. The practical approach is therefore to keep both tools and treat findings from either one as actionable, while recognising that certain configuration issues may only be detected by one tool.

Over time, the integration gap can be reduced by pinning both tools to fixed versions in CI and sending their results to a shared findings store, which is the approach demonstrated later in Lab 10.

---

## Bonus: Custom Checkov Policy

### Policy file

File: `labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure RDS instances use IAM database authentication"
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

**Plain-English rule:** Every RDS database instance must have IAM database authentication enabled.

### Rule fires

Output of:

```bash
jq '
  .[0].results.failed_checks[]
  | select(.check_id | startswith("CKV2_CUSTOM_"))
  | {
      check_id,
      check_name,
      severity,
      file_path,
      resource
    }
' labs/lab6/results/checkov-custom/results_json.json
```

Result:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances use IAM database authentication",
  "severity": "HIGH",
  "file_path": "/database.tf",
  "resource": "aws_db_instance.unencrypted_db"
}

{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances use IAM database authentication",
  "severity": "HIGH",
  "file_path": "/database.tf",
  "resource": "aws_db_instance.weak_db"
}
```

The custom policy therefore caught **2** Terraform RDS resources.

### Terraform change and confirmation

In `database.tf`, I enabled IAM database authentication for both affected RDS instances by adding:

```hcl
iam_database_authentication_enabled = true
```

to `aws_db_instance.unencrypted_db` and `aws_db_instance.weak_db`.

After rerunning Checkov with the custom policy, `CKV2_CUSTOM_1` no longer appeared in `failed_checks`, confirming that both resources now pass the custom check.


### Why this is a custom rule

This rule represents an **internal security standard for this project**: all RDS instances should use IAM database authentication instead of relying on long-lived database passwords. Unlike a generic vulnerability check, this policy enforces a project-specific authentication requirement that we want to apply consistently through CI.