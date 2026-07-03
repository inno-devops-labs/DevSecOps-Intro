# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | "Ensure IAM policies does not allow permissions management / resource exposure without constraints" |
| CKV_AWS_355 | 4 | "Ensure no IAM policies documents allow \"*\" as a statement's resource for restrictable actions" |
| CKV_AWS_23 | 3 | "Ensure every security group and rule has a description" |
| CKV_AWS_288 | 3 | "Ensure IAM policies does not allow data exfiltration" |
| CKV_AWS_290 | 3 | "Ensure IAM policies does not allow write access without constraints" |


### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the shared IAM policy dropped its `Resource: "*"`
wildcard, the CKV_AWS_355/289/290 findings on every policy would collapse into one fix.")

Four of the top-5 rules — CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, and CKV_AWS_290
(14 of 17 top-5 findings) — all fire on the same file, `iam.tf`, because its IAM
policies use `"*"` as the Resource/Action without constraints; scoping that one
shared policy to specific ARNs and actions would collapse all four rules into a
single module-level fix. The fifth rule, CKV_AWS_23 (missing security group
descriptions), lives in a separate file, `security_groups.tf`, and needs its own
fix — a reminder that not every finding rolls up into one leverage point.

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |


### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample
Checkov's IAM-specific rules (CKV_AWS_289, _355, _288, _290) caught nuanced, resource-relationship issues — like a policy allowing "*" on actions that enable privilege escalation or data exfiltration — that go beyond a simple pattern match. That's the "graph relationships across resources" strength from slide 10: Checkov understands what an IAM policy does, not just how it's written.
- One thing KICS did **better** for the Ansible sample
Checkov has limited-to-no native Ansible support, so KICS was the only tool that could scan deploy.yml, configure.yml, and inventory.ini at all. Its uniform Rego rule set caught the same "Passwords And Secrets" pattern across three different file types (playbook vars, inventory host vars, and global vars) with a single rule family — exactly the "wider language coverage, one rule format" advantage the slide calls out.
- (Optional) An example of a finding only ONE of them caught for the same resource type
The Pulumi RDS resource is a good case: KICS flagged publiclyAccessible: true and storageEncrypted: false as CRITICAL/HIGH findings because it understands the Pulumi YAML schema for aws:rds:Instance. Checkov, by contrast, has much shallower Pulumi coverage than its Terraform ruleset — so the same misconfiguration on an equivalent Terraform-defined RDS instance would likely be caught by both tools, but on Pulumi it relied on KICS alone.
