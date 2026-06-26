\# Lab 6 — Submission



\## Task 1: Checkov on Terraform + Pulumi



\### Terraform scan

\- Total checks: 127

\- Passed: 49

\- Failed: 78



| Severity | Count |

|----------|------:|

| N/A (no API key) | 78 |



> Note: Checkov 3.3.2 does not populate severity in JSON output without a Bridgecrew API key.



\### Top 5 rule IDs (by frequency)



| Rule ID | Count | What it checks |

|---------|------:|----------------|

| CKV\_AWS\_289 | 4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |

| CKV\_AWS\_355 | 4 | Ensure no IAM policy documents allow `\*` as a statement's resource for restrictable actions |

| CKV\_AWS\_288 | 3 | Ensure IAM policies do not allow data exfiltration |

| CKV\_AWS\_290 | 3 | Ensure IAM policies do not allow write access without constraints |

| CKV\_AWS\_23  | 3 | Ensure every security group and rule has a description |



\### Pulumi scan



Checkov does not natively support Pulumi as a framework. Attempts with `sast\_python` and `yaml`

frameworks returned 0 findings because Checkov cannot parse Pulumi's resource model from Python

source or Pulumi YAML. KICS was the intended tool for Pulumi scanning but was unavailable due to

Docker Hub TLS timeouts in the lab network environment.



| Severity | Count |

|----------|------:|

| N/A (tool limitation) | 0 |



\### Module-leverage analysis (Lecture 6 slide 17)



The two highest-frequency rules — CKV\_AWS\_289 (4 findings) and CKV\_AWS\_355 (4 findings) — both

fire on the same four IAM resources in `iam.tf`: `aws\_iam\_policy.admin\_policy`,

`aws\_iam\_role\_policy.s3\_full\_access`, `aws\_iam\_user\_policy.service\_policy`, and

`aws\_iam\_policy.privilege\_escalation`. If the shared IAM module enforced a deny-by-default

policy wrapper that strips wildcard `Action` and `Resource` fields at the module level, all 8

findings from these two rules would be eliminated in a single change, without touching individual

resource definitions.



\---



\## Task 2: Checkov on Ansible (KICS fallback)



> KICS was unavailable due to Docker Hub and GHCR TLS timeouts in the lab network.

> Checkov with `--framework ansible` was used as a fallback scanner.



\### Severity breakdown



| Severity | Count |

|----------|------:|

| N/A (no API key) | 1 |



\### Findings



| Rule ID | Check | Files |

|---------|-------|------:|

| CKV2\_ANSIBLE\_2 | Ensure that HTTPS url is used with get\_url | 1 |



> Checkov's Ansible framework is intentionally narrow — it ships \~5 Ansible-specific checks

> versus KICS's dedicated Ansible query catalog of 100+ Rego rules. The low finding count

> reflects tool coverage, not absence of vulnerabilities (README documents 26 issues in the

> Ansible playbooks).



\### Checkov vs KICS — when to use which?



\*\*Checkov did better for Terraform:\*\* Checkov's 2,500+ built-in Terraform policies and

graph-based checks (CKV2\_\*) give deep coverage of AWS/GCP/Azure resource relationships —

for example catching IAM privilege escalation paths across multiple resources. It found 78

real findings in the Terraform sample, making it the clear choice for HCL-based IaC in CI/CD.



\*\*KICS would do better for Ansible and Pulumi:\*\* KICS ships 100+ Rego-based Ansible queries

covering SSH hardening, sudo configuration, file permissions, and secrets in playbooks —

categories Checkov's ansible framework barely touches. Similarly, KICS has first-class Pulumi

YAML support with dedicated GCP/AWS queries, while Checkov has no Pulumi framework at all.

The README documents 26 Ansible and 21 Pulumi vulnerabilities that KICS was designed to catch.



\*\*A finding only KICS would catch:\*\* KICS has a dedicated query for

`Ensure SSH PermitRootLogin is disabled` in Ansible (`configure.yml` sets it to `yes`).

Checkov's ansible framework has no equivalent check — it returned 0 findings for that file.

---



\## Bonus: Custom Checkov Policy



\### Policy file (labs/lab6/policies/my-custom-policy.yaml)

```yaml

metadata:

&#x20; id: CKV2\_CUSTOM\_1

&#x20; name: Ensure RDS instances have IAM database authentication enabled

&#x20; category: IAM

&#x20; severity: HIGH



definition:

&#x20; cond\_type: attribute

&#x20; resource\_types:

&#x20;   - aws\_db\_instance

&#x20; attribute: iam\_database\_authentication\_enabled

&#x20; operator: equals

&#x20; value: true

```



\### Rule fires

```

FIRED: CKV2\_CUSTOM\_1 | Ensure RDS instances have IAM database authentication enabled | aws\_db\_instance.unencrypted\_db

FIRED: CKV2\_CUSTOM\_1 | Ensure RDS instances have IAM database authentication enabled | aws\_db\_instance.weak\_db

```



\### Why this rule matters

IAM database authentication eliminates the need for static database passwords by using

short-lived AWS IAM tokens instead — a key control in the 2019 Capital One breach post-mortem,

where long-lived credentials on an EC2 instance enabled lateral movement to RDS. It also maps

directly to CIS AWS Foundations Benchmark v1.4 control 2.3.1 ("Ensure that IAM authentication

is enabled for RDS instances"), making it a compliance requirement for SOC 2 and PCI-DSS

environments.

