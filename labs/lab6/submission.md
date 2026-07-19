\# Lab 6 - Submission



\## Task 1: Checkov on Terraform



\### Terraform Scan



\* Total checks: 129

\* Passed: 49

\* Failed: 80



\### Top 5 Rule IDs



| Rule ID     | Count |

| ----------- | ----: |

| CKV\_AWS\_289 |     4 |

| CKV\_AWS\_355 |     4 |

| CKV\_AWS\_23  |     3 |

| CKV\_AWS\_288 |     3 |

| CKV\_AWS\_290 |     3 |



\### Severity Breakdown



Checkov JSON output did not provide severity metadata for the detected findings. All 80 failed checks were reported without severity classification.



\### Module-Leverage Analysis



The highest-leverage remediation would be redesigning the IAM policy definitions. Several of the most frequently triggered findings are IAM-related (CKV\_AWS\_289, CKV\_AWS\_355, CKV\_AWS\_288, CKV\_AWS\_290). Replacing wildcard permissions and applying least-privilege principles would eliminate multiple findings simultaneously.



---



\## Task 2: KICS on Ansible and Pulumi



\### Ansible Results



| Severity | Count |

| -------- | ----: |

| CRITICAL |     0 |

| HIGH     |     9 |

| MEDIUM   |     0 |

| LOW      |     1 |

| INFO     |     0 |

| Total    |    10 |



Top findings:



\* Passwords And Secrets - Generic Password (6)

\* Passwords And Secrets - Password in URL (2)

\* Passwords And Secrets - Generic Secret (1)

\* Unpinned Package Version (1)



\### Pulumi Results



| Severity | Count |

| -------- | ----: |

| CRITICAL |     1 |

| HIGH     |     2 |

| MEDIUM   |     1 |

| LOW      |     0 |

| INFO     |     2 |

| Total    |     6 |



Top findings:



\* RDS DB Instance Publicly Accessible (CRITICAL)

\* Passwords And Secrets - Generic Password (HIGH)

\* DynamoDB Table Not Encrypted (HIGH)

\* EC2 Instance Monitoring Disabled (MEDIUM)

\* EC2 Not EBS Optimized (INFO)

\* DynamoDB Table Point In Time Recovery Disabled (INFO)



\### Checkov vs KICS



\*\*Checkov strengths\*\*



\* Deep Terraform support.

\* Large AWS rule library.

\* Strong IAM and S3 security coverage.

\* Detects infrastructure misconfigurations and secret exposure.



\*\*KICS strengths\*\*



\* Multi-platform IaC support.

\* Excellent secret detection.

\* Consistent scanning across Ansible and Pulumi.

\* Clear severity reporting.



\*\*Example unique findings\*\*



\* Checkov identified numerous IAM privilege-escalation and overly permissive policy issues.

\* KICS identified hardcoded credentials, passwords in URLs, and exposed secrets within Ansible inventory and configuration files.



---



\## Bonus: Custom Checkov Policy



\### Custom Policy



ID: CKV2\_CUSTOM\_1



Name: Ensure S3 bucket lifecycle configuration exists



Purpose: Require lifecycle configuration for all S3 buckets.



\### Results



The custom policy successfully detected two non-compliant S3 buckets:



\* aws\_s3\_bucket.public\_data

\* aws\_s3\_bucket.unencrypted\_data



Both resources failed because no lifecycle configuration was defined.



\### Security Benefit



Lifecycle rules help enforce retention policies, reduce long-term exposure of sensitive data, and automatically manage object aging and deletion.



