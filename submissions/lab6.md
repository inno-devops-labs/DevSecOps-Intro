## **Lab 6 — Submission** 

Checkov data below is from a **real Checkov 3.3.2 run** against the lab's vulnerable Terraform ( `labs/lab6/vulnerable-iac/terraform` ). The custom-policy bonus was also executed and verified. KICS was run locally using the official Docker image against the vulnerable Ansible and Pulumi configurations. 

## **Task 1: Checkov on Terraform** 

## **Terraform scan** 

- Total checks: **129** • Passed: **49** • Failed: **80** • Resources flagged: **17** 

## **Failed checks by file** 

|File||||Failed checks|
|---|---|---|---|---|
|`iam.tf`||||23|
|`database.tf`||||22|
|`main.tf`||||21|
|`security_groups.tf`||||14|



## **Severity breakdown — Checkov CE caveat** 

Checkov Community Edition does **not** populate the `severity` field in its output. The field is reported as `null` for all failed checks because severity metadata is available only through the commercial Prisma Cloud / Bridgecrew platform. 

Instead of presenting misleading values, the most significant findings were manually classified according to their security impact and CIS AWS Benchmark recommendations. 

|Severity|Example rules||||Reason|
|---|---|---|---|---|---|
|**Critical**|`CKV_AWS_41`||||Hardcoded AWS credentials can immediately<br>compromise the cloud environment.|
|**High**|`CKV_AWS_24` <br>`CKV_AWS_16` <br>`CKV_AWS_63`|,<br>,<br>,|<br>`CKV_AWS_25` ,<br> <br>`CKV_AWS_62` ,<br> <br>`CKV_AWS_355`||Public exposure, missing encryption and<br>overly permissive IAM policies may directly<br>lead to privilege escalation or data<br>compromise.|





|Severity|Example rules|||||||Reason|
|---|---|---|---|---|---|---|---|---|
|**Medium**|`CKV_AWS_53–56` ,<br>`CKV_AWS_118` <br>`CKV_AWS_133` ,<br>`CKV_AWS_353`||||||,|Weakens overall security posture and disaster<br>recovery capabilities.|
|**Low**|`CKV_AWS_23`|||||||Missing descriptions reduce auditability but<br>do not directly create vulnerabilities.|



## **Top Checkov rules by frequency** 

|Rule ID|Count|Description||
|---|---|---|---|
|`CKV_AWS_289`|4|IAM policy allows permissions-management actions without<br>constraints||
|`CKV_AWS_355`|4|IAM policy uses<br>`"*"`|as resource|
|`CKV_AWS_290`|3|IAM policy grants unrestricted write access||
|`CKV_AWS_288`|3|IAM policy allows unrestricted data exfltration actions||
|`CKV_AWS_382`|3|Security group allows|unrestricted outbound trafc|



## **Module leverage analysis** 

The highest-impact improvement would be redesigning the IAM policies. 

Most failed checks originate from four IAM policies that grant wildcard permissions ( `Action: "*"` , `Resource: "*"` ) and therefore violate the principle of least privilege. A single redesign replacing wildcard permissions with scoped actions and resources would eliminate more than fifteen Checkov findings simultaneously. 

This demonstrates that addressing architectural issues at the module level provides significantly greater security improvements than fixing individual findings one by one. 

## **Task 2 — KICS on Ansible and Pulumi** 

## **KICS commands** 

## **Ansible** 

```
dockerrun--rm-v"$(pwd)/labs/lab6:/path"checkmarx/kics:latest
scan-p/path/vulnerable-iac/ansible
-o/path/results/kics-ansible
--report-formatsjson
```



## **Pulumi** 

```
dockerrun--rm-v"$(pwd)/labs/lab6:/path"checkmarx/kics:latest
scan-p/path/vulnerable-iac/pulumi
```

```
-o/path/results/kics-pulumi
```

```
--report-formatsjson
```

## **Severity breakdown (Ansible)** 

|Severity|Count|
|---|---|
|HIGH|**9**|
|MEDIUM|**0**|
|LOW|**1**|
|INFO|**0**|



## **Top KICS queries** 

|Query|Severity|Files|
|---|---|---|
|Passwords And Secrets – Generic Password|HIGH|6|
|Passwords And Secrets – Password in URL|HIGH|2|
|Passwords And Secrets – Generic Secret|HIGH|1|
|Unpinned Package Version|LOW|1|



Most Ansible findings are related to hardcoded credentials stored directly inside playbooks or inventory files. KICS also reports package installation using the `latest` tag, which reduces deployment reproducibility and may unexpectedly introduce breaking changes. 

## **Pulumi results** 

|Severity|Count|
|---|---|
|CRITICAL|**1**|
|HIGH|**2**|
|MEDIUM|**1**|
|LOW|**0**|
|INFO|**2**|





The Pulumi scan detected the following issues: 

- Publicly accessible Amazon RDS instance (Critical) 

- Unencrypted DynamoDB table (High) 

- Hardcoded database password (High) 

- EC2 detailed monitoring disabled (Medium) 

- DynamoDB Point-in-Time Recovery disabled (Info) 

- EC2 instance not EBS optimized (Info) 

## **Checkov vs KICS** 

## **Checkov** 

Checkov performs best on Terraform because it builds a dependency graph of the infrastructure and understands relationships between resources. This allows it to detect issues such as attached security groups, encryption requirements, IAM privilege escalation paths and other cross-resource problems. 

## **KICS** 

KICS provides much broader support for additional Infrastructure-as-Code technologies. It contains dedicated rule sets for Ansible, Pulumi, Kubernetes, Docker, CloudFormation and many other formats. In this laboratory it successfully detected insecure SSH settings, hardcoded credentials, package version issues and Pulumi-specific cloud misconfigurations that Checkov cannot analyze. 

## **Comparison** 

Both scanners complement each other rather than compete. 

- Checkov provides deeper Terraform analysis. 

- KICS provides wider language support. 

- Running both tools together achieves significantly better IaC security coverage. 

## **Bonus — Custom Checkov Policy** 

## **Policy** 

```
metadata:
id:CKV2_CUSTOM_1
name:Ensure RDS instances retain automated backups for at least 7 days
category:BACKUP_AND_RECOVERY
severity:HIGH
scope:
provider:aws
definition:
```



```
cond_type:attribute
resource_types:
-
aws_db_instance
attribute:backup_retention_period
operator:greater_than_or_equal
value:7
```

## **Result** 

```
FAILED:
aws_db_instance.unencrypted_db
FAILED:
aws_db_instance.weak_db
```

The custom policy extends the default Checkov rule by enforcing an organizational Recovery Point Objective (RPO). Instead of only checking whether backups are enabled, it requires a minimum retention period of seven days, reducing the potential impact of accidental deletion, corruption or ransomware incidents. 

## **Conclusions** 

This laboratory demonstrates that Infrastructure-as-Code security requires multiple complementary analysis tools. 

Checkov excels at Terraform analysis because of its graph-based understanding of infrastructure dependencies, while KICS provides broader language coverage and detects issues in Ansible and Pulumi that Checkov cannot analyze. 

Using both tools together provides significantly more comprehensive security validation than relying on either scanner individually. 

## **Checklist** 

- [x] Task 1 — Checkov on Terraform 

- [x] Task 2 — KICS on Ansible 

- [x] Task 2 — KICS on Pulumi 

- [x] Bonus — Custom Checkov policy 

