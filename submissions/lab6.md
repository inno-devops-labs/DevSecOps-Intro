
# Lab 6 -  IaC Security: Checkov, KICS, and a Policy You Write

## Task 1


|framework|passed|failed|
|---|---|---|
|secrets|0|2|
|terraform|49|78|
|total|49|80|


|rule|purpose|count|
|---|---|---|
|CKV_AWS_289|   Ensure IAM policies does not allow permissions management / resource exposure without constraints             |4|
|CKV_AWS_355|   Ensure no IAM policies documents allow “*” as a statement’s resource for restrictable actions             |4|
|CKV_AWS_23|    Ensure every security group and rule has a description             |3|
|CKV_AWS_288|   Ensure IAM policies does not allow data exfiltration             |3|
|CKV_AWS_290|   Ensure IAM policies does not allow write access without constraints             |3|

Id change file `iam.tf`, resource `aws_iam_policy.admin_policy`, clearing 8 findings

The policy is `{ "Action": "*", "Resource": "*" }`, as such:
```
CKV_AWS_62  full "*-*" administrative privileges     
CKV_AWS_288  data exfiltration
CKV_AWS_63  "*" as a statement's actions             
CKV_AWS_289  permissions management
CKV_AWS_286 privilege escalation                      
CKV_AWS_290  write access without constraints
CKV_AWS_287 credentials exposure                      
CKV_AWS_355  "*" as a statement's resource
```
Fixing it once is not the same as fixing it five times because its duplicated to `service_policy`, `s3_full_access` and `privilege_escalation`. You have to fix it there too.

Id sort by exploitability and blast radius from the fields Checkov's resource type and reachability.  A paid severity column is convenient but it is someone else's generic risk model, not your architecture's. It's a good starter but it cant have all context



## Task 2

Ansible:
|Severity|Queries|Findings|
|---|---|---|
|high|3|9|
|low|1|1|
|total|4|10|

Pulumi:
|Severity|Queries|Findings|
|---|---|---|
|critical|1|1|
|high|2|2|
|medium|1|1|
|info|2|2|
|total|6|6|


|Files| Severity | Query |
|---|---|---|
|6|high | Passwords And Secrets - Generic Password|
|2|high | Passwords And Secrets - Password in URL|
|1|high | Passwords And Secrets - Generic Secret|
|1|low | Unpinned Package Version|

KICS, not Checkov - critical "RDS DB Instance Publicly Accessible" on `Pulumi-vulnerable.yaml`. Checkov does not have pulumi framework, so it finds nothing.

Checkov, not KICS - the IAM wildcard. KICS parsed the wildcard policy in `Pulumi-vulnerable.yaml` but has no Pulumi query that opens up and reasons about an embedded IAM policy document the way Checkov's IAM checks do on HCL

I would run both, because they are useful in non-overlapping places. Checkov solves Terraform with ~2,500 policies and IAM-document analysis, KICS solves Pulumi and Ansible, which Checkov either cannot parse or is not being pointed at. For the gap i would normalize both and key by resource and rule intent and delete overlaps.


## Bonus


Policy: `labs/lab6/policies/my-custom-policy.yaml`, `CKV_CUSTOM_1`: Every S3 bucket must carry all three of the `Environment`, `Owner` and `CostCenter` tags.


```yaml
metadata:
  id: "CKV_CUSTOM_1"
  name: "Ensure every S3 bucket carries Environment, Owner and CostCenter tags"
  category: "CONVENTION"
  severity: "MEDIUM"
definition:
  and:
    - cond_type: "attribute"
      resource_types: ["aws_s3_bucket"]
      attribute: "tags.Environment"
      operator: "exists"
    - cond_type: "attribute"
      resource_types: ["aws_s3_bucket"]
      attribute: "tags.Owner"
      operator: "exists"
    - cond_type: "attribute"
      resource_types: ["aws_s3_bucket"]
      attribute: "tags.CostCenter"
      operator: "exists"
```

Return
```json
[
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf"
  },
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf"
  }
]
```

fix:

```hcl
# Public S3 bucket - SECURITY ISSUE #2
resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-bucket-lab6"
  acl    = "public-read"
  
  tags = {
    Name        = "Public Data Bucket"
    Environment = "production"
    Owner       = "platform-team"
    CostCenter  = "CC-1042"
  }
}

# S3 bucket without encryption - SECURITY ISSUE #3
resource "aws_s3_bucket" "unencrypted_data" {
  bucket = "my-unencrypted-bucket-lab6"
  acl    = "private"
  
  tags = {
    Name        = "Public Data Bucket"
    Environment = "production"
    Owner       = "platform-team"
    CostCenter  = "CC-1042"
  }
  # No server_side_encryption_configuration!
  
  versioning {
    enabled = false  # Versioning disabled
  }
}
```

Confirmation
```json
[]
```

The rule is mine and checkov cannot require a `CostCenter` tag because tag keys are an organisational convention, not an AWS security property. In other companies it could be `cost-center` or `BU`, and most have no such requirement at all.