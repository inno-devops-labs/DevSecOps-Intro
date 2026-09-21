# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

Tooling: Checkov 3.3.10, KICS `checkmarx/kics:latest`, jq 1.6, on macOS 15.3.1 (arm64).
Target: `labs/lab6/vulnerable-iac/` (broken-on-purpose Terraform, Pulumi and Ansible). Analysed, not fixed.

## Task 1

### Passed / failed per framework

Checkov ran two frameworks together (`terraform` and `secrets`), so `results_json.json` is an array —
one object per framework. Indexing it as `.results.failed_checks` errors with "Cannot index array with
string"; the working filter is `.[].results.failed_checks[]?`.

```console
$ jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' results_json.json
```

| Framework | Passed | Failed |
|---|---:|---:|
| terraform | 35 | 57 |
| secrets | 0 | 2 |
| **Total** | **35** | **59** |

The two `secrets` findings are the hardcoded AWS secret key in `main.tf` (`CKV_SECRET_2`) and the RDS
password in `database.tf` (`CKV_SECRET_6`).

### Top five rules by frequency

Open-source Checkov leaves `severity` null on every finding (severities are a paid feature), so
frequency is the triage signal. Descriptions are Checkov's own `check_name`, not guessed:

| Count | Rule | What it checks |
|---:|---|---|
| 4 | `CKV_AWS_289` | IAM policy does not allow permissions-management / resource exposure without constraints |
| 4 | `CKV_AWS_355` | No IAM policy document allows `"*"` as a statement's **resource** for restrictable actions |
| 3 | `CKV_AWS_23` | Every security group and rule has a description |
| 3 | `CKV_AWS_288` | IAM policy does not allow data exfiltration |
| 3 | `CKV_AWS_290` | IAM policy does not allow write access without constraints |

Four of the top five are IAM-policy-document rules, all firing on the same handful of wildcard policies.

### The single highest-leverage change

**File `iam.tf`, resource `aws_iam_policy.admin_policy` — clears 8 findings at once.**

That one policy is `{ "Action": "*", "Resource": "*" }`, and it trips eight distinct IAM checks
simultaneously:

```
CKV_AWS_62  full "*-*" administrative privileges     CKV_AWS_288  data exfiltration
CKV_AWS_63  "*" as a statement's actions             CKV_AWS_289  permissions management
CKV_AWS_286 privilege escalation                      CKV_AWS_290  write access without constraints
CKV_AWS_287 credentials exposure                      CKV_AWS_355  "*" as a statement's resource
```

Scoping the action and resource down to the specific service actions and ARNs the workload actually
needs makes all eight pass in a single edit. It is the most findings-per-edit available: the next
resource, `aws_db_instance.unencrypted_db`, carries *more* raw findings (10) but each is an independent
attribute — encryption, backups, public access, deletion protection, monitoring, logging — so "fixing
it" is ten separate changes, not one.

**Why fixing it once is not the same as fixing it five times.** The same `Action:"*" Resource:"*"`
pattern is copy-pasted across four separate policy resources — `admin_policy`, `service_policy`,
`s3_full_access`, `privilege_escalation` — which is exactly why `CKV_AWS_289` and `CKV_AWS_355` each
report **4** times. Fixing `admin_policy` clears its 8 findings but leaves the identical wildcard in the
other three still firing. The lab's own hint — "the rule that fires most often is usually one shared
module away from being fixed everywhere" — is the counterfactual: if these four policies were one
reusable module with the ARNs as a variable, a single edit would clear all sixteen IAM findings. They
are not; they are duplicated code, so leverage is capped at one resource. The frequency count is
therefore measuring copy-paste, not measuring one fixable root cause — the useful reading is "this rule
fires 4x because the same mistake was pasted 4x," which is an argument for refactoring to a module, not
just for editing four files.

### What I would sort a real backlog by, given the null severity column

Severity is null on all 57 Terraform findings, so I could not rank by it even if I wanted to. In a real
backlog I would sort by **exploitability × blast radius**, approximated from the fields Checkov *does*
give: resource type and reachability. A `0.0.0.0/0` ingress on port 22 (`aws_security_group.ssh_open`)
and the `publicly_accessible = true` RDS outrank a missing security-group *description*
(`CKV_AWS_23`, three of my top five) even though the description rule fires more often — frequency and
importance are orthogonal here. What this says about buying severity from a vendor: a paid severity
column is convenient but it is *someone else's* generic risk model, not your architecture's. The
missing-description finding is genuinely low for anyone; but whether the open RDS is critical depends on
whether that subnet is actually internet-facing, which the vendor cannot know. Severity is worth paying
for as a starting sort, not as a substitute for context — and the fact that OSS Checkov withholds it is
a reminder that the number was always a judgement call dressed as data.

## Task 2

### Severity breakdowns — and whether these are queries or findings

The two counts differ and the lab is explicit about it: KICS's `.queries[]` array counts **distinct
queries**, while the terminal summary (`severity_counters`) counts **individual findings**. I report
both.

**Ansible** — 4 distinct queries, 10 findings:

| Severity | Queries | Findings |
|---|---:|---:|
| HIGH | 3 | 9 |
| LOW | 1 | 1 |
| **Total** | **4** | **10** |

**Pulumi** — 6 distinct queries, 6 findings (here each query fired exactly once, so the two columns
coincide):

| Severity | Queries = Findings |
|---|---:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |
| **Total** | **6** |

### Top five Ansible queries by files touched

(There are only four Ansible queries in total; all are listed.)

| Files | Severity | Query |
|---:|---|---|
| 6 | HIGH | Passwords And Secrets — Generic Password |
| 2 | HIGH | Passwords And Secrets — Password in URL |
| 1 | HIGH | Passwords And Secrets — Generic Secret |
| 1 | LOW | Unpinned Package Version |

### One finding each way, explained by what the tool can parse

**KICS reports, Checkov did not: "RDS DB Instance Publicly Accessible" (CRITICAL) on
`pulumi/Pulumi-vulnerable.yaml`.** This is the pure-parsing case. Checkov 3.x has **no Pulumi
framework** — it wants rendered Terraform state or HCL, not Pulumi YAML/Python — so it produces *zero*
findings on that file no matter what is in it. KICS ships first-class Pulumi YAML parsing, reads
`publiclyAccessible: true` on the `aws:rds:Instance`, and flags it. Checkov's silence here is inability
to parse, not disagreement.

**Checkov covers, KICS did not: the IAM wildcard / privilege-escalation policy class** (`CKV_AWS_286`
privilege escalation, `CKV_AWS_288` data exfiltration, `CKV_AWS_289`, `CKV_AWS_355`). This one is more
interesting than a parsing gap, and I checked it rather than assuming: the **same**
`Action:"*" Resource:"*"` policy (`adminPolicy`) exists in `Pulumi-vulnerable.yaml`, which KICS *did*
parse — yet KICS's Pulumi results contain no IAM query at all (`[.queries[].query_name]` filtered for
IAM/Policy/Wildcard returns `[]`). So this is a **query-catalog** gap, not a parsing one: KICS parsed
the wildcard policy and simply has no Pulumi query that opens up and reasons about an embedded IAM policy
document the way Checkov's IAM checks do on HCL. Checkov unpacks the `jsonencode({...})` statement and
evaluates its actions and resources; KICS's Pulumi pack checks resource *attributes* (encryption, public
access) and stops there. Two tools, same bytes, different depth.

### What runs in the pipeline, and the gap between them

I would run **both**, because they are strong in non-overlapping places and this lab is a live
demonstration of the gap: Checkov owns Terraform with ~2,500 policies and real IAM-document analysis;
KICS owns Pulumi and Ansible, which Checkov either cannot parse (Pulumi) or is not being pointed at
(Ansible). Picking one means going blind on whatever it does not parse — a Pulumi-only shop running only
Checkov would see *nothing*, and a Terraform shop running only KICS would lose the IAM-policy depth shown
above. For the gap between their verdicts I would not try to reconcile the raw numbers (57 vs 10 vs 6 are
not comparable — different languages, different resource counts, findings vs queries); instead I would
normalise both into one tracker keyed by *resource and rule intent* (which is exactly what Lab 10's
DefectDojo import does), dedupe the overlaps, and treat a finding that only one tool produces as coverage
to keep rather than noise to drop. The pipeline decision is "both scanners, unified backlog," and the
plan for the gap is a normalisation layer, not a winner.

## Bonus

### The policy

`labs/lab6/policies/my-custom-policy.yaml`, `CKV_CUSTOM_1`:

> Every S3 bucket must carry all three of the `Environment`, `Owner` and `CostCenter` tags.

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

A `filter`-free `attribute` policy: each `exists` clause is a pass/fail condition, combined with `and`,
so a bucket must have all three tag keys or it fails.

### It fires

```console
$ checkov -d labs/lab6/vulnerable-iac/terraform --external-checks-dir labs/lab6/policies \
    --output json --output-file-path labs/lab6/results/checkov-custom/
$ jq '[.[].results.failed_checks[]? | select(.check_id|test("CUSTOM")) | {check_id,resource,file_path}]' \
    labs/lab6/results/checkov-custom/results_json.json
[
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_s3_bucket.public_data",       "file_path": "/main.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_s3_bucket.unencrypted_data",  "file_path": "/main.tf" }
]
```

Both S3 buckets in the sample fail: `public_data` has only a `Name` tag, `unencrypted_data` has none of
the three. (`aws_s3_bucket` is present in the sample, so the policy actually has something to bind to —
a policy naming an absent resource type runs happily and finds nothing.)

### The change that makes it pass, confirmed

Add the three tags to the bucket:

```hcl
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
```

Confirmed against a fixed copy of the resource:

```console
$ checkov -f fixed-main.tf --external-checks-dir labs/lab6/policies --check CKV_CUSTOM_1 --output json
PASSED   CKV_CUSTOM_1   aws_s3_bucket.public_data
```

Fails with the tags missing, passes with all three present — full round trip.

### Why this rule is mine, not something Checkov should ship

Checkov cannot ship "require a `CostCenter` tag" because tag *keys* are an organisational convention, not
an AWS security property — one company's `CostCenter` is another's `cost-center` or `BU`, and most have
no such requirement at all. This particular rule comes from a concrete internal standard: our finance
team allocates cloud spend by the `CostCenter` tag and incident response pages the `Owner`, so an
untagged bucket is simultaneously **unbillable and unownable** — the exact situation that turns a 2am S3
exposure into "nobody knows whose bucket this is." The generic Checkov catalog rightly stays out of that;
a per-org policy-as-code file is where it belongs, which is the whole point of `--external-checks-dir`.
