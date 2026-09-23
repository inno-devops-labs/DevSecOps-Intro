# Lab 6 — IaC Security

I scanned the supplied Terraform with Checkov and the Ansible and Pulumi
samples with KICS, then tested one high-leverage fix and a custom recovery
policy. The vulnerable samples are unchanged. All fix experiments used
temporary copies under the ignored `labs/lab6/results/` directory.

## Environment and reproducibility

| Item | Version or reference |
|---|---|
| Scan date | 23 September 2026 |
| Sample revision | `4c38d874722a768aec5b2f9d389406fd6df0f27a` |
| Checkov | `bridgecrew/checkov:3.3.19` |
| Checkov image digest | `sha256:d3e96adafdb315ca82e792ca8708c01adae85292800fb064c8b309b3d0cb7b80` |
| KICS | `checkmarx/kics:latest`, resolved to `v2.1.20` |
| KICS image digest | `sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602` |
| Runtime | Docker Desktop, Linux containers; PowerShell on Windows |

The commands below use Docker so the scanners do not depend on the host's
Python packages. For an exact rerun, use the recorded image digests instead
of mutable tags. Raw JSON, SARIF, CLI output, and timing records remain local;
the submission contains this report and the custom policy only.

## Task 1

I ran Checkov with both CLI and JSON output:

```powershell
docker run --rm -v "${PWD}:/src" -w /src bridgecrew/checkov:3.3.19 `
  -d labs/lab6/vulnerable-iac/terraform `
  --output cli --output json `
  --output-file-path labs/lab6/results/checkov-terraform/
```

The scan completed in **6.80 seconds**, excluding image download, and exited
with code **1** because checks failed. `results_json.json` is an array with
one object per framework:

| Framework | Passed | Failed | Skipped | Parsing errors |
|---|---:|---:|---:|---:|
| Terraform | 49 | 78 | 0 | 0 |
| Secrets | 0 | 2 | 0 | 0 |
| **Total** | **49** | **80** | **0** | **0** |

The secrets findings are an AWS access-key pattern in `main.tf` and a
high-entropy string in `database.tf`. These are findings in the supplied
training fixture, not evidence that the example credentials are live.

### Most frequent rules

I counted failed checks across both framework objects, sorted by descending
frequency and then rule ID. Descriptions were checked against the
[Checkov policy index](https://www.checkov.io/5.Policy%20Index/terraform.html)
and the implementations packaged in version 3.3.19.

| Rule | Failures | What it checks |
|---|---:|---|
| `CKV_AWS_289` | 4 | Flags IAM permissions-management or resource-exposure actions without constraints. |
| `CKV_AWS_355` | 4 | Flags unrestricted resources for IAM actions that support resource-level restrictions. |
| `CKV_AWS_23` | 3 | Requires descriptions on security groups and their ingress/egress rules. |
| `CKV_AWS_288` | 3 | Detects IAM permissions that allow unconstrained data-exfiltration actions. |
| `CKV_AWS_290` | 3 | Detects unconstrained IAM write permissions. |

`CKV_AWS_382` also has three failures; it falls just outside this five-row
table because of the tie-break. Repeated findings indicate an opportunity
to fix shared configuration, but frequency alone does not establish impact.

### One change with the largest immediate payoff

I would replace the wildcard statement in
`labs/lab6/vulnerable-iac/terraform/iam.tf`, resource
`aws_iam_policy.admin_policy`, with the application's required actions and
resource scope. It fails **nine checks** because one statement grants
`Action = "*"` on `Resource = "*"`.

For a concrete experiment, I assumed the application only needs to read
objects under its `app/` prefix and replaced that statement in a temporary
copy with:

```hcl
{
  Effect   = "Allow"
  Action   = "s3:GetObject"
  Resource = "arn:aws:s3:::my-public-bucket-lab6/app/*"
}
```

The application's real access requirements would need confirmation before
deploying this allowlist. Re-scanning the copy changed Terraform's result
from **49 passed / 78 failed** to **58 passed / 69 failed**, with no new
findings; the two secrets findings were unchanged. These nine checks moved
from failed to passed on `aws_iam_policy.admin_policy`:

```text
CKV_AWS_62, CKV_AWS_63, CKV_AWS_286, CKV_AWS_287, CKV_AWS_288,
CKV_AWS_289, CKV_AWS_290, CKV_AWS_355, CKV2_AWS_40
```

This is one policy correction removing nine overlapping symptoms of broad
access, not nine independent fixes. The database has more findings on one
resource, but clearing those would require several different controls, such
as encryption, monitoring, backups, and availability. Putting the scoped
policy in a shared module would prevent each consumer from recreating the
wildcard; separately editing five copies creates five opportunities for
drift, and this sample has no such module yet.

### Prioritizing without vendor severity

All **80 baseline failed checks have `severity: null`**, so I would order a
real backlog by reachable exposure, data sensitivity, privilege and blast
radius, then use confidence, shared-fix leverage, and effort to break ties.
For example, the broad IAM policy deserves attention before missing rule
descriptions even though both appear near the top of the frequency table.
Buying severity metadata can improve consistency and save triage time, but
it cannot determine our deployment's exposure or business impact; null is
missing metadata, not evidence of low risk.

## Task 2

I ran the two KICS scans separately:

```powershell
docker run --rm --user 1000:1000 -v "${PWD}/labs/lab6:/path" `
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ `
  -o /path/results/kics-ansible/ --report-formats json,sarif

docker run --rm --user 1000:1000 -v "${PWD}/labs/lab6:/path" `
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ `
  -o /path/results/kics-pulumi/ --report-formats json,sarif
```

UID/GID `1000:1000` was used for the Linux container on Docker Desktop; there
is no host `id -u` equivalent needed for this Windows bind mount. Both scans
wrote JSON and SARIF successfully. Ansible took **4.52 seconds** and exited
**50**; Pulumi took **1.77 seconds** and exited **60**, reflecting detected
findings rather than scanner crashes.

### Severity and counting

Here, a **query** is a distinct matched rule in `.queries[]`; a **finding**
is one entry in a query's `.files[]`. The latter can contain multiple entries
for the same file, so neither measure is a count of unique filenames.

| Severity | Ansible queries | Ansible findings | Pulumi queries | Pulumi findings |
|---|---:|---:|---:|---:|
| Critical | 0 | 0 | 1 | 1 |
| High | 3 | 9 | 2 | 2 |
| Medium | 0 | 0 | 1 | 1 |
| Low | 1 | 1 | 0 | 0 |
| Informational | 0 | 0 | 2 | 2 |
| **Total** | **4** | **10** | **6** | **6** |

The finding columns match `severity_counters` and `total_counter`. Ansible
reported three files scanned and parsed with 287 queries loaded; Pulumi
reported one file with 21 queries loaded. Both reported zero files that
failed to scan and zero queries that failed to execute.

### Top Ansible queries

Only four queries matched, so a top-five list contains four rows. The table
shows both the assignment's `.files | length` measure and the actual number
of distinct files; ranking by either gives this order after tie-breaking.

| Query | Severity | Finding entries | Distinct files | Files touched |
|---|---|---:|---:|---|
| Passwords And Secrets - Generic Password | High | 6 | 3 | `configure.yml`, `deploy.yml`, `inventory.ini` |
| Passwords And Secrets - Password in URL | High | 2 | 1 | `deploy.yml` |
| Passwords And Secrets - Generic Secret | High | 1 | 1 | `inventory.ini` |
| Unpinned Package Version | Low | 1 | 1 | `deploy.yml` |

### Where coverage differs

**KICS finding missing from Checkov:** `Unpinned Package Version`
(`c05e2c20-0a2c-4686-b1f8-5f0a5612d4e8`) flags
`ansible/deploy.yml:99`, where the `Install application` task uses
`apt.state: latest`. To avoid confusing different input directories with
tool capability, I also ran Checkov on the same Ansible directory with
`--framework ansible secrets`: it reported 5 passed / 1 failed Ansible
checks and 3 secrets failures, but no finding for that package task.
KICS recognizes the package module and its update setting; Checkov can
also parse Ansible, but its checks in this run did not cover that behavior.

**Checkov class missing from these KICS results:** Checkov analyzes the IAM
documents produced by Terraform's `jsonencode`, including privilege
escalation and unconstrained permissions on `aws_iam_policy.admin_policy`.
The Pulumi manifest contains the analogous wildcard policy under
`resources.adminPolicy.properties.policy.fn::toJSON`, yet KICS reported no
IAM findings. This is a gap in the tested Pulumi coverage, not proof that
KICS cannot find IAM problems in Terraform: recognizing the outer resource
format does not guarantee equivalent analysis of its embedded policy.

The same-input Ansible review also found the reverse difference:
Checkov's `CKV2_ANSIBLE_2` flagged the HTTP `get_url` task in
`deploy.yml:103-112`, while KICS did not report a transport-security finding
for it. Both tools understand that YAML; the difference is in the checks
applied, so calling the whole format unsupported would be misleading.

The supplied Pulumi directory includes Python as well as YAML, but the KICS
findings all point to **`Pulumi-vulnerable.yaml`**. Its one-file scan does not
demonstrate analysis of `__main__.py` or its runtime expressions; KICS's
[documented Pulumi support](https://docs.kics.io/latest/platforms/#pulumi)
is for YAML manifests, and Checkov has no native Pulumi framework.

### Pipeline decision

I would run Checkov for Terraform and the custom policy, and KICS for the
Ansible and Pulumi YAML paths, retaining both reports and deduplicating
overlapping findings by resource and behavior. Gates would focus on reviewed
exposure and privilege risks, with owners and expiry dates for exceptions,
rather than whichever scanner produces the larger total. I would keep
small known-bad fixtures for gaps such as package updates, HTTP downloads,
and embedded IAM policies, then add focused rules where the current catalogs
miss them. For Pulumi Python, I would add Pulumi-native policy checks over
evaluated resources and review dynamic expressions, instead of treating the
YAML scan as coverage of the Python program.

## Bonus

The policy is [my-custom-policy.yaml](../labs/lab6/policies/my-custom-policy.yaml),
ID **`CKV2_CUSTOM_1`**: every `aws_db_instance` must explicitly retain automated
backups for **14 to 35 days**.

I defined **LAB-DR-14** as the internal recovery standard for this exercise:
the application team needs a two-week recovery window to cover delayed
detection across a weekly review cycle. This is a proposed lab standard,
not a claim about an actual employer policy or a past incident. The explicit
14-day minimum is an organizational choice; a generic scanner cannot infer
it for every workload.

The YAML follows Checkov's [custom-policy schema](https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html).
It filters for RDS instances and combines existence, lower-bound, and
upper-bound checks; metadata supplies category and `HIGH` severity. This
locally assigned severity is present in the custom findings even though the
built-in baseline findings have null severity.

The existing `CKV_AWS_133` is less strict: its packaged implementation accepts
explicit retention from 1 through 35 days and treats an omitted value as the
provider default of one day. Our policy rejects omission and anything below
14, so it adds a measurable requirement rather than renaming that check.

### Failure evidence

```powershell
docker run --rm -v "${PWD}:/src" -w /src bridgecrew/checkov:3.3.19 `
  -d labs/lab6/vulnerable-iac/terraform `
  --external-checks-dir labs/lab6/policies `
  --output json --output-file-path labs/lab6/results/checkov-custom/
```

The scan exited 1. Terraform had **49 passed / 80 failed**, including these
two custom failures; the secrets framework remained at two failures.
This is a projection of the custom records from `results_json.json`:

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf",
    "severity": "HIGH"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf",
    "severity": "HIGH"
  }
]
```

`unencrypted_db` explicitly sets retention to zero; `weak_db` omits it.
Neither meets the explicit two-week requirement.

### Passing change and boundary checks

In a temporary copy at `labs/lab6/results/custom-fixed/`, I changed the first
instance's retention from 0 to 14 and added the same attribute to the second:

```hcl
backup_retention_period = 14
```

I then selected only the custom rule to isolate the result:

```powershell
docker run --rm -v "${PWD}:/src" -w /src bridgecrew/checkov:3.3.19 `
  -d labs/lab6/results/custom-fixed `
  --external-checks-dir labs/lab6/policies `
  --check CKV2_CUSTOM_1 --framework terraform `
  --output json --output-file-path labs/lab6/results/checkov-custom-fixed/
```

The command exited **0** with **2 passed, 0 failed, 0 skipped, and 0 parsing
errors**. Both `aws_db_instance.unencrypted_db` and `aws_db_instance.weak_db`
appeared in `passed_checks` for `CKV2_CUSTOM_1`; this does not claim that their
other vulnerabilities are fixed.

I also ran the policy against isolated boundary fixtures:

| Retention value | Observed result |
|---|---|
| Attribute omitted | Failed |
| 0 days | Failed |
| 13 days | Failed |
| 14 days | Passed |
| 35 days | Passed |
| 36 days | Failed |
| S3 bucket outside the policy's scope | Not evaluated by this rule |

That run produced **2 passes and 4 failures**, with no parsing errors, and
confirmed that the filter does not accidentally apply the RDS rule to S3.
The original Terraform remains unchanged; only the report and reusable
policy are submitted.
