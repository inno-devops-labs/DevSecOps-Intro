# Lab 6 — IaC Security

Completed Task 1, optional Task 2, and the custom-policy bonus on **2026-09-25
(Europe/Moscow; scan timestamps are 2026-09-24 UTC)**. The input is the lab fixture
at commit `b6352535429cc3286f99234753ffdd96161a1003`. No infrastructure was
deployed, and `labs/lab6/vulnerable-iac/` is unchanged. Remediation experiments
used separate copies under the Git-ignored `labs/lab6/results/` directory.

## Reproduction and versions

The host is Windows with Docker Desktop, Docker Engine **29.7.2**. Checkov ran
inside its Linux image rather than being installed into the host Python:

| Scanner | Actual version | Image digest |
| --- | --- | --- |
| Checkov | 3.3.16, matching `tools/versions.yaml` | `bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016` |
| KICS | v2.1.20, resolved from the lab's `latest` tag | `checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602` |

These PowerShell commands reproduce the scans from the repository root; image
digests pin the images used here. Each scan is a separate invocation, and its
non-zero exit is recorded rather than preventing the next scan:

```powershell
$labRoot = (Resolve-Path 'labs/lab6').Path
$checkovImage = 'bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016'
$kicsImage = 'checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602'

docker run --rm --user 1000:1000 -e HOME=/tmp `
  -e BC_SKIP_MAPPING=TRUE -e CKV_SKIP_REGISTRY=TRUE `
  -v "${labRoot}:/path" $checkovImage `
  -d /path/vulnerable-iac/terraform --output cli --output json `
  --output-file-path /path/results/checkov-terraform/
# Exit 1: findings.

docker run --rm --user 1000:1000 -v "${labRoot}:/path" $kicsImage `
  scan -p /path/vulnerable-iac/ansible/ -o /path/results/kics-ansible/ `
  --report-formats json,sarif --no-progress
# Exit 50: findings.

docker run --rm --user 1000:1000 -v "${labRoot}:/path" $kicsImage `
  scan -p /path/vulnerable-iac/pulumi/ -o /path/results/kics-pulumi/ `
  --report-formats json,sarif --no-progress
# Exit 60: findings.
```

The Checkov environment settings skip remote platform mappings and registry
lookups; no local checks were excluded. UID/GID `1000:1000` was usable on the
Windows bind mount and avoided running the scanners as root. JSON aggregation
used PowerShell/Python because `jq` was not installed. Checkov's baseline JSON
is an **array of framework reports**, while each KICS JSON is an **object** with
`queries` and `severity_counters`.

## Task 1

### Per-framework results

Source: `labs/lab6/results/checkov-terraform/results_json.json`.

| Framework | Passed | Failed | Skipped | Parsing errors |
| --- | ---: | ---: | ---: | ---: |
| terraform | 49 | 78 | 0 | 0 |
| secrets | 0 | 2 | 0 | 0 |
| Total | 49 | 80 | 0 | 0 |

Terraform covered 16 resources. The two secrets findings are additional rows,
not part of the 78 Terraform failures. All **80 failed findings** have
`severity: null` in this baseline.

### Five most frequent rules

Counts aggregate `results.failed_checks` across both frameworks. Ties are
resolved by ascending rule ID, matching the lab's grouping/sorting approach.
Descriptions were checked against the actual Python implementations shipped
inside Checkov 3.3.16 and the
[official policy index](https://www.checkov.io/5.Policy%20Index/all.html).

| Rule | Failures | What it checks | Implementation in `checkov/terraform/checks/resource/aws/` |
| --- | ---: | --- | --- |
| CKV_AWS_289 | 4 | Detects unconstrained IAM permissions-management or resource-exposure permissions. | `IAMPermissionsManagement.py` |
| CKV_AWS_355 | 4 | Detects actions granted on `Resource: "*"` when those actions support resource restrictions. | `IAMStarResourcePolicyDocument.py` |
| CKV_AWS_23 | 3 | Requires descriptions on security groups and their ingress/egress rules. | `SecurityGroupRuleDescription.py` |
| CKV_AWS_288 | 3 | Detects permissions classified as permitting data exfiltration by the IAM policy analysis. | `IAMDataExfiltration.py` |
| CKV_AWS_290 | 3 | Detects unconstrained IAM write permissions. | `IAMWriteAccess.py` |

`CKV_AWS_382` also has three failures and falls immediately outside the five
rows under this tie-break. The group descriptions already exist in the sample;
the `CKV_AWS_23` failures include the missing descriptions on egress rules.

### Highest-leverage single change

Replace the single wildcard Allow statement in
`labs/lab6/vulnerable-iac/terraform/iam.tf`, resource
**`aws_iam_policy.admin_policy`**, with an explicitly scoped permission set.
For the verification experiment, the assumed application requirement was
read-only access to the `application/` object prefix in one bucket:

```hcl
Statement = [
  {
    Effect   = "Allow"
    Action   = ["s3:GetObject"]
    Resource = "arn:aws:s3:::my-public-bucket-lab6/application/*"
  }
]
```

This replaces both `Action = "*"` and `Resource = "*"` in that one statement;
it is not a claim that the application's real permissions have been established.
Before adopting it in a real deployment, the owner must confirm that scope.

The rescan of a complete temporary copy, with only that statement changed,
confirms **nine findings cleared**, with no new failures:

| Framework | Before: passed / failed | After: passed / failed |
| --- | --- | --- |
| terraform | 49 / 78 | 58 / 69 |
| secrets | 0 / 2 | 0 / 2 |

The removed rule/resource pairs are `CKV_AWS_62`, `CKV_AWS_63`,
`CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`,
`CKV_AWS_290`, `CKV_AWS_355`, and `CKV2_AWS_40`, all on
`aws_iam_policy.admin_policy`. Evidence is in
`results/checkov-iam-fixed/results_json.json`. Its exit remains 1 because other
resources still fail.

This is one root-cause change clearing overlapping diagnoses, rather than five
or nine independent remediations. `unencrypted_db` has more rows (12), but
clearing all of them requires distinct changes to encryption, networking,
backups, monitoring, authentication and other settings. In a real shared IAM
module, correcting its permission construction once also prevents recurrence
across consumers; this fixture has no shared module, so I do not claim that
changing `admin_policy` fixes the other IAM policy resources.

### What to do with null severity

For a real backlog I would prioritize verified exploitability, Internet
reachability, effective permissions, data sensitivity and business impact,
then use frequency and remediation effort to group work by root cause.
`severity: null` means missing vendor classification, not low risk or safety.
Paid severity enrichment can help normalize a queue, but it does not replace
deployment context or justify buying a score solely to fill this column.

## Task 2

### Severity breakdowns and coverage

Sources: `results/kics-ansible/results.json` and
`results/kics-pulumi/results.json`. **Queries** below means distinct entries in
`.queries`; **findings** means individual entries in `.queries[].files`, also
counted by `severity_counters` and the terminal summary.

| Severity | Ansible queries | Ansible findings | Pulumi queries | Pulumi findings |
| --- | ---: | ---: | ---: | ---: |
| CRITICAL | 0 | 0 | 1 | 1 |
| HIGH | 3 | 9 | 2 | 2 |
| MEDIUM | 0 | 0 | 1 | 1 |
| LOW | 1 | 1 | 0 | 0 |
| INFO | 0 | 0 | 2 | 2 |
| TRACE | 0 | 0 | 0 | 0 |
| Total | 4 | 10 | 6 | 6 |

Ansible reports three files scanned/parsed, 287 queries in `queries_total`,
zero files failed to scan, and zero queries failed to execute. Pulumi reports
one file scanned/parsed, 21 queries in `queries_total`, and the same zero error
counters. `queries_total` is not the number of queries with findings.
Both runs also produced `results.sarif` reports.

All Pulumi findings point to `Pulumi-vulnerable.yaml`. KICS's supported Pulumi
input is [YAML manifests](https://docs.kics.io/latest/platforms/#pulumi): this run
does not establish semantic coverage of `__main__.py`, and `Pulumi.yaml` with
`runtime: python` is not the scanned resource manifest. This qualifies the lab's
phrase that KICS parses Pulumi directly.

### Top Ansible queries by reported file entries

The requested top-five extraction returns **only four rows** for this image
and fixture. There is no fifth matching query to report. Ranked by
`.files | length`, with query name breaking ties:

| Query | Severity | File entries / findings | Distinct files touched |
| --- | --- | ---: | ---: |
| Passwords And Secrets - Generic Password | HIGH | 6 | 3 |
| Passwords And Secrets - Password in URL | HIGH | 2 | 1 |
| Passwords And Secrets - Generic Secret | HIGH | 1 | 1 |
| Unpinned Package Version | LOW | 1 | 1 |

The six password entries span `configure.yml`, `deploy.yml` and `inventory.ini`;
they do not mean six distinct files. The two URL entries are both in
`deploy.yml`; Generic Secret points to `inventory.ini:20`, and Unpinned Package
Version points to `deploy.yml:99` (`apt.state: latest`). Three rows come from
KICS's Common secrets checks; only the final row is an Ansible-specific query.

### What one scanner saw and the other did not

**KICS-only in these runs:**
[`647de8aa-5a42-41b5-9faf-22136f117380`, RDS DB Instance Publicly Accessible](https://docs.kics.io/latest/queries/pulumi-queries/aws/647de8aa-5a42-41b5-9faf-22136f117380/)
flags `Pulumi-vulnerable.yaml:104`,
`resources[unencryptedDb].properties.publiclyAccessible`, as CRITICAL.
Checkov's Terraform run cannot report this Pulumi resource, and Checkov 3.3.16's
supported-framework list has no Pulumi runner. Checkov does flag the analogous
public RDS instance in HCL (`CKV_AWS_17`), so the difference is input-format
coverage, not absence of an RDS publicity rule in Checkov.

**Checkov-covered class absent from the two KICS reports:** broad IAM
permissions and privilege-escalation permissions, including `CKV_AWS_286` and
the four frequent IAM rules in Task 1. Checkov parses Terraform's
`jsonencode` policy document and analyzes its actions/resources. The analogous
Pulumi IAM policies are YAML objects using `fn::toJSON`; the KICS image's
Pulumi query catalog contains no equivalent IAM authorization-policy checks
(its IAM entry checks account password length), and no IAM policy finding
appears in this run. This is a rule-coverage gap after parsing, not evidence
that YAML itself cannot be parsed or that KICS cannot scan Terraform; its
[documented Terraform support](https://docs.kics.io/latest/platforms/#terraform)
is a separate capability that this lab did not exercise.

### Pipeline decision

I would run pinned Checkov on Terraform and pinned KICS on Ansible and Pulumi
YAML, with locally defined blocking criteria for confirmed exposure, excessive
permissions and secrets. I would deduplicate by resource and underlying cause,
retain JSON/SARIF and parse-error counters, and give reviewed exceptions an
owner and expiry. I would track Pulumi Python and missing IAM-policy coverage
explicitly, adding a Pulumi-aware policy check with fixtures for the actual
generated resources rather than treating a successful parser exit as complete
coverage. Scanner upgrades would be tested against these fixtures, because
different counts or severities can reflect a changed catalog rather than a
changed deployment.

## Bonus

### The custom policy

File: [`labs/lab6/policies/my-custom-policy.yaml`](../labs/lab6/policies/my-custom-policy.yaml).

**Rule:** Under the proposed internal standard **LAB6-DB-014**, every RDS
instance must explicitly retain automated backups for **exactly 14 days**.

`CKV_CUSTOM_1` is a single-resource check with an `aws_db_instance` filter and
an attribute condition `backup_retention_period equals 14`. Metadata includes
category `BACKUP_AND_RECOVERY` and local severity `MEDIUM`. It follows the
[Checkov custom YAML policy schema](https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html).

```powershell
docker run --rm --user 1000:1000 -e HOME=/tmp `
  -e BC_SKIP_MAPPING=TRUE -e CKV_SKIP_REGISTRY=TRUE `
  -v "${labRoot}:/path" $checkovImage `
  -d /path/vulnerable-iac/terraform --external-checks-dir /path/policies `
  --output json --output-file-path /path/results/checkov-custom/
# Exit 1.
```

The full custom run reports Terraform **49 passed / 80 failed**, plus secrets
**0 passed / 2 failed**: exactly two additional failures. Extracting only the
custom rule's failed results gives this actual evidence:

```json
[
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf"
  },
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf"
  }
]
```

Both custom findings have `severity: "MEDIUM"` from our metadata. This does not
populate the null severities of the built-in rules. `unencrypted_db` explicitly
sets the retention to 0, while `weak_db` omits it; both violate our requirement.

### Passing change and observed confirmation

Copy the entire Terraform directory to `results/terraform-custom-fixed/`.
In that copy's `database.tf`, change `unencrypted_db.backup_retention_period`
from 0 to 14 and add `backup_retention_period = 14` inside `weak_db`. All other
attributes remain as provided. Then run:

```powershell
docker run --rm --user 1000:1000 -e HOME=/tmp `
  -e BC_SKIP_MAPPING=TRUE -e CKV_SKIP_REGISTRY=TRUE `
  -v "${labRoot}:/path" $checkovImage `
  -d /path/results/terraform-custom-fixed --external-checks-dir /path/policies `
  --framework terraform --check CKV_CUSTOM_1 --output json `
  --output-file-path /path/results/checkov-custom-fixed/
# Exit 0: 2 passed, 0 failed, 0 skipped, 0 parsing errors.
```

The single-framework JSON is an object in this filtered run. Its
`results.passed_checks` contains:

```json
[
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf"
  },
  {
    "check_id": "CKV_CUSTOM_1",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf"
  }
]
```

This is a pass for the custom policy, not a claim that the full fixture has
become secure. A separate boundary fixture scanned with the same policy
confirms the exact-value requirement and resource filter:

| Test resource | Retention | Result |
| --- | --- | --- |
| `aws_db_instance.missing` | omitted | FAILED |
| `aws_db_instance.disabled` | 0 | FAILED |
| `aws_db_instance.too_short` | 13 | FAILED |
| `aws_db_instance.compliant` | 14 | PASSED |
| `aws_db_instance.too_long` | 15 | FAILED |
| `aws_s3_bucket.out_of_scope` | not applicable | Not evaluated by this rule |

Evidence: `results/checkov-policy-cases/results_json.json`, **1 passed / 4
failed**, zero skipped/parsing errors, exit 1 as expected.

### Why this is our policy

**LAB6-DB-014 is an explicitly proposed internal standard for this exercise,
not an existing company mandate or a claimed historical incident.** It defines
a two-week restore window and a matching cap on retained backup history; the
policy checks that configuration choice, not successful restoration or the
retention of manual snapshots. Exactly 14 days is an organizational decision,
whereas a generally useful scanner rule should not reject every otherwise
valid 7-, 21-, or 35-day retention policy.

## Local evidence integrity

Raw reports, CLI logs, rule-source extracts, and temporary fixtures are kept
locally under `labs/lab6/results/` and are excluded from Git as required. These
SHA-256 values identify the JSON files used for the tables and proof above;
regenerated reports can differ because they contain run metadata.

| File relative to `labs/lab6/results/` | SHA-256 |
| --- | --- |
| `checkov-terraform/results_json.json` | `a95ce923195f1822dba1f40c8af2c4cce8b89b60699f2681ff537f5b60e332ec` |
| `kics-ansible/results.json` | `ef1db5c307bcc05871dd28c1eeccfd2b62cf78dfd1b05df36fb1e7d32c414979` |
| `kics-pulumi/results.json` | `6dc397b34fbda45b62beb0dbbcbef6f9f247b63e1a679fed95738caea42bdfe9` |
| `checkov-iam-fixed/results_json.json` | `7a42bcfa53b684b4dcfe294ed85d8e0021239d3d3f5afdb494608c6e4f032242` |
| `checkov-custom/results_json.json` | `938139ca87e65441c50e170d2d63a4587209be57821d3486104f44d5439abc5a` |
| `checkov-custom-fixed/results_json.json` | `21e0547ca489ba7e52adae11de7bf26b3276df9fd6a0b3c59a35526a9d103774` |
| `checkov-policy-cases/results_json.json` | `a8c4bba6b6cfcf92f93f3ed966d97681d3ac64c69fda5673ad200e6a8be8b473` |
