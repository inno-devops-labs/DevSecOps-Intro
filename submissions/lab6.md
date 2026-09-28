# Lab 6 — Submission

IaC scanning of deliberately broken Terraform, Ansible and Pulumi with two scanners that
disagree by design: Checkov on Terraform, KICS on Ansible and Pulumi.

## Setup

```console
$ checkov --version
3.3.20
$ docker --version
Docker version 27.x
```

Checkov 3.3.x installed into the conda env with `pip`. KICS run from `checkmarx/kics:latest`
in Docker, with `--user "$(id -u):$(id -g)"` so the reports are writable by me and not root.

## Task 1 — Checkov on Terraform

```console
$ checkov -d labs/lab6/vulnerable-iac/terraform \
    --output cli --output json \
    --output-file-path labs/lab6/results/checkov-terraform/
```

### Passed / failed per framework

`results_json.json` is an array with one object per framework, because Checkov ran `terraform`
and the `secrets` scanner together:

| Framework | Passed | Failed |
|---|---:|---:|
| `terraform` | 49 | 78 |
| `secrets` | 0 | 2 |

The two `secrets` findings are a hardcoded value in `database.tf` (`CKV_SECRET_6`, high-entropy
string — the RDS password) and an AWS access key pattern in `main.tf` (`CKV_SECRET_2`).

### Top five rules by frequency

Looked up against the [Checkov policy index](https://www.checkov.io/5.Policy%20Index/all.html):

| n | Rule | What it checks |
|---:|---|---|
| 4 | `CKV_AWS_289` | IAM policy grants permissions-management / resource-exposure actions with no resource constraint |
| 4 | `CKV_AWS_355` | IAM statement uses `"*"` as its `Resource` for restrictable actions |
| 3 | `CKV_AWS_23` | Every security group and rule must carry a description |
| 3 | `CKV_AWS_288` | IAM policy allows data-exfiltration actions (e.g. `s3:GetObject`) unconstrained |
| 3 | `CKV_AWS_290` | IAM policy allows write actions with no resource constraint |

(`CKV_AWS_382` — SG egress to `0.0.0.0/0` on all ports — also fires 3×, tied for fifth.)

Every one of the top rules except `CKV_AWS_23` traces back to the same anti-pattern: an IAM
statement with `Action = "*"` / `Resource = "*"`.

### The single highest-leverage change

**File `iam.tf`, resource `aws_iam_policy.admin_policy`.** Its policy body is one statement:

```hcl
Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
```

That single block fails **9 distinct checks** at once — `CKV_AWS_62`, `CKV_AWS_63`,
`CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_355`, and the
graph check `CKV2_AWS_40`. Scoping that one statement down to named actions and ARNs clears all
nine in a single edit — far more leverage than the 12-finding `aws_db_instance.unencrypted_db`,
where each finding (encryption, public access, backups, monitoring, deletion protection…) is an
independent attribute needing its own line.

**Why fixing it once is not fixing it five times.** The same `Resource = "*"` wildcard also lives
in `aws_iam_role_policy.s3_full_access`, `aws_iam_user_policy.service_policy` and
`aws_iam_policy.privilege_escalation` — which is exactly why `CKV_AWS_355` and `CKV_AWS_289` each
fire **4×**, not once. Checkov evaluates each policy document independently; there is no shared
module, so fixing `admin_policy` leaves those rules firing on the other three. The real
highest-leverage move is architectural: refactor the four hand-written policies into one
least-privilege module, so the scoped fix propagates to every caller and the rule count drops to
zero everywhere at once. "One rule fires four times" is a signal that four copies of the same
mistake are one refactor away from being fixed together.

### What I would sort by, given null severity

Every finding here has `severity: null` — open-source Checkov ships no severities, and no flag
turns them on. In a real backlog I would sort by **blast radius**, not by a vendor's severity
label: how many resources the rule touches (frequency, as above), whether it is internet-exposed
(the public S3 bucket and `0.0.0.0/0` SG rules first), and whether it leaks credentials (the two
`secrets` findings jump the queue regardless of count). That the paid tier's only addition here is
a `severity` column tells you severity is a **convenience, not the analysis** — the same
prioritisation is reconstructable for free from exposure and frequency, and buying it mainly buys
a shared vocabulary and SLA mapping, not new detection.

## Task 2 — KICS on Ansible and Pulumi

```console
$ docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
    checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
    -o /path/results/kics-ansible/ --report-formats json,sarif
$ docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
    checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
    -o /path/results/kics-pulumi/ --report-formats json,sarif
```

### Severity breakdowns

Two different denominators, so both are shown. The `.queries` array counts **distinct queries**;
`severity_counters` counts **individual findings** (KICS's terminal total).

**Ansible** — 4 queries / 10 findings across 3 files:

| Severity | Queries | Findings |
|---|---:|---:|
| HIGH | 3 | 9 |
| LOW | 1 | 1 |

**Pulumi** — 6 queries / 6 findings in 1 file:

| Severity | Queries | Findings |
|---|---:|---:|
| CRITICAL | 1 | 1 |
| HIGH | 2 | 2 |
| MEDIUM | 1 | 1 |
| INFO | 2 | 2 |

### Top Ansible queries by findings

Only four queries fired, ordered by finding locations (KICS's per-query `files` array is one entry
per finding, not per distinct file):

| Findings | Severity | Query |
|---:|---|---|
| 6 | HIGH | Passwords and Secrets — Generic Password |
| 2 | HIGH | Passwords and Secrets — Password in URL |
| 1 | HIGH | Passwords and Secrets — Generic Secret |
| 1 | LOW | Unpinned Package Version |

Nine of the ten Ansible findings are hardcoded credentials; the outlier is an unpinned `apt`
package version.

### One finding each way, explained by what each tool can parse

- **KICS reports, Checkov cannot:** `RDS DB Instance Publicly Accessible` (CRITICAL) in
  `pulumi/Pulumi-vulnerable.yaml`. Checkov 3.x has **no Pulumi framework** — it wants rendered
  state, not a Pulumi program — so it structurally never sees this resource. KICS parses the Pulumi
  definition directly and flags it. Same story for the whole Ansible corpus: Checkov never scanned
  it.
- **Checkov covers, KICS did not:** Checkov's **graph checks** (`CKV2_*`) reason across resources —
  e.g. `CKV2_AWS_6` "S3 bucket has a Public Access block" and `CKV2_AWS_40` "policy does not grant
  full IAM privileges" fire only after Checkov builds a dependency graph of the Terraform and
  evaluates relationships between resources. KICS's per-resource query model doesn't express
  "resource A must be referenced by a separate resource B" as naturally. (Caveat: the two tools
  were pointed at different corpora by design — Checkov at Terraform, KICS at Ansible/Pulumi — so
  this is a capability difference, not a same-file miss.)

### Two scanners, three formats, two verdicts — pipeline decision

I would run **both, gated differently**: Checkov as a blocking check on Terraform (it has the
deepest AWS graph coverage and runs natively without Docker), and KICS as a blocking check on
Ansible and Pulumi, where Checkov is blind. Neither is a superset of the other, so picking one
leaves a whole language unscanned. The gap between them — different rule sets, different severity
scales, one tool with severities and one without — I would close by normalising both outputs to
SARIF (both emit it) and importing into a single tracker (Lab 10's DefectDojo) so findings
dedupe and rank on one scale instead of two tool-native ones. The pipeline decision is not "which
scanner," it is "which scanner owns which language," plus a merge step so the two verdicts become
one backlog.

## Bonus

Not attempted — the custom policy (6.5/6.6) is optional and I focused on Tasks 1 and 2. The
Terraform sample has good candidates if I come back to it (e.g. an RDS `iam_database_authentication`
rule against `aws_db_instance.unencrypted_db`, which currently lacks it).

## Cleanup

```console
$ docker rm ...   # KICS containers are --rm, nothing to clean
```

`labs/lab6/results/` is left uncommitted, per the lab; the numbers above are pasted from it.
