# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

Tooling: `checkov 3.3.19`, `checkmarx/kics:latest`, Docker 29.4.3, `jq-1.7.1`.
Target: `labs/lab6/vulnerable-iac/`, broken on purpose.

## Task 1

### Passed and failed per framework

```bash
$ jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' \
    labs/lab6/results/checkov-terraform/results_json.json
[
  { "framework": "terraform", "passed": 49, "failed": 78 },
  { "framework": "secrets",   "passed": 0,  "failed": 2 }
]
```

| Framework | Passed | Failed |
|---|---:|---:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |
| **Total** | **49** | **80** |

The `secrets` framework runs alongside `terraform` without being asked, which is why `results_json.json` is a JSON **array** and a filter starting `.results.failed_checks` dies with `Cannot index array with string`. Its two findings are `CKV_SECRET_2` (AWS Access Key) at `main.tf:8` and `CKV_SECRET_6` (Base64 High Entropy String) at `database.tf:48`.

Failures cluster by file: `iam.tf` 23, `database.tf` 22, `main.tf` 21, `security_groups.tf` 14.

### Top five rules by frequency

```bash
$ jq '[.[].results.failed_checks[]?.check_id] | group_by(.) | map({rule: .[0], count: length})
      | sort_by(-.count) | .[:5]' labs/lab6/results/checkov-terraform/results_json.json
```

| # | Rule | Count | What it checks |
|--:|---|---:|---|
| 1 | `CKV_AWS_289` | 4 | IAM policies must not allow permissions management or resource exposure without constraints — i.e. `iam:Put*`/`iam:Attach*`-class actions on `Resource: "*"` |
| 2 | `CKV_AWS_355` | 4 | No IAM policy document may use `"*"` as a statement's `Resource` for actions that can be restricted to specific ARNs |
| 3 | `CKV_AWS_23` | 3 | Every security group and every rule inside it must carry a `description` |
| 4 | `CKV_AWS_288` | 3 | IAM policies must not allow data exfiltration — read-everything actions granted without a resource constraint |
| 5 | `CKV_AWS_290` | 3 | IAM policies must not allow write access without constraints |

(`CKV_AWS_382`, egress to `0.0.0.0/0` on all ports, ties for fifth at 3.)

Four of the five are IAM policy-document checks, and they hit the same four resources — `aws_iam_policy.admin_policy`, `aws_iam_policy.privilege_escalation`, `aws_iam_role_policy.s3_full_access`, `aws_iam_user_policy.service_policy`. That is the shape of the finding list: it is not 80 independent problems, it is a handful of over-broad policy documents counted from several angles.

### The single highest-leverage change

**File `labs/lab6/vulnerable-iac/terraform/database.tf`, resource `aws_db_instance.unencrypted_db` (lines 5–37): 12 of the 80 findings, 15 % of the entire backlog, in one resource block.**

```
CKV_AWS_16   storage encryption at rest          CKV_AWS_17   not publicly accessible
CKV_AWS_118  enhanced monitoring                 CKV_AWS_129  CloudWatch log exports
CKV_AWS_133  backup retention                    CKV_AWS_157  Multi-AZ
CKV_AWS_161  IAM database authentication         CKV_AWS_226  auto minor version upgrades
CKV_AWS_293  deletion protection                 CKV_AWS_353  performance insights
CKV2_AWS_30  Postgres query logging              CKV2_AWS_60  copy tags to snapshots
```

Rewriting that one block — `storage_encrypted = true`, `publicly_accessible = false`, a non-zero `backup_retention_period`, `deletion_protection = true`, `multi_az`, monitoring and log exports on — clears all twelve.

**Why fixing it once is not the same as fixing it five times.** Fixing five findings one at a time gives you five edits, five reviews and five chances to regress, and it leaves the *cause* untouched: this RDS block was written from scratch with every default left at the insecure value. The next database someone adds starts from the same blank slate and re-earns the same twelve findings. Fixing it once in a shared module — or a `terraform_module` the team is required to call — makes the secure values the defaults, so the twelve findings never come back and every future database inherits the fix. The leverage is not in the twelve findings; it is in the fact that one edit changes what "a new database" means in this repository. That is also why frequency is a better triage signal here than any per-finding score: a rule that fires four times across four different IAM policies is pointing at a missing convention, not at four unrelated mistakes.

### Severity is null on every finding

```bash
$ jq -r '[.[].results.failed_checks[]?.severity] | unique' labs/lab6/results/checkov-terraform/results_json.json
[ null ]
```

Every one of the 80 findings has `severity: null` — open-source Checkov ships no severities, and no flag turns them on; they are a Prisma Cloud feature. In a real backlog I would not sort by vendor severity anyway. I would sort by **blast radius × reachability × fix cost**: which resource holds production data, whether the misconfiguration is reachable from the internet (`publicly_accessible = true` and `0.0.0.0/0` ingress outrank a missing tag no matter what a CVSS-style number says), and how many findings one edit clears. Frequency, as above, is a decent free proxy for that last term.

What that says about buying severity from a vendor: the number is a *starting* prior, computed without knowing which of your buckets is public or which database holds customer records. It is worth money when you have thousands of findings and need any ordering at all, and it is worth very little once a human who knows the architecture spends ten minutes with the list. The free tier withholding it is annoying, not blocking — and a team that treats a purchased severity column as the answer will patch a HIGH on an internal test bucket while the MEDIUM on the internet-facing database waits.

## Task 2

### Severity breakdowns

**These numbers are `.queries` entries — distinct queries, not findings.** KICS's terminal summary counts findings, and the two differ: the Ansible scan reports 10 findings across 4 distinct queries; the Pulumi scan reports 6 findings across 6 queries.

```bash
$ jq -c '[.queries[].severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab6/results/kics-ansible/results.json
$ jq -c '{files_scanned, lines_scanned, queries_total, total_counter, severity_counters}' \
    labs/lab6/results/kics-ansible/results.json
{"files_scanned":3,"lines_scanned":309,"queries_total":287,"total_counter":10,
 "severity_counters":{"CRITICAL":0,"HIGH":9,"INFO":0,"LOW":1,"MEDIUM":0,"TRACE":0}}
```

| Severity | Ansible (queries) | Ansible (findings) | Pulumi (queries) | Pulumi (findings) |
|---|---:|---:|---:|---:|
| CRITICAL | 0 | 0 | 1 | 1 |
| HIGH | 3 | 9 | 2 | 2 |
| MEDIUM | 0 | 0 | 1 | 1 |
| LOW | 1 | 1 | 0 | 0 |
| INFO | 0 | 0 | 2 | 2 |
| **Total** | **4** | **10** | **6** | **6** |

Ansible: 3 files, 309 lines, 287 queries executed. Pulumi: 1 file, 280 lines, 21 queries executed — and that "1 file" is the finding of the task, see below.

### Top five Ansible queries by files touched

| Severity | Query | Files |
|---|---|---:|
| HIGH | Passwords And Secrets - Generic Password | 6 |
| HIGH | Passwords And Secrets - Password in URL | 2 |
| HIGH | Passwords And Secrets - Generic Secret | 1 |
| LOW | Unpinned Package Version | 1 |

Only four queries fired, so that is the whole list rather than a top five. Nine of the ten findings are the same class — plaintext credentials in `inventory.ini` (`ansible_password`, `ansible_ssh_pass`, `ansible_become_password`) and in the playbooks.

### One finding in each direction

**KICS found, Checkov did not: `RDS DB Instance Publicly Accessible` (CRITICAL), `pulumi/Pulumi-vulnerable.yaml:104`.**

```
'resources.unencryptedDb.properties.publiclyAccessible' is set to 'true'
```

Pointing Checkov at the same directory produces exactly one finding — `CKV_SECRET_6`, a base64 high-entropy string at `Pulumi-vulnerable.yaml:19` — and nothing else. Checkov 3.x has **no Pulumi framework**: it wants rendered state, not a Pulumi program, so `__main__.py` is not parsed as infrastructure at all and the YAML is only reached by the generic secrets scanner, which pattern-matches strings without understanding that `unencryptedDb` is an RDS instance. KICS has a Pulumi parser and a resource model, so it can ask "is this an RDS resource with `publiclyAccessible: true`". This is a parsing-capability gap, not a policy-coverage gap.

**Checkov found, KICS did not: `CKV2_AWS_5`, "Ensure that Security Groups are attached to another resource"** — firing on `aws_security_group.allow_all` and `aws_security_group.ssh_open`.

I ran KICS against the same Terraform directory for a fair comparison (202 findings to Checkov's 80, so KICS is not simply weaker here) and it has no equivalent query; grepping its query names for `attach`/`unused` returns only `IAM Policies Attached To User`. The reason is the kind of question being asked: every KICS query in this run evaluates **one resource in isolation**, while `CKV2_AWS_5` is a graph check — it has to build the dependency graph across files and ask whether any *other* resource references this security group's id. All six `CKV2_*` checks that fired here are of that shape (S3 public-access blocks, lifecycle configurations, RDS query logging), and they are the class KICS structurally cannot express.

### What runs in the pipeline, and the gap

Two scanners, three formats, two verdicts — and the disagreement is mostly about what each tool can *read*, not about what either believes is dangerous. So I would not pick a winner; I would map tools to formats and make that mapping explicit. Checkov runs on Terraform, where its graph checks and its `secrets` framework earn their place; KICS runs on Ansible and Pulumi, where Checkov is nearly blind (one secrets hit on a whole Pulumi program). Both run on every PR that touches `infra/`, both exit non-zero on findings, and that exit code is the gate.

For the gap itself, two things. First, write it down: a short `SCANNER-COVERAGE.md` saying which format each tool actually parses, so that "the pipeline is green" is never mistaken for "this code was examined" — the Pulumi program here would have sailed through a Checkov-only pipeline with one irrelevant finding. Second, close what the tools cannot reach with policies of my own, which is what the bonus does: a rule that neither vendor ships, running in the tool that already understands the format.

## Bonus

### The policy

`labs/lab6/policies/my-custom-policy.yaml`:

```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure every RDS instance carries a data_classification tag"
  category: "GENERAL_SECURITY"
  severity: "HIGH"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      value:
        - "aws_db_instance"
      operator: "within"
    - cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "tags.data_classification"
      operator: "exists"
```

**In plain English: every RDS database must declare what class of data it holds, as a `data_classification` tag.** The `filter` condition narrows the policy to `aws_db_instance`; the `attribute` condition with `operator: exists` is what actually passes or fails.

### It fires

```bash
$ checkov -d labs/lab6/vulnerable-iac/terraform \
    --external-checks-dir labs/lab6/policies \
    --output json --output-file-path labs/lab6/results/checkov-custom/

$ jq '[.[].results.failed_checks[]? | select(.check_id | test("CUSTOM"))
      | {check_id, resource, file_path, file_line_range}]' \
    labs/lab6/results/checkov-custom/results_json.json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf",
    "file_line_range": [5, 37]
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf",
    "file_line_range": [40, 69]
  }
]
```

Both RDS instances in the sample carry only a `Name` tag — `database.tf:33` even has the comment `# Missing required tags` — so both fail.

### The change that makes it pass, confirmed

```hcl
  tags = {
    Name                = "Unencrypted Database"
    data_classification = "restricted"
  }
```

and the same for `weak_db` with `data_classification = "internal"`. Re-running against the patched copy:

```bash
$ jq '[.[].results.failed_checks[]? | select(.check_id | test("CUSTOM"))] | length'
0
$ jq -r '[.[].results.passed_checks[]? | select(.check_id | test("CUSTOM")) | "\(.check_id)\t\(.resource)"] | .[]'
CKV2_CUSTOM_1	aws_db_instance.unencrypted_db
CKV2_CUSTOM_1	aws_db_instance.weak_db
```

Two failures become two passes. (The edit was made on a copy under `/tmp`; the sample stays broken, as the lab instructs.)

### Why this rule is mine and not Checkov's

Checkov cannot ship this because the tag name, the allowed values and the consequence are all internal inventions — `data_classification` is not an AWS concept, and a vendor has no way to know that my organisation's values are `public` / `internal` / `restricted` rather than someone else's four-tier scheme. Generic tooling can only check things that are true everywhere, which is why both scanners cover encryption and public access and neither covers governance.

Concretely, this is the rule that comes out of an incident like the one this repository is full of: `aws_db_instance.unencrypted_db` is public and unencrypted, and the question that actually decides whether that is an inconvenience or a breach notification — *what was in it* — is answerable by nobody, because nothing in the code says. A retention-and-classification audit finding ("data stores must be classifiable without asking the team that built them") turns into exactly this policy: one required tag, enforced at the point where the database is created rather than at the point where somebody has to write an incident report about it.
