# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-IaC%20Security-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Checkov%20%2B%20KICS-informational)

> **Goal:** Scan deliberately broken infrastructure code with two scanners that disagree by design, triage the findings by leverage rather than by count, and write a policy neither tool ships.
> **Deliverable:** A PR from `feature/lab6` with `submissions/lab6.md` and, for the bonus, your policy file. Submit the PR link via Moodle.
> **Builds on:** the triage habits from Lab 5. **Used by:** Lab 10 imports these findings.

## Setup

- Docker, Python 3.10+, `jq`.
- Checkov 3.3.x: `pip install checkov` (on Debian and Ubuntu add `--break-system-packages`, or use `pipx`).

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab6
```

```bash
checkov --version && docker --version
mkdir -p labs/lab6/results
ls labs/lab6/vulnerable-iac/
```

`labs/lab6/vulnerable-iac/` holds broken-on-purpose Terraform, Pulumi and Ansible, with a `README.md` naming the vulnerability class each file targets. Read the code, do not fix it.

## Task 1 — Checkov on Terraform (6 pts)

### 6.1 Scan

<!-- verify:nonzero-ok checkov exits 1 when it finds anything -->
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

Checkov exits non-zero when it finds anything, which it will. Expect roughly 78 failed checks in the `terraform` framework and a couple more from `secrets`, which runs alongside it.

### 6.2 Triage by leverage

```bash
jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' \
  labs/lab6/results/checkov-terraform/results_json.json

jq '[.[].results.failed_checks[]?.check_id]
    | group_by(.) | map({rule: .[0], count: length})
    | sort_by(-.count) | .[:5]' \
  labs/lab6/results/checkov-terraform/results_json.json
```

Two things about that output. The file is a JSON **array**, one object per framework, because Checkov ran `terraform` and `secrets` together: a filter starting `.results.failed_checks` fails with "Cannot index array with string". And open-source Checkov leaves `severity` null on every finding, since severities are a paid feature. With no severity to sort on, frequency is your triage signal: the rule that fires most often is usually one shared module away from being fixed everywhere.

**Submit** in `submissions/lab6.md`, section `## Task 1`:

- Passed and failed per framework.
- The top five rules by frequency, each with a one-line description of what it checks. Look the IDs up rather than guessing.
- Pick the single change that would clear the most findings at once. Name the file and the resource, say how many findings it clears, and explain why fixing it once is not the same as fixing it five times.
- Two or three sentences: `severity` is null on every one of these findings. What would you sort by in a real backlog, and what does that tell you about buying severity from a vendor?

## Task 2 — KICS on Ansible and Pulumi (4 pts)

Optional. Skipping it does not affect later labs.

Checkov 3.x has no Pulumi framework: it wants rendered state, not Python. KICS parses Pulumi and Ansible directly. This is the point of the task, not an accident of tooling.

### 6.3 Scan both

<!-- produces: labs/lab6/results/kics-ansible/results.json for lab 10 -->
<!-- verify:nonzero-ok kics exits non-zero when it finds anything -->
```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ --report-formats json,sarif
```

<!-- produces: labs/lab6/results/kics-pulumi/results.json for lab 10 -->
<!-- verify:nonzero-ok kics exits non-zero when it finds anything -->
```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ --report-formats json,sarif
```

Run them one at a time: KICS exits non-zero on findings, so chaining both in one script with `set -e` stops after the first.

Without `--user` the container writes its reports as root and you cannot delete them afterwards without Docker's help.

### 6.4 Read the reports

```bash
for scan in kics-ansible kics-pulumi; do
  echo "== $scan =="
  jq -c '[.queries[].severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab6/results/$scan/results.json
done

jq '[.queries[] | {query: .query_name, severity, files: (.files | length)}]
    | sort_by(-.files) | .[:5]' labs/lab6/results/kics-ansible/results.json
```

KICS reports one object with a `.queries` array and it does assign severities, so here you can triage by severity. Watch the arithmetic: the terminal summary counts individual findings, the `.queries` array counts distinct queries, and the two numbers are different.

**Submit**, section `## Task 2`:

- Severity breakdowns for both scans, and a note on whether your numbers are queries or findings.
- The top five Ansible queries by number of files touched.
- One finding KICS reports that Checkov did not, and one class Checkov covers that KICS did not. Explain each in terms of what the tool can parse.
- Three or four sentences: two scanners, three formats, two different verdicts. How would you decide what runs in your pipeline, and what would you do about the gap between them?

## Bonus — Write the policy nobody ships (2 pts)

Both tools cover generic cloud hygiene. Neither knows your organisation's rules.

### 6.5 Pick a rule and write it

Something specific and checkable, for example: every RDS instance must enable IAM database authentication; every S3 bucket must carry a lifecycle configuration; every log group must expire within a year.

```yaml
# labs/lab6/policies/my-custom-policy.yaml
# YOUR TASK: a custom Checkov policy in YAML
# Required keys:
#   metadata:   id (CKV_* for single-resource, CKV2_* for graph), name, category, severity
#   definition: a cond_type tree, combined with and / or / not
# Hints:
#   - the schema, with worked examples:
#     https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html
#   - a `filter` condition on resource_type narrows what the policy applies to;
#     an `attribute` condition is what actually passes or fails
#   - write it against a resource that exists in the sample, or it will never fire
```

### 6.6 Run it and prove it fires

<!-- verify:skip needs the policy the student writes in 6.5 -->
```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output json --output-file-path labs/lab6/results/checkov-custom/

jq '[.[].results.failed_checks[]? | select(.check_id | startswith("CKV"))
     | select(.check_id | test("CUSTOM")) | {check_id, resource, file_path}]' \
  labs/lab6/results/checkov-custom/results_json.json
```

**Submit**, section `## Bonus`:

- The policy file and the rule in one sentence of plain English.
- The JSON showing it firing, with the resources it caught.
- The change to the Terraform that would make it pass, and confirmation that it then does.
- Two or three sentences: what makes this rule yours rather than something Checkov should ship for everyone? Name the incident, audit finding or internal standard it comes from.

## Submit

<!-- verify:skip student fork files -->
```bash
git add submissions/lab6.md
git add labs/lab6/policies/my-custom-policy.yaml   # bonus only
git commit -m "feat(lab6): checkov and kics findings, custom policy"
git push -u origin feature/lab6
```

Do not commit `labs/lab6/results/`.

## Acceptance criteria

- Task 1 (6): scan completed; per-framework table matches the JSON; five rules with real descriptions; the highest-leverage fix names a file, a resource and a count; the severity answer engages with the null column.
- Task 2 (4): both KICS scans completed; severity tables for each, labelled as queries or findings; top-five Ansible queries; one finding in each direction between the tools, explained by parsing ability; a pipeline decision with a plan for the gap.
- Bonus (2): the policy file exists, is valid YAML, and fires against a real resource in the sample; the JSON evidence is included; the passing change is stated and confirmed.

## Common pitfalls

- `results_json.json` is an array, one entry per framework. `.results.failed_checks[]` errors with "Cannot index array with string"; use `.[].results.failed_checks[]?`.
- Open-source Checkov has no severities. Every `severity` field is null, and no flag turns them on.
- KICS in Docker writes as root unless you pass `--user "$(id -u):$(id -g)"`. If you already have root-owned reports, remove them with a container rather than sudo.
- KICS's terminal totals count findings; the `.queries` array counts queries. Say which you are reporting.
- A custom policy that names a resource type absent from the sample runs happily and finds nothing. Check the sample first.
- `checkov` and `kics` both exit non-zero on findings. In CI that is the point; in a shell script with `set -e` it stops your script.

## Resources

- [Checkov policy index](https://www.checkov.io/5.Policy%20Index/all.html) — look up what a `CKV_AWS_*` id means
- [Checkov custom YAML policies](https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html)
- [KICS queries](https://docs.kics.io/latest/queries/all-queries/)
- [AWS security best practices for IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
