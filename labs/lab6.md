# Lab 6 — IaC Security: Checkov + KICS + a Custom Policy

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-IaC%20Security-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Checkov%20%2B%20KICS-informational)

> **Goal:** Scan vulnerable Terraform with Checkov, scan vulnerable Ansible + Pulumi with KICS, then (bonus) write a custom Checkov policy for a project-specific rule.
> **Deliverable:** A PR from `feature/lab6` with `submissions/lab6.md` (findings tables + analysis) and (bonus) a custom Checkov policy file. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- **Checkov 3.x** on Terraform (~2,500 built-in policies, including 800+ graph-based) — Lecture 6
- **KICS** on Ansible + Pulumi (~2,400 Rego-based queries) — Lecture 6
- **Triage at the module level** (Lecture 6 slide 17 — one fix at module level closes many findings)
- (Bonus) Writing a **custom Checkov policy** in YAML for a project-specific rule

> Plumbing in `labs/lab6/vulnerable-iac/` contains deliberately misconfigured IaC across all three formats. Don't fix the files — analyze them.

---

## Project State

**You should have from Labs 1-5:**
- A working `feature/labN` PR workflow + signed commits + pre-commit secret scanning
- A general feel for "static text → security findings" from Lab 5's SAST work

**This lab adds:**
- Checkov + KICS scan reports across three IaC formats
- A custom Checkov policy in your fork (the bonus)

---

## Setup

You need:
- **Docker** (for KICS, optionally Checkov)
- **Python 3.10+** + **pip**
- **`jq`**

```bash
git switch main && git pull
git switch -c feature/lab6

# Install Checkov (course pins 3.x)
pip install checkov

# Verify
checkov --version
docker --version

# Examine the vulnerable IaC (don't fix it — that's the lecture exercise)
ls labs/lab6/vulnerable-iac/{terraform,pulumi,ansible}

mkdir -p labs/lab6/results
```

> **Plumbing provided** (in `labs/lab6/vulnerable-iac/`):
> - `terraform/` — deliberately misconfigured AWS resources (IAM, RDS, DynamoDB, security groups)
> - `pulumi/` — deliberately misconfigured AWS resources (Python + YAML)
> - `ansible/` — deliberately misconfigured Linux hardening playbook
> - `README.md` — documents the vulnerability classes each file targets

---

## Task 1 — Checkov on Terraform (6 pts)

**Objective:** Scan the Terraform sample with Checkov; identify findings; group by module/rule frequency to find the highest-leverage fixes.

> **Why Terraform-only for Checkov?** Pulumi is real Python; Checkov 3.x does not have a `pulumi` framework directly (it expects rendered state via `pulumi preview --json` OR the SAST-Python framework). To keep the lab's tool surface manageable, **Pulumi is scanned with KICS** in Task 2 (which natively understands Pulumi source). You'll see the trade-off live: tool ecosystems specialize differently.

### 6.1: Scan Terraform

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

### 6.2: Triage by rule frequency

Checkov scans the directory with several frameworks at once (`terraform` and `secrets`), so
`results_json.json` is a JSON **array** — one object per framework. Open-source Checkov doesn't
assign severities (that's a Prisma Cloud feature), so you triage by **how often each rule fires**:
the most frequent rule is the one a single module-level fix can clear in bulk (Lecture 6 slide 17).

```bash
# Top 5 rule IDs by count — the highest-leverage fixes
jq '[.[].results.failed_checks[]?.check_id]
    | group_by(.) | map({rule: .[0], count: length})
    | sort_by(-.count) | .[:5]' \
  labs/lab6/results/checkov-terraform/results_json.json

# Passed / failed per framework
jq 'map({framework: .check_type, passed: .summary.passed, failed: .summary.failed})' \
  labs/lab6/results/checkov-terraform/results_json.json
```

### 6.3: Document in `submissions/lab6.md`

```markdown
# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | <n> | <n> |
| secrets | <n> | <n> |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| <CKV_AWS_*> | <n> | <1-line description> |

### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the shared IAM policy dropped its `Resource: "*"`
wildcard, the CKV_AWS_355/289/290 findings on every policy would collapse into one fix.")
```

---

## Task 2 — KICS on Ansible + Pulumi (4 pts)

> ⏭️ Optional. Skipping won't affect future labs.

**Objective:** Run KICS against the Ansible playbook AND the Pulumi source; see how Rego-based queries surface different findings than Checkov, and demonstrate KICS's broader format coverage.

### 6.4: Run KICS on Ansible

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ \
       -o /path/results/kics-ansible/ \
       --report-formats json,sarif
```

### 6.4b: Run KICS on Pulumi (natively supported)

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/pulumi/ \
       -o /path/results/kics-pulumi/ \
       --report-formats json,sarif
```

### 6.5: Analyze

Each scan wrote its own `results.json` (`kics-ansible/` and `kics-pulumi/`). KICS reports a single
JSON object with a `.queries` array, and — unlike Checkov — it assigns severities, so here you can
triage by severity as well as frequency.

```bash
# Severity breakdown — for each scan
for scan in kics-ansible kics-pulumi; do
  echo "== $scan =="
  jq '[.queries[].severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab6/results/$scan/results.json
done

# Top queries by impact (Ansible shown; repeat for kics-pulumi)
jq '[.queries[] | {query: .query_name, severity, count: (.files | length)}]
    | sort_by(-.count) | .[:5]' \
  labs/lab6/results/kics-ansible/results.json
```

### 6.6: Document in `submissions/lab6.md`

```markdown
## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | <n> |
| MEDIUM | <n> |
| LOW | <n> |
| INFO | <n> |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | <n> |
| HIGH | <n> |
| MEDIUM | <n> |
| LOW | <n> |
| INFO | <n> |

### Top 5 KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| <name> | <sev> | <n> |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample
- One thing KICS did **better** for the Ansible sample
- (Optional) An example of a finding only ONE of them caught for the same resource type
```

---

## Bonus Task — Custom Checkov Policy (2 pts)

> 🌟 **Genuinely challenging.** Writing custom policies is how Policy-as-Code scales beyond what vendors ship.

**Objective:** Write a custom Checkov policy in YAML (graph-based or single-resource — your choice). Apply it to the vulnerable Terraform sample and demonstrate it fires.

### B.1: Pick a rule

Pick a project-specific check that's NOT already in Checkov's built-in catalog. Examples:

- "Every S3 bucket must have a `lifecycle_configuration` block"
- "Every RDS instance must have `iam_database_authentication_enabled = true`"
- "Every IAM policy attached to a Lambda must not have `Action: *` or `Resource: *`"
- "Every CloudWatch log group must have `retention_in_days <= 365`"

### B.2: Write the policy

```yaml
# labs/lab6/policies/my-custom-policy.yaml
# YOUR TASK: Custom Checkov policy
# Required structure:
# metadata:
#   id: CKV2_CUSTOM_1     # CKV_* for single-resource, CKV2_* for graph (cross-resource)
#   name: <descriptive>
#   category: <one of Checkov's standard categories>
#   severity: HIGH | MEDIUM | LOW
# definition:
#   and:                  # or: or, not — Boolean composition
#     - cond_type: filter | attribute | connection
#       attribute: <field-path>
#       value: <expected>
#       operator: equals | within | exists | greater_than | ...
#
# See Checkov docs for the full schema:
# https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html
```

### B.3: Run Checkov with the custom policy

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-custom/
```

### B.4: Verify your policy fires

```bash
# Look for your custom rule ID among the failed checks
jq '[.[].results.failed_checks[]?]
    | map(select(.check_id | startswith("CKV2_CUSTOM_")))' \
  labs/lab6/results/checkov-custom/results_json.json
```

### B.5: Document in `submissions/lab6.md`

````markdown
## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
<paste>
```

### Rule fires
Output of the B.4 jq (must show ≥1 failed check whose `check_id` starts with `CKV2_CUSTOM_`):
```
<paste — must show ≥1 failed check with YOUR rule ID>
```

### Why this rule matters
2-3 sentences: what real-world incident or compliance requirement does your custom policy address?
(References to specific incidents or NIST/CIS controls strengthen the answer.)
````

---

## How to Submit

```bash
git add labs/lab6/policies/my-custom-policy.yaml    # Bonus only
git add submissions/lab6.md
git commit -m "feat(lab6): Checkov + KICS scans + custom policy"
git push -u origin feature/lab6
```

> **Do NOT commit** `labs/lab6/results/` — scanner output is regeneratable. Submission paste-ins are the evidence.

PR checklist body:

```text
- [x] Task 1 — Checkov on Terraform with top-5 rules and module-leverage analysis
- [ ] Task 2 — KICS on Ansible + Pulumi with Checkov-vs-KICS comparison
- [ ] Bonus — Custom Checkov policy demonstrably firing on the vulnerable sample
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Checkov scan completes on the Terraform sample
- ✅ Passed/failed table matches actual JSON output (no placeholders)
- ✅ Top-5 rules table populated with real CKV_AWS_* IDs + descriptions
- ✅ Module-leverage analysis identifies ONE concrete fix with multi-finding impact

### Task 2 (4 pts)
- ✅ KICS scan completes on both the Ansible and Pulumi samples
- ✅ Ansible + Pulumi severity tables and the Ansible top-5 table use real values
- ✅ Checkov-vs-KICS comparison has substantive 2-3-sentence answers per question

### Bonus Task (2 pts)
- ✅ Custom policy file exists at `labs/lab6/policies/my-custom-policy.yaml`
- ✅ Policy has valid YAML schema (Checkov accepts it without parse errors)
- ✅ Policy fires on ≥1 resource in the vulnerable Terraform sample (proof in submission)
- ✅ "Why this rule matters" answer references a real incident or compliance control

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Checkov | **6** | Terraform scan + top-5 rules + module-leverage analysis |
| **Task 2** — KICS | **4** | Ansible + Pulumi scans + Checkov-vs-KICS comparison with concrete examples |
| **Bonus Task** — Custom policy | **2** | Valid YAML schema + actually firing on vulnerable resource + business justification |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Checkov rule catalog](https://www.checkov.io/5.Policy%20Index/terraform.html) — Every CKV_AWS_*/CKV_GCP_*/CKV_AZURE_* with description
- [Checkov custom policies (YAML)](https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html) — Schema for the bonus
- [Checkov graph policies (CKV2_*)](https://www.checkov.io/3.Custom%20Policies/Graph%20YAML%20Custom%20Policies.html) — Cross-resource rules
- [KICS queries catalog](https://docs.kics.io/latest/queries/all-queries/) — All 2,400+ Rego queries
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — Source of most rules (mentioned in Lecture 6)

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **Checkov scans 0 files** — `-d` expects a DIRECTORY (the whole `terraform/` folder); `-f` expects a single file. This lab uses `-d`.
- 🚨 **KICS finds 0 issues on Ansible** — point `-p` at the playbook directory (`-p .../ansible/`). Run `kics list-platforms` to confirm Ansible is supported (it is).
- 🚨 **Custom policy doesn't fire** — usually an `attribute` path typo. Test on a known-failing resource first, and always include a `severity:` field; Checkov is strict about required fields.
- 🚨 **`CKV_CUSTOM_*` ID collides with a built-in** — use `CKV2_CUSTOM_1+`; the `2` prefix marks graph rules and stays clear of the built-in sequence.
- 💡 **Read the plumbing README** — `labs/lab6/vulnerable-iac/README.md` lists the vulnerability classes each file targets, so you can sanity-check that your scans found what they should.

</details>

<details>
<summary>🪜 Looking ahead</summary>

- **Lab 7** (Container Security) — uses Trivy `config` mode against Dockerfiles + K8s manifests; same SARIF pattern as Checkov here
- **Lab 9** (Falco + Conftest) — Conftest uses **Rego** (same as KICS); your KICS reading today smooths Lab 9's Rego learning curve
- **Lab 10** (DefectDojo) — imports Checkov and KICS JSON; you'll see how they dedupe at the program level

</details>
