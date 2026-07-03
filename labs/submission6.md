# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

> Target code: `labs/lab6/vulnerable-iac/` (Terraform, Pulumi, Ansible)
> Tools: **tfsec**, **Checkov**, **Terrascan** (Terraform); **KICS / Checkmarx** (Pulumi + Ansible)
> All scanners run as pinned Docker images from the project root.

---

## Summary of Results

| Framework | Tool | Findings |
|-----------|------|---------:|
| Terraform | tfsec | **53** |
| Terraform | Checkov | **78** (failed checks; 49 passed) |
| Terraform | Terrascan | **22** (167 policies validated) |
| Pulumi (YAML) | KICS | **6** |
| Ansible | KICS | **10** |

Raw evidence: `labs/lab6/analysis/*.json`, `*-report.txt`, `kics-*.html`, plus the
derived summaries `terraform-comparison.txt`, `pulumi-analysis.txt`,
`ansible-analysis.txt`, and `tool-comparison.txt`.

---

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform Tool Comparison (tfsec vs Checkov vs Terrascan)

Severity distribution actually observed:

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW |
|------|------:|---------:|-----:|-------:|----:|
| tfsec | 53 | 9 | 25 | 11 | 8 |
| Checkov | 78 | — (uses pass/fail, not CVSS severity) | | | |
| Terrascan | 22 | 0 | 14 | 8 | 0 |

**Why the counts differ so much (53 / 78 / 22 over the *same* 16 resources):**

- **Checkov (78)** is the most aggressive. It ships 1000+ policies and flags
  *governance/best-practice* items the others ignore — RDS Multi-AZ, enhanced
  monitoring, deletion protection, cross-region replication, IAM policy
  constraints (`CKV_AWS_355`, `CKV_AWS_289`, `CKV_AWS_290`). High recall, but
  more noise.
- **tfsec (53)** is Terraform-native and CVSS-graded. It concentrates on
  exploitable misconfig: IAM wildcards (`aws-iam-no-policy-wildcards`, 9 hits),
  public security-group ingress/egress, S3 public access + encryption. Clear
  rule IDs (`AVD-AWS-xxxx`) and code snippets — the best signal-to-noise.
- **Terrascan (22)** is the most conservative. It is OPA/Rego-based and maps to
  compliance benchmarks, so it reports fewer, higher-confidence violations
  (`rdsPubliclyAccessible`, `portWideOpenToPublic`, `s3Versioning`). Lowest
  false-positive rate, but misses best-practice items.

**Overlap:** all three independently flag the headline issues — public RDS,
0.0.0.0/0 security groups, unencrypted/public S3, IAM wildcards. The *extra*
findings in Checkov are mostly governance controls; the *extra* findings in
tfsec are granular per-rule splits (e.g. block-public-acls vs ignore-public-acls
counted separately).

### 1.2 Pulumi Security Analysis (KICS)

KICS scanned `Pulumi-vulnerable.yaml` and reported **6** findings:

| Severity | Query | Location |
|----------|-------|----------|
| CRITICAL | RDS DB Instance Publicly Accessible | `Pulumi-vulnerable.yaml:104` (`publiclyAccessible: true`) |
| HIGH | DynamoDB Table Not Encrypted | `Pulumi-vulnerable.yaml:205` (`serverSideEncryption` missing) |
| HIGH | Passwords And Secrets – Generic Password | `Pulumi-vulnerable.yaml:16` (hardcoded secret) |
| MEDIUM | EC2 Instance Monitoring Disabled | `Pulumi-vulnerable.yaml` |
| INFO | DynamoDB Point-In-Time Recovery Disabled | `Pulumi-vulnerable.yaml` |
| INFO | EC2 Not EBS Optimized | `Pulumi-vulnerable.yaml` |

### 1.3 Terraform vs Pulumi

The same logical infrastructure expressed two ways produced very different
finding counts: **53–78 (Terraform)** vs **6 (Pulumi)**. This is *not* because
the Pulumi code is more secure — it is a tooling-coverage gap:

- The Pulumi project contains a Python program (`__main__.py`, ~21 intentional
  issues) **and** a YAML manifest. KICS only parses the **declarative YAML**;
  the imperative Python is invisible to static IaC scanners (it would need code
  SAST instead). The 6 findings come entirely from the YAML.
- Terraform's HCL is fully declarative, so the scanners can resolve every
  resource/attribute — hence near-complete coverage.

**Takeaway:** programmatic IaC (Pulumi Python, CDK) is harder to scan than
declarative IaC (HCL, Pulumi YAML). Where security scanning matters, prefer the
declarative form or add language-level SAST.

### 1.4 KICS Pulumi Support

KICS auto-detected the Pulumi platform from the YAML and applied AWS-resource
queries (RDS, DynamoDB, EC2) plus its generic secrets query. The query catalog
is real and useful, but narrower than the Terraform tools' AWS coverage — it
caught the public RDS and missing encryption, but did not split governance
controls the way Checkov does.

### 1.5 Critical Findings (Terraform + Pulumi)

1. **Public RDS instance** — `terraform/database.tf:17` (tfsec `AVD-AWS-0082`),
   also `Pulumi-vulnerable.yaml:104`. Database reachable from the internet.
2. **Security groups open to 0.0.0.0/0** — `terraform/security_groups.tf:15,41,49,75,83`
   (tfsec `AVD-AWS-0107`). Includes admin ports exposed to the world.
3. **IAM wildcard policies** — 9× `aws-iam-no-policy-wildcards` in `terraform/iam.tf`.
   `Action:"*"`/`Resource:"*"` enables privilege escalation.
4. **Hardcoded secrets** — KICS Generic-Password in `Pulumi-vulnerable.yaml:16`;
   Terraform `variables.tf` ships secrets as defaults.
5. **Unencrypted storage** — S3 without SSE/KMS (tfsec `aws-s3-enable-bucket-encryption`),
   RDS `storage_encrypted` unset, DynamoDB `serverSideEncryption` missing (KICS).

---

## Task 2 — Ansible Security Scanning with KICS

KICS reported **10** findings (9 HIGH, 1 LOW):

| Severity | Query | Affected items |
|----------|-------|---------------:|
| HIGH | Passwords And Secrets – Generic Password | 6 |
| HIGH | Passwords And Secrets – Generic Secret | 1 |
| HIGH | Passwords And Secrets – Password in URL | 2 |
| LOW | Unpinned Package Version | 1 |

### Best-Practice Violations (impact + fix)

1. **Hardcoded credentials in playbooks/inventory** (9 of 10 findings).
   `deploy.yml`/`inventory.ini` carry plaintext passwords, secrets and
   credentials embedded in URLs. *Impact:* anyone with repo read access (or a
   leaked clone) gets production creds; they also land in git history and CI
   logs. *Fix:* move secrets to **Ansible Vault** (`ansible-vault encrypt`) or an
   external secrets manager, reference via vars, and add `no_log: true` to tasks
   that touch them.
2. **Secrets passed inside URLs** (`Password in URL`, 2×). Credentials in
   `http(s)://user:pass@host` get logged by proxies, shell history and `ps`.
   *Fix:* use module auth parameters (`url_username`/`url_password`) with vaulted
   values, never inline.
3. **Unpinned package version** (LOW). Installing without a pinned version yields
   non-reproducible, drift-prone deploys and can silently pull a compromised
   release. *Fix:* pin explicit versions (`name=nginx=1.24.*`) and update
   deliberately.

### KICS Ansible Query Types

KICS's Ansible catalog here is dominated by **secrets-management** detection
(generic password/secret, password-in-URL) plus **best-practice** checks
(version pinning). It auto-detected the playbooks by content and did not need
the `ansible-lint` toolchain installed locally — a benefit of the
container-based, multi-framework approach.

### Remediation Steps

```yaml
# Before (deploy.yml) — flagged HIGH
db_password: "SuperSecret123"

# After
db_password: "{{ vault_db_password }}"   # stored in vaulted group_vars
# task using it:
- name: configure db
  template: { src: db.conf.j2, dest: /etc/db.conf }
  no_log: true
```

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (6 Pulumi + 10 Ansible) |
| **Scan Speed** | Fast | Medium | Fast | Medium |
| **False Positives** | Low | Medium | Low | Low–Med |
| **Report Quality** | ⭐⭐⭐⭐ (rule ID + code + remediation) | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ (JSON+HTML) |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ (root-owned output dir) |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform only | Multiple (TF, CFN, K8s, Docker, Helm…) | Multiple | Multiple (TF, Pulumi, Ansible, K8s, CFN…) |
| **Output Formats** | JSON, text, SARIF, CSV, JUnit | JSON, CLI, SARIF, JUnit | JSON, human, YAML, SARIF | JSON, HTML, SARIF, console |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strengths** | Best Terraform signal-to-noise, clear AVD rules | Widest policy library, governance/compliance | Compliance/benchmark mapping (OPA) | One tool for Pulumi + Ansible + more |

### 3.2 Vulnerability Category Analysis

Derived from reviewing each tool's JSON/HTML report (✅ strong, ◑ partial, ✗ none):

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|-------------------|:----:|:------:|:--------:|:------------:|:-------------:|----------|
| Encryption | ✅ (S3/RDS) | ✅ | ✅ | ✅ (DynamoDB) | N/A | tfsec/Checkov |
| Network Security | ✅ (SG ingress/egress) | ✅ | ✅ (port rules) | ◑ | N/A | tfsec |
| Secrets Management | ◑ | ◑ | ◑ | ✅ | ✅ (9/10) | KICS |
| IAM / Permissions | ✅ (9 wildcards) | ✅ | ◑ | ✗ | N/A | tfsec/Checkov |
| Access Control (public exposure) | ✅ | ✅ | ✅ (public RDS) | ✅ (public RDS) | N/A | all |
| Compliance / Best Practice | ◑ | ✅ (most) | ✅ (benchmarks) | ◑ | ◑ | Checkov |

### 3.3 Top 5 Critical Findings with Remediation

1. **Publicly accessible RDS** (`database.tf:17`, `Pulumi-vulnerable.yaml:104`)
   ```hcl
   resource "aws_db_instance" "main" {
     publicly_accessible = false          # was true
     storage_encrypted   = true           # add encryption
   }
   ```
2. **0.0.0.0/0 ingress on admin ports** (`security_groups.tf:15,41,49,75,83`)
   ```hcl
   ingress { cidr_blocks = ["10.0.0.0/16"] }   # restrict to VPC/bastion, not "0.0.0.0/0"
   ```
3. **IAM wildcard policy** (`iam.tf`, 9 hits)
   ```hcl
   statement {
     actions   = ["s3:GetObject"]               # no "*"
     resources = ["arn:aws:s3:::app-bucket/*"]  # no "*"
   }
   ```
4. **Hardcoded secrets** (`variables.tf`, `Pulumi-vulnerable.yaml:16`, Ansible)
   ```hcl
   # pull from a secrets store instead of a default value
   data "aws_secretsmanager_secret_version" "db" { secret_id = "prod/db" }
   ```
5. **Unencrypted S3 / DynamoDB**
   ```hcl
   resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
     bucket = aws_s3_bucket.b.id
     rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
   }
   ```

### 3.4 Tool Selection Guide

- **Pre-commit / fast PR gate:** **tfsec** — fastest, lowest noise, Terraform-native.
- **Authoritative CI gate / multi-framework:** **Checkov** — broadest coverage,
  governance + compliance, fails the build on policy violations.
- **Compliance reporting (PCI/HIPAA/CIS):** **Terrascan** — benchmark mapping.
- **Pulumi & Ansible (and mixed estates):** **KICS** — single tool, first-class
  Pulumi YAML + Ansible queries, JSON/HTML/SARIF output.

### 3.5 Lessons Learned

- **Finding count ≠ security.** Pulumi's 6 vs Terraform's 78 reflects scanner
  coverage of imperative code, not relative safety. Always know *what the tool
  can and cannot parse*.
- **Run more than one tool.** Each surfaced something another downplayed
  (Checkov's governance set, Terrascan's compliance view, tfsec's clean
  exploitable subset). Union ≫ any single tool.
- **Operational gotcha:** KICS writes its report directory as **root** (the
  container runs as root). `mv` of those files failed with *Permission denied*;
  I worked around it by `cp`-ing the world-readable reports into `analysis/`
  and removing the root-owned dir via a throwaway `alpine` container (instead of
  the lab's `sudo mv`, to avoid host privilege escalation).
- Non-zero exit codes (tfsec=1, KICS=50/60, Terrascan=3) are **expected** when
  findings exist — handle with `|| true` so the JSON is still captured.

### 3.6 CI/CD Integration Strategy

1. **Pre-commit hook:** tfsec on changed `.tf` (seconds, blocks obvious issues).
2. **PR pipeline:** Checkov (Terraform + K8s/Docker) **and** KICS (Pulumi/Ansible),
   both emitting **SARIF** → GitHub code-scanning annotations. Fail on HIGH/CRITICAL.
3. **Nightly / pre-release:** Terrascan compliance scan → audit report.
4. **Policy-as-code:** keep suppressions in-repo with justifications; track
   remediation SLAs (CRITICAL ≤ 7 days, HIGH ≤ 30 days).

**Justification:** layering a fast local gate, a high-recall PR gate, and a
compliance sweep balances developer speed against coverage — no single tool
gives both low noise *and* full breadth, so the pipeline composes them by stage.

---

## Appendix — Commands & Environment

- Run from repo root; scanners mounted `labs/lab6/vulnerable-iac/<fw>` read-only into the container.
- Images: `aquasec/tfsec:latest`, `bridgecrew/checkov:3.3.2`, `tenable/terrascan:latest`, `checkmarx/kics:latest`.
- Outputs committed under `labs/lab6/analysis/`.
