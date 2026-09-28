# Lab 10 — Vulnerability Management: The Capstone

> **Environment note:** DefectDojo was cloned at tag `2.58.3` (confirmed with `git describe --tags` inside `labs/lab10/work/dd`) and started with `./docker/setEnv.sh release`. All six containers (`nginx`, `uwsgi`, `celeryworker`, `celerybeat`, `postgres`, `valkey`) came up healthy. The admin password was read from `docker compose logs initializer`.

## Task 1

**DefectDojo version:** `2.58.3` (pinned clone, confirmed via `git describe --tags`).

**Parser used for each file, with finding count:**

| Lab | File | Parser | Findings |
|---|---|---|---|
| 4 | `grype-from-sbom.json` | Anchore Grype | 181 |
| 4 | `trivy.json` | Trivy Scan | 175 |
| 5 | `semgrep.json` | Semgrep JSON Report | 27 |
| 5 | `auth-report.json` → converted to XML | ZAP Scan | 13 |
| 6 | `checkov-terraform/results_json.json` | Checkov Scan | 80 |
| 6 | `kics-ansible/results.json` | KICS Scan | 10 |
| 6 | `kics-pulumi/results.json` | KICS Scan | 6 |
| 7 | `trivy-image.json` | Trivy Scan | 76 |
| 7 | `trivy-k8s.json` | **Trivy Scan** (not Trivy Operator Scan — see below) | 77 |

**Total active findings: 645.**

**Two parser mismatches I had to work around, not covered by the lab's pitfalls list:**

1. **`run-imports.sh` failed on `auth-report.json` → `ZAP Scan` with `HTTP 400: "Internal error: Wrong file format, please use xml."`** I read DefectDojo's actual parser source (`dojo/tools/zap/parser.py:76-78`): it hard-checks `file.name.endswith(".xml")` and parses `<site><alerts><alertitem>` XML nodes. It does not accept ZAP's JSON report format at all, despite both being official ZAP output formats and despite the lab's own file/parser table pairing `auth-report.json` with `ZAP Scan`. I wrote a small conversion script (`labs/lab10/work/zap_json_to_xml.py`) that re-serializes the same alert data (title, description, riskcode, cweid, solution, reference, instances) from the JSON into the XML structure the parser expects, and imported the resulting `auth-report.xml` by hand. Same 13 findings, same severities — only the container format changed.

2. **`trivy-k8s.json` imported as `Trivy Operator Scan` (per the lab's table) produced 0 findings, silently.** I checked `dojo/tools/trivy_operator/parser.py`: it expects the trivy-operator Kubernetes CRD format, keyed on `metadata.labels` and `report.vulnerabilities` per resource — the output of the actual `trivy-operator` Kubernetes controller. Our `trivy-k8s.json` (from `trivy k8s ... --format json` in Lab 7) has top-level `ClusterName`/`Resources[].Results[].Vulnerabilities`, which is a *different*, plain-CLI JSON schema — the parser's `output_findings()` returns `[]` immediately because `metadata` is absent, with no error raised. I checked `dojo/tools/trivy/parser.py:176-230` and found it explicitly handles `cluster_name = data.get("ClusterName")` with a `Resources[].Results[]` walk — i.e. the plain `Trivy Scan` parser, not `Trivy Operator Scan`, is the correct one for this file. Re-importing as `Trivy Scan` produced 77 findings (74 verified vulnerabilities + misconfig entries), matching the 74 vulnerabilities I could independently count in the raw file with `jq`. I deleted the two empty/misrouted test records (ZAP-as-JSON and Trivy-Operator) so the instance only holds the correct nine tests.

**Active findings by severity:**

| Severity | Count |
|---|---|
| Critical | 45 |
| High | 309 |
| Medium | 227 |
| Low | 47 |
| Info | 17 |
| **Total** | **645** |

**Two duplicate titles:**

1. **`CVE-2015-9235 Jsonwebtoken 0.1.0`** — appears 3 times (finding IDs 261, 499, 589), in tests 2 (`Trivy Scan`, Lab 4's `trivy.json`), 8 (`Trivy Scan`, Lab 7's `trivy-image.json`), and 11 (`Trivy Scan`, Lab 7's `trivy-k8s.json`). I checked `component_name`, `component_version`, and `file_path` on all three — identical (`jsonwebtoken` 0.1.0, same `node_modules/express-jwt/node_modules/jsonwebtoken/package.json` path). **This is one underlying vulnerability counted three times**, because Labs 4 and 7 both scanned the same Juice Shop image (or the same running container derived from it) with the same tool at different points in the course. DefectDojo's `duplicate` flag reported `false` on all three — cross-test/cross-engagement deduplication isn't automatic in the way I imported these; it needs to be configured (dedupe algorithm) at the product level or the imports need to land in the same test.

2. **`CVE-2020-8203 lodash.set 4.3.2`** — same pattern: 3 occurrences (IDs 278, 510, 600), same component/version, same tests 2/8/11. Same conclusion: one real vulnerability, counted three times because three separate labs scanned overlapping targets. I decided this by comparing `component_name` + `component_version` + `file_path` across the duplicate-titled findings, not just the title string — the title alone (`CVE-xxxx Component Version`) is already specific enough here that a title match plus a component/path match is strong evidence of the same finding, not a coincidence.

Notably, **Grype and Trivy never produce title collisions with each other** even when flagging the exact same CVE in the exact same package (e.g. Grype: `CVE-2010-4756 in libc6:2.41-12+deb13u2`, Trivy: `CVE-2015-9235 Jsonwebtoken 0.1.0` — different title templates entirely). This means the 645-finding total almost certainly *undercounts* cross-tool duplication: DefectDojo's title-based view can't surface a Grype/Trivy pair on the same CVE, so the real number of distinct vulnerabilities is lower than 645, not higher.

**Which labs contributed findings I'd act on this week, and which contributed noise:**

Lab 5's authenticated ZAP scan and Semgrep results are the most actionable: the ZAP `SQL Injection` (High) and `Vulnerable JS Library` (High) alerts, and Semgrep's 13 ERROR-level findings, point at specific lines of Juice Shop's own source and request paths — these are real, fixable code defects, not third-party dependency noise. Lab 6's Checkov and KICS findings (80 + 10 + 6 = 96 findings, mostly Medium/High) are close to pure noise this week: they scan `labs/lab6/vulnerable-iac/`, a fixture deliberately built insecure for the exercise, not infrastructure that is actually deployed anywhere — "fix this week" doesn't apply to Terraform that was never going to be applied. Lab 7's `trivy-k8s.json` (77 findings) is largely duplicate noise on top of Lab 4's `trivy.json` (175 findings) and Lab 7's own `trivy-image.json` (76 findings) — all three are scanning the same base Juice Shop image, which is exactly what the duplicate-title analysis above shows. The dependency-scanner findings from Grype/Trivy (181 + 175 + 76 + 77 = 509 of the 645 total, i.e. 79%) are mostly known, pre-existing CVEs in OWASP Juice Shop's intentionally-vulnerable `node_modules` — real supply-chain risk in principle, but not something this week's triage should spend time on individually versus Lab 5's application-layer findings, which are unique, few, and directly traceable to exploitable behavior.

## Task 2

### SLA configuration

| Severity | Default (days) | Mine (days) | Why |
|---|---|---|---|
| Critical | 7 | **3** | A Critical finding (e.g. the SQLi ZAP found, or a Critical CVE with a known exploit) on a customer-facing app is the kind of thing that gets a CVE press cycle; 7 days is long enough for a second breach to happen while it sits in a backlog. 3 days matches "drop other work and patch it." |
| High | 30 | **14** | High findings are numerous here (309 active) and not all equally urgent, but 30 days is long enough that a High finding opened at the start of a sprint can slip two sprints. 14 days keeps it inside one sprint cycle. |
| Medium | 90 | **45** | Most of the 227 Medium findings are IaC/config hardening items (Checkov, missing security headers) that are real but not exploitable on their own. 90 days is closer to "never gets prioritized"; 45 forces it onto at least one planning cycle per quarter. |
| Low | 120 | **90** | Left closer to the default — Low findings (info disclosure headers, unpinned package versions) are genuinely low-urgency, but 120 days means a Low finding opened in January is still "on time" in May, which is too loose to mean anything as a deadline. |

Applied via `PATCH /api/v2/sla_configurations/1/`.

### Findings by severity and by source tool

| Tool (test) | Active | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|---|
| Anchore Grype (Lab 4) | 181 | 14 | 84 | 60 | 12 | 11 |
| Trivy Scan — SBOM image (Lab 4) | 175 | 10 | 66 | 68 | 31 | 0 |
| Semgrep JSON Report (Lab 5) | 27 | 0 | 13 | 14 | 0 | 0 |
| ZAP Scan (Lab 5, authenticated) | 13 | 0 | 2 | 4 | 3 | 4 |
| Checkov Scan (Lab 6) | 80 | 0 | 0 | 80 | 0 | 0 |
| KICS Scan — Ansible (Lab 6) | 10 | 0 | 9 | 0 | 1 | 0 |
| KICS Scan — Pulumi (Lab 6) | 6 | 1 | 2 | 1 | 0 | 2 |
| Trivy Scan — image (Lab 7) | 76 | 10 | 66 | 0 | 0 | 0 |
| Trivy Scan — k8s (Lab 7) | 77 | 10 | 67 | 0 | 0 | 0 |
| **Total** | **645** | **45** | **309** | **227** | **47** | **17** |

### Three numbers

**Median age of active findings: 0 days.** **Oldest active finding: 0 days.** Query: `GET /api/v2/findings/?active=true&limit=1000`, then `jq '[.[].age]'` on the result — every one of the 645 active findings has `"age": 0` and `"date": "2026-09-28"`. This isn't a data error: DefectDojo stamps a finding's `date` at *import* time by default (none of these parsers back-date a finding to a timestamp embedded in the original scan report), and every one of these nine reports — spanning scans that were actually run across Labs 4 through 7, weeks apart, per the source files' own mtimes (Sept 10 through Sept 27) — was imported into DefectDojo for the first time today. The honest reading is: this capstone import is the first day this data has ever existed as a tracked, deduplicated program; there is no finding-age history yet because there was no vulnerability-management *system* before today, only nine independent one-off scans.

**Share of active findings currently inside SLA: 100%** (628 of 628 findings that carry an SLA — the 17 Info-severity findings have no SLA days configured, per `sla_days_remaining: null` — all report `sla_days_remaining >= 0`). Query: `jq '[.[] | select(.sla_days_remaining != null)] | length as $t | [.[] | select(.sla_days_remaining >= 0)] | length as $ok | ($ok/$t)*100'` against the same findings dump. This number is trivially 100% for the same reason the ages are all 0 — nothing has had time to breach SLA yet. It should not be read as "the program is healthy"; it should be read as "the SLA clock started today," and it is worth re-running this exact query in a week to see the first real breaches.

### What Labs 8 and 9 don't show up in any of these numbers

Lab 8's Cosign signature verification (image signed, tamper-swap detected, two SBOM/provenance attestations) and Lab 9's runtime detections (Falco's built-in and custom rules firing, the Conftest policy pass/fail on the Kubernetes manifests) produced real security evidence, but none of it is a format DefectDojo 2.58.3 has a parser for — there is no "supply-chain attestation" or "Falco alert stream" importer, so a signed-and-verified image and a live SIGHUP-triggered CRITICAL alert both count as zero in this dashboard. What I'd do about it: at minimum, log these as manually-created DefectDojo findings (the API supports `POST /api/v2/findings/` without an import) tagged by source so they at least appear in the same inventory even without automated parsing, and longer-term, either write a small custom DefectDojo parser for Falco's JSON alert format (it's simple enough — one alert per line) or push Falco alerts to a SIEM that DefectDojo can pull a summary from instead.

### Risk acceptance

**Finding:** `Ensure That RDS Instances Have Performance Insights Enabled` (Checkov Scan, Medium severity, test 5).

**Decision:** Risk-accept, expiring **2026-12-15** (end of the course engagement window, matching the engagement's `target_end`).

**Compensating control:** The Terraform this finding comes from (`labs/lab6/vulnerable-iac/`) is a course exercise fixture that is never applied to real infrastructure — there is no actual RDS instance running, so there is nothing to gain visibility into. The compensating control is simply that this fixture's `terraform apply` is blocked in CI (the same gate covered in Lab 6's Checkov/KICS enforcement); if the fixture were ever promoted to a real deployment, this finding would have to be re-triaged against a live instance, not accepted from the exercise's risk acceptance.

### Executive summary

Nine weeks of independent scanner output are now one number: 645 active findings across nine imported reports, with 45 Critical and 309 High needing attention, though 79% of the total is dependency CVEs concentrated in three overlapping scans of the same Juice Shop base image rather than 645 distinct problems. The single biggest risk is that this is day one of tracking — every finding shows zero age and 100% nominal SLA compliance not because remediation is fast, but because nothing has had time to become overdue yet, and two entire labs' worth of supply-chain and runtime security evidence (Cosign attestations, Falco alerts) are invisible to this dashboard because DefectDojo has no parser for them. To close that gap I need: a real deduplication pass across the Grype/Trivy pairs that currently look like separate findings, a decision on whether to keep re-scanning the same base image three times per cycle, and either a custom parser or a manual-finding workflow so Lab 8 and 9's evidence stops being invisible to the one number a manager will actually look at.

## Bonus

See `submissions/lab10-walkthrough.md`.

The hardest part of the semester to explain concisely was the vulnerability-management capstone itself — every other lab has one tool and one clear before/after (a scan finds N issues, a fix brings it to 0), but Lab 10's value is entirely about what changes when nine separate one-off scans become one queryable system with SLAs and dedup, which is a process claim, not a technical one, and much harder to compress into "I ran X and it found Y." That tells me the next project's documentation should capture the *decision points* (what did I choose as the SLA and why, what did I decide was noise versus signal) as they happen, rather than trying to reconstruct that reasoning afterward from raw finding counts — the counts alone don't carry the judgment calls that actually made the system useful.
