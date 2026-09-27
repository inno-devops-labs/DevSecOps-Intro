# Lab 10 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (DefectDojo load) · Task 2 (SLA + governance) · **Bonus Task** (`submissions/lab10-walkthrough.md`, +2 pts)

## Environment

| Item | Value |
|------|-------|
| DefectDojo | **2.58.3** (git tag + `DJANGO_VERSION`/`NGINX_VERSION=2.58.3`) |
| UI / API | `http://127.0.0.1:18080` (host **8080** already taken by another container) |
| Product type | Research and Development |
| Product / engagement | OWASP Juice Shop / Course Semester Run |

## Task 1

### Imports (parser → file → active findings)

| Lab | File | Parser | Active findings |
|-----|------|--------|----------------:|
| 4 | `labs/lab4/grype-from-sbom.json` | Anchore Grype | **182** |
| 4 | `labs/lab4/trivy.json` | Trivy Scan | **176** |
| 5 | `labs/lab5/results/semgrep.json` | Semgrep JSON Report | **27** |
| 5 | `labs/lab5/results/auth-report.xml` | ZAP Scan | **12** |
| 6 | `labs/lab6/results/checkov-terraform/results_json.json` | Checkov Scan | **80** |
| 6 | `labs/lab6/results/kics-ansible/results.json` | KICS Scan | **10** |
| 6 | `labs/lab6/results/kics-pulumi/results.json` | KICS Scan | **6** |
| 7 | `labs/lab7/results/trivy-image.json` | Trivy Scan | **76** |
| 7 | `labs/lab7/results/trivy-k8s.json` | Trivy Operator Scan | **0** |

**ZAP note:** community `ZAP Scan` on 2.58.3 rejected the JSON report (`Wrong file format, please use xml`). I converted `auth-report.json` → traditional OWASP ZAP XML (`auth-report.xml`) with the same 12 alerts and imported that. Same findings, different serialization.

`run-imports.sh` completed for every other file; Trivy Operator reported **0** active findings for this k8s JSON (parser accepted the file).

### Active findings by severity

```bash
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?active=true&limit=1000" \
  | jq -c '[.results[].severity] | group_by(.) | map({severity:.[0], count:length})'
```

| Severity | Count |
|----------|------:|
| Critical | 34 |
| High | 242 |
| Medium | 230 |
| Low | 47 |
| Info | 16 |
| **Total active** | **569** |

### Duplicate titles

```bash
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?limit=1000" \
  | jq -c '[.results[].title] | group_by(.) | map(select(length>1) | {title:.[0], n:length}) | sort_by(-.n) | .[:5]'
```

1. **`Secret Management: Passwords and Secrets - Generic Password` (n=7)** — **seven separate findings**, not one issue counted twice. Same KICS rule, different file/line pairs under the vulnerable Ansible/Pulumi playground (`inventory.ini` lines 5/10/18/19, `configure.yml`, `deploy.yml`, `Pulumi-vulnerable.yaml`). Decided by distinct `file_path` + `line` in the API.

2. **`javascript.sequelize…express-sequelize-injection` (n=6)** — **six separate findings**. Same Semgrep rule ID, different source locations (`routes/login.ts`, `routes/search.ts`, and several `codefixes/*` fixtures). Same decision rule: path+line differ → treat as distinct backlog items (some may be intentional Juice Shop challenges).

### Which labs matter this week vs noise

I would **act this week** on Lab 5 ZAP/Semgrep authenticated SQLi and injection paths that are reachable in the running app, and on Lab 6 IaC secrets / public DB style failures that would burn a real cloud account if applied. Lab 4/7 **SCA CRITICAL/HIGH with fixes** (e.g. `jsonwebtoken` / `lodash` / OpenSSL) are the rebuild backlog. Lab 7 Trivy Operator returning **0** and the bulk of duplicate SCA titles across Grype+Trivy are **noise for triage** until deduped — same CVEs twice do not double the work. Labs **8 and 9** produced signatures and Falco/Conftest evidence DefectDojo cannot parse here; they matter operationally but do not inflate this 569.

## Task 2

### SLA configuration

| Severity | Default (days) | Ours (days) | Why |
|----------|---------------:|------------:|-----|
| Critical | 7 | **3** | Internet-facing Juice Shop class bugs and known-exploited style CVEs need a same-week fix or compensating control |
| High | 30 | **14** | Two-week sprint cadence; keeps High inside one planning cycle |
| Medium | 90 | **45** | Still scheduled, but not allowed to rot a full quarter without review |
| Low | 120 | **90** | Backlog hygiene without pretending Low is firefight |

Changed via `PATCH /api/v2/sla_configurations/1/` on the `Default` profile.

### Active findings by severity and source tool

Severity table: above. By scan type (active):

| Tool / parser | Active |
|---------------|-------:|
| Trivy Scan (lab4 + lab7 image) | 252 |
| Anchore Grype | 182 |
| Checkov Scan | 80 |
| Semgrep JSON Report | 27 |
| KICS Scan | 16 |
| ZAP Scan | 12 |
| Trivy Operator Scan | 0 |

### Age and SLA compliance

Query: `GET /api/v2/findings/?active=true&limit=1000`, age = today − finding `date` (UTC calendar days).

| Metric | Value | Method |
|--------|------:|--------|
| Median age of active findings | **0 days** | median of ages; all imports dated 2026-09-27 |
| Oldest active finding | **0 days** | max age (example title `GHSA-35jh-r3h4-6jhm in lodash:2.4.2`) |
| Share inside SLA | **100%** | age 0 vs SLA windows 3/14/45/90 — none breached yet |

### What Labs 8 and 9 leave out of these numbers

Cosign signature/attestation failures and Falco CRITICAL mining / Conftest deny results never enter DefectDojo — **no parser**. I would track them as manual “Control findings” (or export JSON into a generic parser) with owners and SLAs beside this CVE backlog, not pretend the dashboard is complete.

### Risk acceptance (example)

**Finding class:** Lab 7 / SCA CRITICAL with **no listed fix** (`decompress@4.2.1` / `CVE-2026-53486` and similar no-fix rows from Lab 7).  
**Decision:** risk-accept until upstream ships a fix or we remove the dependency.  
**Expiry:** **2026-11-01**.  
**Compensating controls:** PSS `restricted` + read-only root + NetworkPolicy from Lab 7; no public admin without auth; rescan on every image rebuild. “We will not fix this” without a date is not recorded.

### Executive summary

The semester backlog is **569** active findings in one DefectDojo product, dominated by SCA (Grype/Trivy) and IaC (Checkov), with a smaller but higher-signal set of Semgrep/ZAP application issues. The single biggest risk is **reachable injection and secret exposure** (DAST/SAST + IaC passwords), not the raw CVE count. To close it we need a two-week plan: fix or WAF-mitigate the authenticated SQLi class, rotate/remove hardcoded IaC secrets, and rebuild Juice Shop from a digest-pinned base that clears fixable CRITICAL SCA.

## Bonus

See [`submissions/lab10-walkthrough.md`](lab10-walkthrough.md).

The hardest part to explain in five minutes was **why 569 is not 569 equal emergencies** — dedup across Grype/Trivy, intentional Juice Shop vulns, and IaC playground findings. That tells me the next project needs a one-page “how we triage” note (severity × reachability × fixability) written **before** the first dashboard screenshot, or every stakeholder meeting collapses into count inflation.
