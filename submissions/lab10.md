# Lab 10 — Submission

The capstone: nine weeks of scanner output loaded into one DefectDojo instance, deduplicated by
eye, triaged, and turned into a report a manager could act on.

## Setup

```console
$ # DefectDojo pinned to the tag the lab requires
$ git -C labs/lab10/work/dd describe --tags
2.58.3
```

Six containers via `docker compose` (postgres, valkey, uwsgi, celeryworker, celerybeat, nginx).
**Port note:** `:8080` was already in use on this machine, so nginx failed to bind and I remapped
it with `DD_PORT=8081` — every API call below uses `http://localhost:8081`. API token obtained via
`/api/v2/api-token-auth/` (the scriptable path CI would use), product type `Research and
Development` (stock id 1).

## Task 1 — Stand it up and load it

### Imported reports, parsers, and counts

DefectDojo **2.58.3**. The importer auto-discovered the parser names and loaded every report that
exists:

| Lab | File | Parser | Active findings |
|---|---|---|---:|
| 4 | `grype-from-sbom.json` | Anchore Grype | 230 |
| 4 | `trivy.json` | Trivy Scan | 225 |
| 5 | `semgrep.json` | Semgrep JSON Report | 27 |
| 5 | `auth-report.xml` | ZAP Scan | 13 |
| 6 | `checkov-terraform/results_json.json` | Checkov Scan | 80 |
| 6 | `kics-ansible/results.json` | KICS Scan | 10 |
| 6 | `kics-pulumi/results.json` | KICS Scan | 6 |
| 7 | `trivy-image.json` | Trivy Scan | 87 |
| 7 | `trivy-k8s.json` | Trivy Operator Scan | 0 |

**Two honest notes on the import:**

- **ZAP didn't import as shipped.** The lab maps `auth-report.json → ZAP Scan`, but DefectDojo
  2.58.3's ZAP parser is **XML-only** and rejected the JSON with *"Wrong file format, please use
  xml."* I converted the real auth-scan data from JSON to ZAP's XML schema (same findings, no
  re-scan) and imported that — 13 findings. This is exactly the kind of format friction a central
  vuln-management system surfaces that individual tools hide.
- **`trivy-k8s.json` imported as 0 findings.** Lab 7's file comes from `trivy k8s`, which is not the
  Trivy *Operator* report format the `Trivy Operator Scan` parser expects, so it parsed cleanly but
  yielded nothing. The container-image CVEs are still represented — via `trivy-image.json` (87).

### Active findings by severity

```console
$ curl -s …/api/v2/findings/?active=true&limit=2000 | jq '[.results[].severity]|group_by(.)…'
```

| Critical | High | Medium | Low | Info | **Total** |
|---:|---:|---:|---:|---:|---:|
| 44 | 283 | 282 | 56 | 13 | **678** |

### Two duplicate titles — one issue, or many?

I decided by comparing each duplicate's **component/CVE and `file_path`**: identical
component+version+CVE across scans is one issue counted twice; distinct `file:line` locations are
separate issues that merely share a rule title.

- **`CVE-2026-93748 HTTP-Cache-Semantics 4.2.0` (×4) — one issue counted four times.** All four rows
  are the same package at the same version, at two `node_modules` paths
  (`make-fetch-happen/...` and `sqlite3/...`), scanned by **both** Trivy runs (test 2 = lab4,
  test 8 = lab7 image). Same CVE, same component — bumping `http-cache-semantics` once clears all
  four. DefectDojo left them separate because dedup wasn't configured and the install paths differ.
- **`Passwords and Secrets - Generic Password` (×7) — seven separate findings.** KICS reported these
  at seven distinct locations (`ansible/configure.yml:16`, `deploy.yml:12`, four lines across
  `inventory.ini`, and `pulumi/Pulumi-vulnerable.yaml:16`). Same rule, but each is a different
  hardcoded secret in a different file — seven things to remediate, not one counted seven times.

### One number for the project — signal vs noise

The "678 active findings" headline is badly inflated and most of it is not this week's work.
**What I'd act on now** comes from Labs 4, 5 and 7: the fixable Critical/High dependency CVEs
(`crypto-js`, `jsonwebtoken`, `lodash`, the `tar` and `http-cache-semantics` npm issues — all with
a patched version), and the one vulnerability two independent tools agree on — Semgrep's
`express-sequelize-injection` in `routes/search.ts` and ZAP's confirmed **SQL Injection** at
`/rest/products/search`. Cross-validated and reachable beats a high count every time. **The noise**
is mostly Lab 6: all 96 Checkov+KICS findings are against the *deliberately broken* sample IaC in
`vulnerable-iac/` — teaching fixtures, not the app's real infrastructure — and the seven "generic
password" hits are in that sample Ansible. On top of that, the SCA count is double-counted: Grype
(230) and the two Trivy runs (225 + 87) scan overlapping dependency sets, so the same npm CVE lands
three times. And **Labs 8 and 9 contributed nothing here** — DefectDojo has no parser for Cosign
signatures/attestations or Falco runtime alerts, so the supply-chain and runtime evidence simply
isn't in this number (addressed in Task 2).

## Task 2 — Make it a program

### SLA — mine vs the stock defaults

| Severity | Default (days) | Mine (days) | Why |
|---|---:|---:|---|
| Critical | 7 | **7** | Kept. Critical = actively exploitable / KEV-class; 7 days is already the aggressive end and I can defend it. |
| High | 30 | **14** | Most of our Highs are dependency CVEs *with a patched version* — a one-line bump shouldn't wait a month; two weeks (one sprint) is honest. |
| Medium | 90 | **60** | A full quarter is a deadline teams quietly ignore; 60 days fits a normal monthly patch cadence with one month of slack. |
| Low | 120 | **180** | Lowered priority, longer window. 120 days was a deadline nobody hit; 180 with tracking is more honest than a date that's always breached. |

Set via `PATCH /api/v2/sla_configurations/1/`.

### Active findings by severity and by source tool

Severity (from Task 1): **Critical 44, High 283, Medium 282, Low 56, Info 13 — total 678.**

By tool:

| Tool (lab) | Active findings |
|---|---:|
| Anchore Grype (4) | 230 |
| Trivy — image/SBOM (4 + 7) | 312 |
| Checkov (6) | 80 |
| Semgrep (5) | 27 |
| KICS (6, ansible + pulumi) | 16 |
| ZAP (5) | 13 |

### Three numbers, with method

```console
$ curl -s …/findings/?active=true&limit=2000 | jq '[.results[].age] | {median, max}'
$ # within-SLA = findings whose age <= the SLA for their severity
```

| Metric | Value | How |
|---|---:|---|
| Median age of active findings | **0 days** | `.age` field across all 678 active findings |
| Oldest active finding | **0 days** | `max(.age)` |
| Share currently inside SLA | **100%** | age (0) ≤ SLA for every severity |

**The honest caveat:** these are flattering because every finding was imported *today*, so `age`
measures *time in DefectDojo*, not time since the vulnerability was introduced or first scanned.
The SLA clock started at ingestion. In a real program I'd set each finding's date from the scan or
commit that produced it so the clock reflects true exposure — then "100% in SLA" would become a
real number instead of an artifact of a fresh import. As it stands, 100%-in-SLA says only "nothing
has aged yet," not "the backlog is healthy."

### What Labs 8 and 9 produced that none of these numbers include

**Nothing from Labs 8 (supply chain) or 9 (runtime) is in the 678.** DefectDojo has no parser for
Cosign signatures/attestations or Falco alerts — a signed digest, a signed SBOM attestation, and a
CRITICAL "mining pool connection" alert are not vulnerability findings it ingests. That's a real
blind spot: the dashboard implies "678 things to fix" but says nothing about whether the image is
*signed*, whether its SBOM is *attested*, or whether anything is being *detected at runtime*. I'd
close it by tracking those as separate program signals — attestation/signature coverage as a CI
gate metric, and Falco alerts routed to a SIEM/alerting pipeline — and, where I wanted them on one
pane, use DefectDojo's generic-findings import to record "image unsigned" or "runtime alert fired"
as findings so they show up alongside the CVEs.

### A risk acceptance (with an expiry and a control)

**Finding:** `GHSA-p6mc-m468-83gw in lodash.set@4.3.2` (High) — prototype pollution.
**Decision:** risk-accept until **2026-01-15** (≈90 days).
**Why it's acceptable:** `lodash.set` is a deprecated transitive dependency with **no patched
release** — the real fix is migrating callers off it, a refactor, not a bump, so it can't meet the
14-day High SLA.
**Compensating control:** the package isn't on an attacker-reachable input path in Juice Shop's
runtime (it's pulled in transitively, not called on request data), and the pod runs under the Lab 7
`restricted` profile with a read-only root filesystem, which blunts the impact of a pollution
primitive. Re-review at expiry; if a maintained replacement exists by then, it moves back to the
backlog. ("We won't fix this" with no date is not a decision — this one has one.)

### Executive summary

> Across ten weeks we put OWASP Juice Shop through SCA, SAST, DAST, IaC, container, supply-chain and
> runtime controls and consolidated the results into one DefectDojo instance: 678 active findings,
> but after removing duplicate npm CVEs and the deliberately-broken IaC fixtures, the real backlog
> is a few dozen fixable dependency upgrades plus one SQL-injection that two tools independently
> confirmed. The single biggest risk is that confirmed, reachable SQL injection at
> `/rest/products/search` — it's a High with a known fix (parameterize the query) and a working
> exploit, so it leads the queue. To close it I need one developer-day to land the fix plus a
> re-scan to confirm, and a decision on backdating finding dates so our SLA numbers reflect real
> exposure rather than import day.

## Bonus — The five-minute walkthrough

See `submissions/lab10-walkthrough.md`.

The hardest part to explain concisely was **why 678 findings is almost the wrong number** — that
most of the count is duplication (the same npm CVE reported by three scanners) and deliberately-
broken teaching fixtures, so the honest backlog is a fraction of it. Explaining that requires the
listener to already believe that a high finding count can be noise, which is itself the insight the
whole semester builds toward, so it resists a one-liner. What that tells me about documenting the
next project is that the *number* should never ship without the *reduction* next to it: "678 raw →
~40 actionable → 1 to fix first" is the sentence, and I should produce that triage view as a
first-class artifact from day one rather than reconstructing it at the end.

## Artifacts

- `labs/lab5/results/auth-report.xml` — ZAP findings converted to the XML the parser accepts.
- `submissions/lab10-walkthrough.md` — the five-minute interview script (bonus).
- `labs/lab10/imports/import-*.json` — importer response bodies (uncommitted).
