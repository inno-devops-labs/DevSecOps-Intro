# Lab 10 — Submission

## Task 1: DefectDojo Aggregation

### Screenshot: Engagement page showing 4 tests
![engagement](./lab10-engagement.png)

### Findings by source
| Scanner (test id) | Findings |
|---|---:|
| Grype (test=1) | <108> |
| Semgrep (test=2) | <27> |
| Trivy (test=3) | <51> |
| ZAP (test=6) | <10> |
| **Total** | **196** |

### Dedup evidence
Number of ACTIVE findings after dedup (via `GET /api/v2/findings/?engagement=1&active=true`):
```
196 total ingested, 193 active after workflow triage (3 closed).
```
Number of duplicate group members (via cross-parser CVE-id join):
```
37 CVE-ids appear in BOTH Grype and Trivy → 74 duplicate rows across the two SCA parsers that DefectDojo default settings did not collapse into single findings.
```

### Deduplication reflection (Lecture 10 slide 11)
Grype+Trivy overlap was 37 CVEs (95% of Trivy). DefectDojo dedup keys per the slide are CVE ID, Vulnerability ID + affected component, File path + line, URL path + parameter. On this engagement with default settings the dedup was per-parser only, so the 37 shared CVEs appear as 74 rows instead of 37 with `evidence: 2 tools`; the slide 11 target state ("↑ confidence, ↓ noise. You triage the finding, not the tool output") is reachable but requires reconfiguring the Grype and Trivy parsers to key on Vulnerability ID + component and enabling cross-parser dedup.

## Task 2: Triage + Governance Report

### Three workflow actions taken
1. **Risk-accepted:** Finding #5 — Grype `GHSA-jf85-cpcp-j695 in lodash:2.4.2` (Critical). Rationale: lodash 2.4.2 is only in test-fixture paths, not on the production runtime path. 90-day expiry (2026-10-10). Required enabling `enable_simple_risk_acceptance` on the Product first — DefectDojo returned `Simple risk acceptance is disabled for this product, use the UI to accept this finding` until enabled.
2. **False positive:** Finding #109 — Semgrep `github-actions-mutable-action-tag` on `labs/lab5/semgrep/juice-shop/.github/workflows/ci.yml`. This file is the Juice Shop upstream's own CI workflow, inside the source clone we scanned in Lab 5. It is not part of our fork's CI. Required `verified: false` alongside `false_p: true` — DefectDojo returned `False positive findings cannot be verified` otherwise.
3. **Closed by fix:** Finding #138 — Trivy `CVE-2023-46233 crypto-js 3.3.0` (Critical). Same CVE is in the Lab 4 top-10 with fix `4.2.0`, covered by the signed CycloneDX SBOM attestation from Lab 8. Marked `is_mitigated: true`.

### Governance report

**Executive summary (3 sentences)**
The DevSecOps program on OWASP Juice Shop v20.0.0 has run pre-commit, build, deploy, and runtime checks across 10 labs and now aggregates the output of four scanners (Grype, Semgrep, Trivy, ZAP) into a single DefectDojo engagement with 196 findings. Of these, 193 are active, 1 is risk-accepted with a 90-day expiry, 1 is a documented false positive, and 2 are closed by fixes tracked in Lab 4 and attested in Lab 8. The dominant risk cluster is SCA (Grype + Trivy = 159 of 196 findings) driven by outdated npm dependencies (`jsonwebtoken`, `lodash`, `crypto-js`, `express-jwt`), and the top remediation lever is bumping those packages to the fix versions already tracked in the Lab 4 top-10 CVE table.

**Findings by severity (active only)**
| Severity | Open |
|---|---:|
| Critical | <12> |
| High | <109> |
| Medium | <51> |
| Low | <11> |
| Info | <10> |
| **Total open** | **193** |

Two Criticals closed (one risk-accepted, one mitigated) — that is why the open Critical count is 12 rather than the 14 ingested.

**Findings by source (which scanner produced what; coverage gaps)**
| Scanner | Findings | Coverage gap |
|---|---:|---|
| Grype (SCA) | <108> | Image contents only; no runtime/behavioral coverage. |
| Trivy (image) | <51> | Overlaps ~95% with Grype on CVE-ids (37 CVEs in both parsers). |
| Semgrep (SAST) | <27> | Source-only; can't see transitive/runtime behavior. |
| ZAP (DAST) | <10> | Baseline only; authenticated scan from Lab 5 was not re-imported. |

Additional coverage gaps: no runtime detector (Falco documented as non-functional on Apple Silicon via Colima in Lab 9); no IaC scanner in this engagement (Lab 6 Checkov + KICS findings belong to a different product).

**MTTR + age distribution**
All 196 findings were ingested on 2026-07-10 in a single batch import, and the DefectDojo `date` field on every finding is the ingest date, not the true "introduced" date in the codebase. So MTTD and Vuln age cannot be computed meaningfully from this dataset — they would all read as ~0 days, which is a measurement artefact. MTTR can only be computed for the three findings closed today (2026-07-10); ingest and close are the same day, so `MTTR ≈ 0 days` for those three — again a measurement artefact. Slide 13 says "DefectDojo computes all five out of the box. You don't write SQL; you read dashboards" — that is true operationally, but the numbers become meaningful only after multiple weekly ingests. This engagement is a Week-0 baseline.

**SLA compliance**
No SLA policy has been attached to this Product yet. Per DefectDojo defaults, when no SLA Configuration is set for a Product, findings do not carry SLA due-dates and SLA compliance % cannot be computed. This is the smallest concrete unlock for meaningful governance metrics (see Next-quarter goals).

**Risk-accepted items**
| Finding | Title | Severity | Accepted | Expiry / re-review |
|---:|---|---|---|---|
| #5 |<GHSA-jf85-cpcp-j695 in lodash:2.4.2 | Critical | 2026-07-10 | 2026-10-10> |

**Next-quarter goals (one concrete SAMM ladder step from Lecture 9)**
1. **Configure per-product SLA policy** (Critical: 7d, High: 30d, Medium: 90d, Low: 180d). Without this the SLA compliance % row above stays undefined.
2. Reconfigure Grype and Trivy dedup keys to `vulnerability_ids + component_name` and enable cross-parser dedup, collapsing the 37 CVE overlap into 37 findings with `evidence: 2 tools` (the slide-11 target state) instead of 74 separate rows.
3. Attach an authenticated ZAP scan and an IaC scan to this engagement so the "Findings by source" table has no coverage gaps other than the runtime one.

## Bonus: Python API script

### Script (paste labs/lab10/scripts/dd-metrics.py)
```python
#!/usr/bin/env python3
"""Lab 10 Bonus: pull metrics from DefectDojo via API and print a compact dashboard."""
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

DD_URL = "http://localhost:8080"
TOKEN_FILE = Path("labs/lab10/results/api-token.txt")
ENGAGEMENT_ID = 1


def api_get(path: str) -> dict:
    token = TOKEN_FILE.read_text().strip()
    req = urllib.request.Request(
        f"{DD_URL}{path}",
        headers={"Authorization": f"Token {token}"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def fetch_all(path: str) -> list:
    results = []
    next_url = path
    while next_url:
        data = api_get(next_url)
        results.extend(data.get("results", []))
        next_page = data.get("next")
        next_url = next_page.replace(DD_URL, "") if next_page else None
    return results


def main() -> int:
    findings = fetch_all(f"/api/v2/findings/?engagement={ENGAGEMENT_ID}&limit=100")
    total = len(findings)
    if not total:
        print("No findings in engagement.", file=sys.stderr)
        return 1

    by_severity = Counter(f["severity"] for f in findings)
    active = sum(1 for f in findings if f["active"])
    risk_accepted = sum(1 for f in findings if f["risk_accepted"])
    false_p = sum(1 for f in findings if f["false_p"])
    mitigated = sum(1 for f in findings if f["is_mitigated"])

    print(f"=== DefectDojo dashboard: engagement {ENGAGEMENT_ID} ===")
    print(f"Total findings ingested: {total}")
    print()
    print("Severity breakdown:")
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        print(f"  {sev:>10}: {by_severity.get(sev, 0)}")
    print()
    print("Workflow status:")
    print(f"  Active:         {active}")
    print(f"  Risk accepted:  {risk_accepted}")
    print(f"  False positive: {false_p}")
    print(f"  Mitigated:      {mitigated}")
    print()

    parsers = Counter(f["test"] for f in findings)
    print("Findings per test (parser):")
    for test_id, count in parsers.most_common():
        print(f"  test={test_id}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### Actual output on the current engagement
```
=== DefectDojo dashboard: engagement 1 ===
Total findings ingested: 196

Severity breakdown:
    Critical: 14
        High: 109
      Medium: 52
         Low: 11
        Info: 10

Workflow status:
  Active:         193
  Risk accepted:  1
  False positive: 1
  Mitigated:      2

Findings per test (parser):
  test=1: 108
  test=3: 51
  test=2: 27
  test=6: 10
```

### The 5-minute interview walkthrough (Lecture 10 slide 15)
Slide 15's canonical structure: Context (30s) → Layers (90s) → Findings (60s) → Metrics (60s) → Next (30s) → Q&A (30s). Filled with the numbers from this engagement:

- **Context (30s)** — "I built a 10-lab DevSecOps program on OWASP Juice Shop v20.0.0: signed commits, SBOM + Cosign attestations, SAST+DAST+SCA scans, IaC policies, Kubernetes hardening, admission-time Conftest, and this final aggregation into DefectDojo."
- **Layers (90s)** — pre-commit (gitleaks + SSH signing, Lab 3), CI/build (Semgrep + Grype + Trivy, Labs 4/5/7), deploy (Cosign verify + Conftest, Labs 8/9), runtime (Falco documented as non-functional on the platform, Task 2 Conftest as shift-left equivalent, Lab 9).
- **Findings (60s)** — "196 findings across four scanners. Kept 193 active, risk-accepted one Critical (lodash in test-fixture path), false-positive'd one Semgrep rule that fired on upstream's own CI workflow, closed one via the Lab 4 top-10 fix table. The Grype and Trivy overlap of 37 CVEs is the next dedup-tuning task."
- **Metrics (60s)** — 12 open Critical/109 High/51 Medium/11 Low/10 Info; 74 duplicate rows across Grype+Trivy that default settings do not collapse; SCA is the biggest bucket (159 of 196), DAST the smallest (10).
- **Next (30s)** — set a per-product SLA policy so slide 13's compliance metric becomes computable; reconfigure dedup per slide 11 to collapse the 37-CVE overlap; add SLSA provenance verification at admission time using the Lab 8 attestations; migrate the Falco layer off Colima to a real Linux node so runtime detection actually fires.

Slide 15's own framing at the end applies here: "This is the deliverable that gets you hired. Many DevSecOps interviews boil down to 'talk me through your last program.' Lab 10 produces exactly this script."