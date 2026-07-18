# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1832332 bytes
- `juice-shop.spdx.json` component count: 908

### Grype severity breakdown (paste table or JSON)
| Severity   | Count |
|------------|------:|
| Critical   | 7     |
| High       | 51    |
| Medium     | 35    |
| Low        | 4     |
| Negligible | 7     |
| **Total**  | 104   |

### Top 10 CVEs (paste from jq output)
| CVE                  | Severity | Package        | Installed   | Fix       |
|---------------------|----------|----------------|-------------|-----------|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken   | 0.1.0       | 4.2.2     |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken   | 0.4.0       | 4.2.2     |
| GHSA-jf85-cpcp-j695 | Critical | lodash         | 2.4.2       | 4.17.12   |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js      | 3.3.0       | 4.2.0     |
| CVE-2026-5450       | Critical | libc6          | 2.41-12     |           |
| CVE-2026-34182      | Critical | libssl3t64     | 3.5.5        | 3.5.6     |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb         | 0.6.11      |           |
| GHSA-35jh-r3h4-6jhm | High     | lodash         | 2.4.2       | 4.17.21   |
| GHSA-8hfj-j24r-96c4 | High     | moment         | 2.0.0       | 2.29.2    |
| GHSA-p6mc-m468-83gw | High     | lodash.set     | 4.3.2       |           |

### Fix-available rate
Out of the top 10 CVEs, 7 have an available fix, while 3 do not. This shows that most of the highest-risk vulnerabilities can be addressed through dependency upgrades, so they should be prioritized in patching efforts. Following the lecture triage strategy, we should first focus on issues that are both High/Critical severity and have available fixes, since they provide the fastest and most effective risk reduction. The remaining unfixed issues may require monitoring, upstream updates, or architectural changes rather than immediate patching.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity   | Grype | Trivy | Δ (Trivy - Grype) |
|------------|------:|------:|------------------:|
| Critical   | 7     | 5     | -2                |
| High       | 51    | 43    | -8                |
| Medium     | 35    | 39    | +4                |
| Low        | 4     | 22    | +18               |
| **Total**  | 104   | 109   | +5                |

---

### Why the difference?

**1) jsonwebtoken / GHSA-c7hr-j4mj-j2w6**
- Found by: **Grype**
- Missed by: Trivy

Grype reports multiple vulnerable versions of `jsonwebtoken` (0.1.0, 0.4.0), while Trivy only reports a subset of findings. This is likely due to differences in vulnerability DB mapping and package version resolution rules. Grype’s database (Anchore) tends to be more aggressive in matching older transitive versions inside SBOM inputs, while Trivy may consolidate or filter some matches depending on ecosystem metadata confidence.

---

**2) lodash / GHSA-f23m-r3pf-42rh (and related older lodash CVEs)**
- Found by: **Grype**
- Missed by: **Trivy**

Grype detects additional historical lodash vulnerabilities affecting very old versions (2.4.2) with broader CVE mapping coverage. Trivy does not surface these same entries, likely because its vulnerability database prioritizes more recent or directly mapped advisories and may drop low-confidence matches for deeply nested or legacy versions.

---

### When would you pick each?

**Syft + Grype (decoupled model):**  
This approach wins when you need reproducibility and auditability. Since SBOM is generated separately and then scanned, it fits well into supply-chain security pipelines and compliance workflows (you can store SBOMs as attestations, re-scan later with updated DBs without rebuilding images). It’s especially useful in regulated environments or multi-stage CI/CD where artifacts must remain immutable.

**Trivy (all-in-one model):**  
Trivy wins in simplicity and speed. One tool does image scanning, SBOM generation, secrets detection, and IaC scanning, which makes it ideal for CI pipelines where you want minimal setup and fast feedback. It’s particularly useful for developer-first workflows and quick security gating in pull requests.