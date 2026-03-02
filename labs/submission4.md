# Lab 4 Submission — SBOM Generation & SCA Comparison

## Scope and Method

- Target image: `bkimminich/juice-shop:v19.0.0`
- SBOM tools: Syft and Trivy
- Vulnerability tools: Grype (on Syft SBOM) and Trivy image scanner
- Additional Trivy scanners used: secrets and license
- All outputs analyzed from `labs/lab4/` artifacts generated during lab execution

## Task 1 — SBOM Generation with Syft and Trivy

### 1) Package Type Distribution (Syft vs Trivy)

From `analysis/sbom-analysis.txt`:

- **Syft package counts:**
  - `npm`: 1128
  - `deb`: 10
  - `binary`: 1
  - **Total:** 1139
- **Trivy package counts:**
  - `Node.js`: 1125
  - `debian`: 10
  - **Total:** 1135

**Observation:** Both tools discover very similar dependency inventories, but Syft reports slightly more total components and includes a separate binary artifact class.

### 2) Dependency Discovery Analysis

From `comparison/accuracy-analysis.txt` and package set files:

- Packages detected by both: **1126**
- Only Syft: **13**
- Only Trivy: **9**

Examples unique to Syft (`comparison/syft-only.txt`):
- `node@22.18.0`
- `libssl3@3.0.17-1~deb12u2`
- metadata-like entries such as `baz@UNKNOWN`, `false_main@UNKNOWN`

Examples unique to Trivy (`comparison/trivy-only.txt`):
- `portscanner@2.2.0`
- `toposort-class@1.0.1`
- normalized OS versions (e.g., `libssl3@3.0.17`, `libc6@2.36`)

**Conclusion:** Discovery coverage is close, but model/normalization differences exist:
- Syft tends to preserve richer artifact-level metadata (including `UNKNOWN`/synthetic entries and full Debian revision strings).
- Trivy tends to normalize some package records and still catches a small set of language packages Syft misses.

### 3) License Discovery Analysis

From `analysis/sbom-analysis.txt` and `analysis/vulnerability-analysis.txt`:

- Syft found **32 unique license types**
- Trivy found **28 unique license types**

Top license families seen by both tools:
- `MIT` (largest share)
- `ISC`
- `BSD-2-Clause` / `BSD-3-Clause`
- `Apache-2.0`
- `LGPL-3.0`

**Conclusion:** Syft provides broader license variety in this run, while Trivy still captures the dominant license distribution well.

---

## Task 2 — SCA with Grype and Trivy

### 1) SCA Tool Comparison (Vulnerability Detection)

From `analysis/vulnerability-analysis.txt`:

- **Grype by severity:**
  - Critical: 11
  - High: 88
  - Medium: 32
  - Low: 3
  - Negligible: 12
- **Trivy by severity:**
  - CRITICAL: 10
  - HIGH: 81
  - MEDIUM: 34
  - LOW: 18

From `comparison/accuracy-analysis.txt`:

- CVEs found by Grype: **95**
- CVEs found by Trivy: **91**
- Common CVEs: **26**

**Conclusion:** Both tools identify significant risk, but overlap is partial. They should be treated as complementary for higher confidence triage.

### 2) Critical Vulnerabilities Analysis (Top 5 + Remediation)

The following are high-impact findings visible in generated scanner outputs:

1. **CVE-2023-32314 (`vm2` 3.9.17, CVSS 10.0, sandbox escape)**  
   - Fix: upgrade to at least `3.9.18` (prefer latest supported `vm2`).
2. **CVE-2023-37466 (`vm2` 3.9.17, CVSS 10.0, sandbox bypass)**  
   - Fix: upgrade to at least `3.10.0`.
3. **CVE-2025-15467 (`libssl3` 3.0.17-1~deb12u2, CVSS 9.8, OpenSSL RCE/DoS class issue)**  
   - Fix: update OS package to `3.0.18-1~deb12u2` or newer base image patch level.
4. **CVE-2015-9235 (`jsonwebtoken` 0.1.0 / 0.4.0, CVSS 9.8, token verification bypass)**  
   - Fix: upgrade to `4.2.2+` (prefer modern maintained major).
5. **CVE-2019-10744 (`lodash` 2.4.2, CVSS 9.1, prototype pollution)**  
   - Fix: upgrade to `4.17.12+` (prefer current patched release).

Prioritization approach used:
- Patch sandbox-escape and crypto/auth vulnerabilities first.
- Patch OS/base image vulnerabilities in parallel with application dependency upgrades.
- Re-scan after updates to confirm risk reduction.

### 3) License Compliance Assessment

From `trivy/trivy-licenses.json` and `analysis` summaries:

- Dominant permissive licenses (`MIT`, `ISC`, `BSD`, `Apache-2.0`) suggest generally low compliance friction.
- Potentially higher-compliance-attention licenses were detected, including:
  - `GPL-2.0-only` / `GPL-2.0-or-later`
  - `LGPL-3.0-only` / `LGPL-2.1-only`
  - `WTFPL` variants

Recommendations:
- Maintain an allow/deny policy per business/legal context.
- Flag copyleft licenses for legal review before distribution.
- Keep SBOM-driven license checks in CI to detect drift in transitive dependencies.

### 4) Additional Security Features — Secrets Scanning

From `trivy/trivy-secrets.txt`:

- Trivy detected secrets in multiple files, including:
  - `AsymmetricPrivateKey` findings in `insecurity` source/build files (HIGH)
  - `JWT` token findings in spec files (MEDIUM)

Interpretation:
- Findings are plausible in a deliberately vulnerable training application and test fixtures.
- They should still be triaged with context (real secret vs embedded demo/test material).

---

## Task 3 — Syft+Grype vs Trivy All-in-One

### 1) Accuracy Analysis (Quantified)

- **Package overlap:** 1126 common, 13 Syft-only, 9 Trivy-only.
- **Vulnerability overlap:** 95 Grype CVEs, 91 Trivy CVEs, 26 common.

Interpretation:
- SBOM/package coverage is highly similar.
- Vulnerability mapping overlap is much lower due to differences in advisory sources, matching logic, and identifier normalization (CVE vs GHSA emphasis).

### 2) Tool Strengths and Weaknesses

**Syft + Grype (specialized chain)**
- Strengths:
  - Rich SBOM artifact detail and strong license extraction depth.
  - Decoupled workflow: generate once, scan many times from SBOM.
  - Good for audit-heavy and evidence-preserving pipelines.
- Weaknesses:
  - Two tools to operate and maintain.
  - More moving parts in CI/CD integration.

**Trivy all-in-one**
- Strengths:
  - Unified scanner for vuln + license + secrets.
  - Simpler operational workflow and developer onboarding.
  - Fast adoption in CI for broad baseline checks.
- Weaknesses:
  - Slightly less artifact richness in this SBOM comparison.
  - Different vulnerability coverage profile; not a full substitute for every use case.

### 3) Use Case Recommendations

- Choose **Syft+Grype** when:
  - You need high-fidelity SBOM artifacts for governance or compliance.
  - You want reusable SBOM-centric workflows across environments.
- Choose **Trivy** when:
  - You want one tool for broad security checks with low setup overhead.
  - You prioritize CI simplicity and fast feedback.
- For mature DevSecOps: use **both** in layered pipelines (Trivy for broad gate + Syft/Grype for deep SBOM/SCA validation).

### 4) Integration Considerations (CI/CD and Operations)

- Run scans on every PR and nightly on default branch.
- Fail CI on `CRITICAL`/`HIGH` thresholds with risk-accepted exception process.
- Version-pin scanner images and periodically update vulnerability databases.
- Store SBOMs and scan reports as pipeline artifacts for traceability.
- Include license and secrets stages, not only vulnerability scanning.

---

## Commands Executed (Summary)

Commands followed the lab guide and were executed using Docker images:

- `anchore/syft:latest` for SBOM generation (`syft-json`, `table`)
- `anchore/grype:latest` for SBOM-based vulnerability scanning (`json`, `table`)
- `aquasec/trivy:latest` for:
  - image SBOM/dependency output (`json`, `table`, `--list-all-pkgs`)
  - vulnerability scan (`trivy-vuln-detailed.json`)
  - secrets scan (`--scanners secret`)
  - license scan (`--scanners license`)
- `jq`, `sort`, `uniq`, `comm`, and `wc` for analysis and comparison metrics

## Issues Encountered

No blocking execution issues were observed in the stored artifacts. The main challenge was **tool result normalization differences** (package naming/version formatting and advisory ID mapping), which were handled through side-by-side quantitative comparison.
