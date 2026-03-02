# Lab 4 Submission — SBOM Generation & Software Composition Analysis

## Environment
- Date: 2026-03-02
- OS: macOS (Darwin 25.3.0)
- Branch: `feature/lab4`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Tools (Docker images): `anchore/syft:latest`, `anchore/grype:latest`, `aquasec/trivy:latest`

---

## Task 1 — SBOM Generation with Syft and Trivy

### 1.1 Commands and artifacts

Executed the required SBOM workflow with Dockerized tools and stored all outputs under `labs/lab4/`:
- Syft SBOM: `labs/lab4/syft/juice-shop-syft-native.json`
- Syft table: `labs/lab4/syft/juice-shop-syft-table.txt`
- Syft licenses: `labs/lab4/syft/juice-shop-licenses.txt`
- Trivy detailed SBOM: `labs/lab4/trivy/juice-shop-trivy-detailed.json`
- Trivy table: `labs/lab4/trivy/juice-shop-trivy-table.txt`
- Component/license summary: `labs/lab4/analysis/sbom-analysis.txt`

### 1.2 Package type distribution (Syft vs Trivy)

From `labs/lab4/analysis/sbom-analysis.txt`:

| Tool | Package classes detected | Count |
| --- | --- | ---: |
| Syft | `npm` | 1128 |
| Syft | `deb` | 10 |
| Syft | `binary` | 1 |
| **Syft total** |  | **1139** |
| Trivy | Node.js packages | 1125 |
| Trivy | Debian OS packages | 10 |
| **Trivy total** |  | **1135** |

### 1.3 Dependency discovery analysis

- Shared package coordinates (name+version): **1126**
- Only Syft: **13**
- Only Trivy: **9**

Interpretation:
- Syft found slightly more entries overall and includes extra metadata-rich package records (including several `UNKNOWN` versions), which increases visibility but can add noise.
- Trivy normalizes some OS package versions (e.g., Debian package revisions), which explains a portion of the mismatch in `syft-only`/`trivy-only` sets.
- For dependency graph completeness, Syft had marginally better recall in this image; Trivy output was a bit cleaner for operational consumption.

### 1.4 License discovery analysis

From `labs/lab4/analysis/sbom-analysis.txt` and `labs/lab4/analysis/vulnerability-analysis.txt`:

- Syft unique license types: **32**
- Trivy unique license types: **28**

Observations:
- Both tools detected dominant permissive licenses (`MIT`, `ISC`, `BSD`, `Apache-2.0`) across Node ecosystem dependencies.
- Both tools also detected compliance-sensitive license families (`GPL-*`, `LGPL-*`, `GFDL-*`) and non-standard entries (`ad-hoc`, `public-domain`).
- Syft provided broader raw license variety; Trivy used more normalized SPDX-style labels (e.g., `GPL-2.0-only`, `LGPL-3.0-only`).

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### 2.1 SCA tool comparison (vulnerability capabilities)

Generated outputs:
- Grype JSON/table: `labs/lab4/syft/grype-vuln-results.json`, `labs/lab4/syft/grype-vuln-table.txt`
- Trivy vuln/secrets/license: `labs/lab4/trivy/trivy-vuln-detailed.json`, `labs/lab4/trivy/trivy-secrets.txt`, `labs/lab4/trivy/trivy-licenses.json`
- Severity summary: `labs/lab4/analysis/vulnerability-analysis.txt`

Severity distribution:

| Severity | Grype | Trivy |
| --- | ---: | ---: |
| Critical | 11 | 10 |
| High | 88 | 81 |
| Medium | 32 | 34 |
| Low | 3 | 18 |
| Negligible | 12 | 0 |
| **Total** | **146** | **143** |

Identifier overlap from `labs/lab4/comparison/accuracy-analysis.txt`:
- CVEs found by Grype: **95**
- CVEs found by Trivy: **91**
- Common CVEs: **26**

Interpretation:
- Grype reported slightly more findings and more advisory diversity.
- Trivy and Grype use partially different vulnerability intelligence sources and naming conventions (CVE vs GHSA-centric records), causing low direct CVE overlap.

### 2.2 Critical vulnerabilities analysis (top 5 + remediation)

| Finding | Affected package | Installed | Fixed / target | Detected by | Remediation |
| --- | --- | --- | --- | --- | --- |
| `CVE-2025-15467` | `libssl3` | `3.0.17-1~deb12u2` | `3.0.18-1~deb12u2` | Trivy + Grype | Rebuild image on updated Debian base; pin patched package revision in image build pipeline. |
| `CVE-2023-32314` / `GHSA-whpj-8f3w-67p5` | `vm2` | `3.9.17` | `>=3.9.18` | Trivy + Grype (different IDs) | Upgrade `vm2` to patched release and run regression tests for sandboxed execution paths. |
| `CVE-2023-37466` / `GHSA-cchq-frgv-rjh5` | `vm2` | `3.9.17` | `>=3.10.0` | Trivy + Grype (different IDs) | Same remediation as above; prioritize due sandbox escape class and RCE potential. |
| `CVE-2015-9235` / `GHSA-c7hr-j4mj-j2w6` | `jsonwebtoken` | `0.1.0`, `0.4.0` | `>=4.2.2` | Trivy + Grype (different IDs) | Replace legacy `jsonwebtoken` transitives; enforce modern JWT verification and algorithm restrictions. |
| `CVE-2023-46233` / `GHSA-xwcq-pm8m-c4vf` | `crypto-js` | `3.3.0` | `>=4.2.0` | Trivy + Grype (different IDs) | Upgrade crypto library and revalidate key-derivation settings and backward compatibility. |

Prioritization strategy used:
1. Critical severity first,
2. package exploitability and blast radius in web app context,
3. availability of a clear fixed version.

### 2.3 License compliance assessment

Potentially risky / policy-sensitive license groups observed:
- Copyleft and reciprocal families: multiple `GPL-*` and `LGPL-*` variants
- Documentation/data obligations: `GFDL-*`
- Ambiguous entries: `ad-hoc`, `public-domain`

Recommendations:
1. Define CI policy gates (allow/deny/needs-review) on SPDX identifiers.
2. Flag all `GPL/LGPL/GFDL` dependencies for legal review before production release.
3. Treat non-standard labels (`ad-hoc`, unknown-like entries) as manual-review required.
4. Export approved-license inventory from SBOM to artifact repository for auditability.

### 2.4 Additional security features — secrets scanning

From `labs/lab4/trivy/trivy-secrets.txt`:
- Total secret findings: **4**
- High: **2** (`AsymmetricPrivateKey` pattern)
- Medium: **2** (`JWT` token pattern)

All findings are located in Juice Shop source/build test files (e.g., `lib/insecurity.ts`, frontend spec files), which is consistent with intentionally insecure training content.  
Practical recommendation: keep secret scanning enabled in CI, but maintain narrowly scoped path exceptions for known educational fixtures instead of broad allow-listing.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1 Accuracy and coverage analysis

From `labs/lab4/comparison/accuracy-analysis.txt`:

| Metric | Value |
| --- | ---: |
| Packages detected by both tools | 1126 |
| Packages only detected by Syft | 13 |
| Packages only detected by Trivy | 9 |
| CVEs found by Grype | 95 |
| CVEs found by Trivy | 91 |
| Common CVEs | 26 |

Conclusion:
- Package coverage is close, with slight edge to Syft on raw component discovery.
- Vulnerability overlap is limited, so relying on a single engine can miss advisory context.

### 3.2 Tool strengths and weaknesses

**Syft + Grype (specialized stack)**
- Strengths: detailed SBOM artifacting, better separation of concerns, strong fit for audit workflows.
- Weaknesses: two-tool orchestration overhead, more pipeline steps to maintain.

**Trivy (all-in-one)**
- Strengths: simple operational model, one CLI for vuln+secret+license scanning, easy CI adoption.
- Weaknesses: less granular SBOM specialization; when run in ephemeral containers without cache, DB redownload overhead is noticeable.

### 3.3 Use-case recommendations

- Choose **Syft + Grype** when:
  - SBOM lifecycle management is a hard requirement,
  - you need richer artifact metadata and stronger audit trail separation,
  - security and compliance teams consume SBOMs independently from scanning.

- Choose **Trivy all-in-one** when:
  - developer productivity and quick CI feedback are top priority,
  - one integrated scanner command is preferred,
  - secret/license/vulnerability checks should run together with minimal setup.

### 3.4 Integration considerations (CI/CD and operations)

1. Always archive SBOMs and scan reports as build artifacts (`labs/lab4/...` equivalent in CI).
2. Use scanner cache volumes to avoid repeated DB downloads in short-lived CI jobs.
3. Implement quality gates on:
   - critical vulnerabilities,
   - policy-violating licenses,
   - high-confidence secret findings.
4. Schedule periodic rescans of released images because vulnerability intelligence changes over time.
5. For production-grade pipelines, combine vulnerability + license + secret checks with explicit exception governance.

---

## Issues Encountered

- Docker daemon was initially unavailable (`docker.sock` path error); resolved by starting Docker Desktop.
- Trivy DB was downloaded multiple times because scanner runs were executed in clean containers without persistent cache mounts.

---

## Final Conclusion

Both approaches are viable and complementary:
- **Syft+Grype** gives better artifact-centric governance and slightly broader component/advisory visibility in this run.
- **Trivy** provides faster operational adoption and broader built-in scanner coverage (including secrets and licenses) in a single workflow.

For mature DevSecOps pipelines, the best practical approach is often hybrid: generate canonical SBOMs with Syft, then run both Grype and Trivy (or at least periodically cross-validate) to reduce blind spots.
