# Lab 4 — SBOM Generation & Software Composition Analysis

Target image: `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SBOM Generation with Syft and Trivy

### Package Type Distribution

| Package Type | Syft | Trivy |
|-------------|-----:|------:|
| npm         | 1128 | 1125  |
| deb         |   10 |   10  |
| binary      |    1 |    0  |
| **Total**   | **1139** | **1135** |

Syft detected 4 more packages overall. The difference comes from a single binary artifact (`node`) that Trivy skips and 3 additional npm packages (`baz`, `browser_field`, `false_main`, `invalid_main`, `hashids-esm` — test/fixture packages with `UNKNOWN` versions) that Syft picks up from the filesystem but Trivy filters out. Trivy uniquely found `portscanner@2.2.0` and `toposort-class@1.0.1` that Syft missed.

Debian packages overlap fully in name but differ in version format:
- Syft uses the full Debian version (e.g. `12.2.0-14+deb12u1`)
- Trivy uses the upstream version only (e.g. `12.2.0`)

This causes `comm` to report them as distinct even though they refer to the same package.

### Dependency Discovery Analysis

Syft produced a 3.5 MB native JSON SBOM with full artifact metadata: locations (layer info, filesystem paths), CPE identifiers, and PURL references. Its dependency graph is oriented around what is physically present in the image layers.

Trivy produced a 1.2 MB JSON with a `Results[]` structure grouped by scan target (OS packages vs. language packages). Each package includes `InstalledVersion`, `FixedVersion` (when a fix exists), and layer metadata. Trivy's approach is more vulnerability-assessment-oriented — it records packages alongside their known vulnerabilities in one pass.

**Verdict:** Syft discovers slightly more packages (including edge cases like binaries and test fixtures) and provides richer SBOM metadata. Trivy focuses on actionable packages with vulnerability context.

### License Discovery Analysis

| Metric | Syft | Trivy |
|--------|-----:|------:|
| Unique license types | 32 | 28 |
| Packages with license data | 1128 | ~1110 |

**Top licenses (both tools):** MIT (~890), ISC (~143), LGPL-3.0 (~19), BSD-3-Clause (~15), Apache-2.0 (~15)

Syft uses SPDX license identifiers but also returns raw/non-standard values (e.g. `GPL-2`, `GPL`, `MIT/X11`, a raw SHA256 hash). Trivy normalizes to SPDX format more consistently (e.g. `GPL-2.0-only`, `LGPL-3.0-only`).

**Notable license risks identified:**
- LGPL-3.0 (19 packages) — copyleft, requires source disclosure for modifications
- GPL-2/GPL-3 variants (~15 packages) — strong copyleft
- MPL-2.0 (2 packages) — file-level copyleft

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### Vulnerability Severity Breakdown

| Severity   | Grype | Trivy |
|------------|------:|------:|
| Critical   |    11 |    11 |
| High       |   112 |    93 |
| Medium     |    56 |    60 |
| Low        |     8 |    23 |
| Negligible |    12 |     0 |
| Unknown    |     2 |     0 |
| **Total**  | **201** | **187** |

Grype reports more total vulnerabilities (201 vs 187), primarily due to additional High-severity findings and its inclusion of Negligible/Unknown categories that Trivy omits. Trivy reports more Low-severity issues (23 vs 8), suggesting different severity classification thresholds.

### Top 5 Critical Vulnerabilities

| CVE / GHSA | Package | Description | Both Tools? |
|-----------|---------|-------------|:-----------:|
| GHSA-whpj-8f3w-67p5 / CVE-2023-32314 | vm2@3.9.17 | Sandbox escape — attacker can run arbitrary code outside VM | Yes |
| GHSA-g644-9gfx-q4q4 / CVE-2023-37466 | vm2@3.9.17 | Promise handler bypass enables sandbox escape | Yes |
| GHSA-c7hr-j4mj-j2w6 / CVE-2015-9235 | jsonwebtoken@0.1.0, @0.4.0 | JWT verification bypass via altered token | Yes |
| GHSA-xwcq-pm8m-c4vf / CVE-2023-46233 | crypto-js@3.3.0 | PBKDF2 1,000x weaker than 1993 spec | Yes |
| CVE-2025-15467 | libssl3@3.0.17 | OpenSSL RCE/DoS via oversized InitialClientHello | Trivy only |

**Remediation priorities:**
1. **vm2** — deprecated, no fix available. Replace with `isolated-vm` or Node.js `vm` module with `--experimental-vm-modules`
2. **jsonwebtoken** — upgrade from 0.1.0/0.4.0 to >=9.0.0
3. **crypto-js** — upgrade from 3.3.0 to >=4.2.0
4. **libssl3** — update base image to get patched OpenSSL
5. **lodash@2.4.2** — upgrade to >=4.17.21

### Secrets Scanning (Trivy)

Trivy's secrets scanner found **4 embedded secrets** across the image:

| File | Type | Severity |
|------|------|----------|
| `/juice-shop/build/lib/insecurity.js` | RSA Private Key | HIGH |
| `/juice-shop/frontend/src/app/app.guard.spec.ts` | Hardcoded credential | MEDIUM |
| 2 additional files | Hardcoded credentials | MEDIUM |

The RSA private key in `insecurity.js` is particularly concerning — it is used for JWT signing and is bundled directly in the application code. This is an intentional vulnerability in the Juice Shop demo, but in a real application would be critical.

**Note:** Grype does not perform secrets scanning — this is a Trivy-exclusive capability.

### License Compliance Assessment

| License Category | Count | Risk Level |
|-----------------|------:|------------|
| MIT, ISC, BSD | ~1050 | Permissive — low risk |
| Apache-2.0 | ~15 | Permissive with patent grant |
| LGPL-3.0 | 19 | Weak copyleft — moderate risk |
| GPL-2/GPL-3 | ~15 | Strong copyleft — high risk |
| MPL-2.0 | 2 | File-level copyleft |
| WTFPL, Unlicense | ~5 | Public domain equivalent |

GPL-licensed packages in a web application bundled with npm are generally acceptable since the application is not distributed as a binary. However, if this software were distributed to customers, the GPL dependencies would require source code disclosure.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy

### Package Detection Accuracy

| Metric | Count |
|--------|------:|
| Packages detected by both | 1126 |
| Syft-only packages | 13 |
| Trivy-only packages | 9 |
| **Overlap rate** | **~99%** |

Package detection overlap is very high. The Syft-only packages are mostly test fixtures with `UNKNOWN` versions and Debian packages with full version strings. The Trivy-only packages include a few npm dependencies (`portscanner`, `toposort-class`) that Syft missed.

### Vulnerability Detection Overlap

| Metric | Count |
|--------|------:|
| Unique CVEs in Grype | 131 |
| Unique CVEs in Trivy | 116 |
| CVEs found by both | 37 |
| Grype-only CVEs | 94 |
| Trivy-only CVEs | 79 |
| **Overlap rate** | **~28%** |

The low CVE overlap (28%) is significant. This means relying on a single tool would miss a substantial number of vulnerabilities. Key reasons:
- **Different vulnerability databases** — Grype uses Anchore's feed (GitHub Advisories, NVD), Trivy uses its own aggregated DB
- **Different matching logic** — how each tool maps packages to CVEs, especially for transitive dependencies
- **Severity threshold differences** — Grype includes Negligible/Unknown, Trivy does not

### Strengths and Weaknesses

| Dimension | Syft + Grype | Trivy |
|-----------|-------------|-------|
| SBOM depth | Richer metadata (CPEs, PURLs, layer info) | Grouped by target, vulnerability-focused |
| Package detection | Slightly more packages (1139 vs 1135) | Cleaner version normalization |
| Vuln detection | More total CVEs (131 unique) | Fewer false positives, better severity normalization |
| Secrets scanning | Not supported | Built-in (found 4 secrets) |
| License scanning | Via SBOM metadata extraction | Dedicated scanner with compliance focus |
| Output formats | CycloneDX, SPDX, Syft-JSON, table | JSON, table, SARIF, CycloneDX, SPDX |
| Modularity | Separate tools, composable | All-in-one, simpler setup |

### Use Case Recommendations

| Use Case | Recommended Tool | Why |
|----------|-----------------|-----|
| Quick CI/CD gate | **Trivy** | Single binary, fast, all-in-one scanning |
| Compliance/audit SBOM | **Syft** | Richer SBOM metadata, better SPDX/CycloneDX output |
| Deep vulnerability analysis | **Both** | Only 28% CVE overlap — use both for maximum coverage |
| Secrets detection | **Trivy** | Grype has no secrets scanning capability |
| Supply chain attestation | **Syft** | Integrates with Cosign/in-toto via Anchore ecosystem |
| License compliance | **Trivy** | Dedicated license scanner with structured output |

### CI/CD Integration Considerations

- **Syft+Grype** requires two pipeline steps (generate SBOM, then scan). This adds complexity but enables SBOM reuse — generate once, scan with multiple tools, archive for compliance.
- **Trivy** runs as a single step with configurable scanners (`vuln,secret,license`). Lower operational overhead, easier to maintain.
- **Best practice:** Use Trivy as the primary CI gate (fast, comprehensive) and Syft for generating archival SBOMs that feed into supply chain security workflows (attestation, SBOM distribution).
- The 28% CVE overlap strongly argues for running both tools in critical pipelines where maximum vulnerability coverage is required.
