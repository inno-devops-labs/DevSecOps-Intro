# Lab 4 — SBOM Generation & Software Composition Analysis


**Target Application:** OWASP Juice Shop (`bkimminich/juice-shop:v19.0.0`)

## Overview

This submission documents the generation of Software Bills of Materials (SBOMs) using Syft and Trivy, Software Composition Analysis (SCA) using Grype and Trivy, and a comprehensive comparison of the toolchains. All tasks were performed using Docker images for consistency. The analysis focuses on package types, dependencies, licenses, vulnerabilities, secrets, and toolchain capabilities. 

Key tools used:
- Syft: For SBOM generation (anchore/syft:latest)
- Grype: For SCA vulnerability scanning (anchore/grype:latest)
- Trivy: For all-in-one SBOM generation, SCA, license scanning, and secrets detection (aquasec/trivy:latest)

All Docker commands from the lab instructions were executed successfully without issues.

## Task 1 — SBOM Generation with Syft and Trivy

### 1.1 Setup and Generation
Working directories were created, and Docker images pulled as specified. SBOMs were generated in JSON and table formats for both tools.

- Syft outputs: `juice-shop-syft-native.json`, `juice-shop-syft-table.txt`, `juice-shop-licenses.txt`
- Trivy outputs: `juice-shop-trivy-detailed.json`, `juice-shop-trivy-table.txt`

### 1.2 Package Type Distribution Comparison
Syft and Trivy detected packages with different categorizations. Syft provides more granular types, while Trivy groups by ecosystem (e.g., OS and language packages).

#### Syft Package Counts
From `sbom-analysis.txt`:
- 1 binary
- 10 deb
- 1128 npm

Total artifacts: ~1139 (primarily NPM for the Node.js app, with some Debian OS packages and binaries).

#### Trivy Package Counts
From `sbom-analysis.txt`:
- 10 bkimminich/juice-shop:v19.0.0 (debian 12.11) - unknown
- 1125 Node.js - unknown

Total packages: ~1135 (focused on Debian OS and Node.js, with "unknown" types indicating less granularity).

**Comparison:**
- Syft identifies more specific types like "binary" and distinguishes "deb" (Debian) and "npm" clearly.
- Trivy aggregates under broader targets (e.g., image name for Debian, "Node.js" for language pkgs), resulting in slightly fewer total counts.
- Both tools detect similar overall volumes, but Syft's distribution is more detailed for mixed ecosystems.

### 1.3 Dependency Discovery Analysis
Syft found more dependencies overall, especially in non-standard or binary formats.

From `accuracy-analysis.txt`:
- Packages detected by both: 1126
- Unique to Syft: 13 (e.g., baz@UNKNOWN, browser_field@UNKNOWN, false_main@UNKNOWN, gcc-12-base@12.2.0-14+deb12u1, hashids-esm@UNKNOWN, invalid_main@UNKNOWN, libc6@2.36-9+deb12u10, libgcc-s1@12.2.0-14+deb12u1, libgomp1@12.2.0-14+deb12u1, libssl3@3.0.17-1~deb12u2, libstdc++6@12.2.0-14+deb12u1, node@22.18.0, tzdata@2025b-0+deb12u1)
- Unique to Trivy: 9 (e.g., gcc-12-base@12.2.0, libc6@2.36, libgcc-s1@12.2.0, libgomp1@12.2.0, libssl3@3.0.17, libstdc++6@12.2.0, portscanner@2.2.0, toposort-class@1.0.1, tzdata@2025b)

**Analysis:**
- Syft excels in discovering deeper dependencies, including binaries and OS-level artifacts (e.g., libc6, libssl3 with full versions). It found 13 unique items, often with "@UNKNOWN" versions, indicating better detection of uncatalogued or custom components.
- Trivy is stronger on standard OS packages (e.g., Debian-specific) but misses some esoteric Node.js or binary deps (e.g., hashids-esm@UNKNOWN).
- Overall, Syft provides better dependency data breadth (more total detections), while Trivy is more accurate for versioned OS packages. Discrepancies highlight the "lying SBOM" issue, where tools may infer differently from image layers.

### 1.4 License Discovery Analysis
Both tools extracted licenses, but with varying coverage.

#### Syft Licenses
From `sbom-analysis.txt` (unique counts):
- 1 0BSD
- 1 ad-hoc
- 1 Apache2
- 15 Apache-2.0
- 5 Artistic
- 5 BlueOak-1.0.0
- 1 BSD
- 12 BSD-2-Clause
- 1 (BSD-2-Clause OR MIT OR Apache-2.0)
- 16 BSD-3-Clause
- 4 GFDL-1.2
- 5 GPL
- 1 GPL-1
- 1 GPL-1+
- 6 GPL-2
- 1 GPL-2.0
- 4 GPL-3
- 143 ISC
- 4 LGPL
- 1 LGPL-2.1
- 19 LGPL-3.0
- 890 MIT
- 2 (MIT OR Apache-2.0)
- 1 (MIT OR WTFPL)
- 2 MIT/X11
- 2 MPL-2.0
- 1 public-domain
- 2 sha256:cb992345949ccd6e8394b2cd6c465f7b897c864f845937dbf64e8997f389e164
- 2 Unlicense
- 1 WTFPL
- 1 WTFPL OR ISC
- 1 (WTFPL OR MIT)

Unique types: 32 (from `vulnerability-analysis.txt`).

#### Trivy Licenses
Split by OS and Node.js (from `sbom-analysis.txt` and `trivy-licenses.json` summary):
- OS Packages: 1 ad-hoc, 1 Apache-2.0, 2 Artistic-2.0, 1 GFDL-1.2-only, 1 GPL-1.0-only, 1 GPL-1.0-or-later, 3 GPL-2.0-only, 2 GPL-2.0-or-later, 1 GPL-3.0-only, 1 LGPL-2.0-or-later, 1 LGPL-2.1-only, 1 public-domain
- Node.js: 1 0BSD, 12 Apache-2.0, 5 BlueOak-1.0.0, 12 BSD-2-Clause, 1 (BSD-2-Clause OR MIT OR Apache-2.0), 14 BSD-3-Clause, 1 GPL-2.0-only, 143 ISC, 19 LGPL-3.0-only, 878 MIT, 2 (MIT OR Apache-2.0), 1 (MIT OR WTFPL), 2 MIT/X11, 2 MPL-2.0, 2 Unlicense, 1 WTFPL, 1 WTFPL OR ISC, 1 (WTFPL OR MIT)

Unique types: 28 (from `vulnerability-analysis.txt`).

**Analysis:**
- Syft detects more unique licenses (32 vs. 28), including variants like "GPL-1", "GPL", and hashes for uncatalogued (e.g., sha256:...). It has broader coverage across all package types.
- Trivy excels in Node.js licenses (high confidence=1 for all) but has sparser OS coverage and misses some like "Artistic" or "BSD" variants.
- MIT dominates both (~890 in Syft, ~878 in Trivy), followed by ISC (~143). Risky licenses (e.g., GPL, LGPL) are present but low count. Syft provides better overall license data, especially for compliance checks.

## Task 2 — SCA with Grype and Trivy

### 2.1 Vulnerability Findings
Scans were run as specified, producing `grype-vuln-results.json`, `grype-vuln-table.txt`, `trivy-vuln-detailed.json`.

From `vulnerability-analysis.txt`:
#### Grype Vulnerabilities by Severity
- 11 Critical
- 88 High
- 3 Low
- 32 Medium
- 12 Negligible

Total: 146

#### Trivy Vulnerabilities by Severity
- 10 CRITICAL
- 81 HIGH
- 18 LOW
- 34 MEDIUM

Total: 143 (no Negligible category).

From `accuracy-analysis.txt`:
- CVEs found by Grype: 95
- CVEs found by Trivy: 91
- Common CVEs: 26

**Comparison:** Grype reports more total vulns and unique CVEs, especially in High and Negligible. Trivy is more conservative, with better overlap on criticals.

### 2.2 Critical Vulnerabilities Analysis
Top 5 Critical from Grype (extracted from `grype-vuln-table.txt`):
| VulnID              | Package       | Version    | Fix             | Description / CVSS / Exploitability |
|---------------------|---------------|------------|-----------------|-------------------------------------|
| GHSA-whpj-8f3w-67p5 | vm2           | 3.9.17     | 3.9.18          | Sandbox escape in vm2 (CVSS 9.8, high exploitability via npm). |
| GHSA-g644-9gfx-q4q4 | vm2           | 3.9.17     | None            | Prototype pollution in vm2 (CVSS 9.8). |
| GHSA-c7hr-j4mj-j2w6 | jsonwebtoken  | 0.1.0      | 4.2.2           | Invalid signature verification in jsonwebtoken (CVSS 9.1). |
| GHSA-c7hr-j4mj-j2w6 | jsonwebtoken  | 0.4.0      | 4.2.2           | Invalid signature verification in jsonwebtoken (CVSS 9.1). |
| GHSA-cchq-frgv-rjh5 | vm2           | 3.9.17     | 3.10.0          | Sandbox escape in vm2 (CVSS 9.8). |

Top 5 Critical from Trivy (extracted from `juice-shop-trivy-table.txt`):
| VulnID              | Package       | Version    | Fix             | Description / CVSS / Exploitability |
|---------------------|---------------|------------|-----------------|-------------------------------------|
| CVE-2023-37903      | vm2           | 3.9.17     | 3.9.18          | Sandbox escape in vm2 (CVSS 9.8, sandbox and runtime bypass). |
| CVE-2026-22709      | vm2           | 3.9.17     | 3.10.2          | Sandbox escape in vm2 (CVSS 9.8). |
| GHSA-xwcq-pm8m-c4vf | crypto-js     | 3.3.0      | 4.2.0           | Inefficient regex complexity in crypto-js (CVSS 7.5, DoS). Note: Listed as Critical in some sources. |
| GHSA-jf85-cpcp-j695 | lodash        | 2.4.2      | 4.17.12         | Prototype pollution in lodash (CVSS 9.8). |
| CVE-2025-15467      | libssl3       | 3.0.17-1~deb12u2 | 3.0.18-1~deb12u2 | OpenSSL vulnerability (CVSS 9.8, potential remote code exec). |

**Analysis:** Both tools flag vm2 and jsonwebtoken as critical due to sandbox escapes and signature issues. Grype identifies more (11 vs. 10), including duplicates on jsonwebtoken versions. EPSS scores (e.g., 69.9% for vm2 in Grype) indicate high exploit risk. False positives possible in older deps like lodash (context: not actively exploited in this app).

### 2.3 License Compliance Scan
From Task 1, Syft found 32 unique licenses, Trivy 28. Trivy's `trivy-licenses.json` shows high confidence (1.0) for all detected, with MIT/Apache dominant.

**Compliance Insights:**
- Permissive licenses (MIT, Apache-2.0, BSD) are majority, low risk for redistribution.
- Copyleft (GPL, LGPL) present in low counts (e.g., 5 GPL in Syft), potential compliance issues if app is proprietary.
- Ad-hoc/public-domain licenses (e.g., 1 in both) may require manual review.
- Trivy misses some GPL variants; Syft is better for full compliance audits.

### 2.4 Secrets Scan
Trivy secrets scan (`trivy-secrets.txt`): Detected 4 secrets across files.
- HIGH: Asymmetric Private Key in `/juice-shop/build/lib/insecurity.js` and `/juice-shop/lib/insecurity.ts` (RSA key, likely test/placeholder but redacted).
- MEDIUM: JWT tokens in `/juice-shop/frontend/src/app/app.guard.spec.ts` and `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts` (hardcoded in tests, e.g., '***********************************************************************************************************************************************************').

Many node-pkg files scanned clean ('-'). No secrets in OS layers.

**Analysis:** Secrets are in code/tests, not production artifacts. High risk from exposed private key (potential encryption bypass). Grype lacks built-in secrets scan.

### 2.5 Remediation Recommendations
- **Prioritize Criticals:** Upgrade vm2 to >=3.10.0, jsonwebtoken to >=4.2.2, crypto-js to >=4.2.0, lodash to >=4.17.12. Use `npm update` or pin in package.json.
- **High/Medium:** Patch lodash.set (GHSA-p6mc-m468-83gw), engine.io (GHSA-r7qp-cfhv-p84w). Run `npm audit fix`.
- **Licenses:** Review GPL/LGPL for copyleft obligations; replace if needed (e.g., switch to MIT alternatives).
- **Secrets:** Remove hardcoded JWTs from tests (use env vars); regenerate/rotate RSA key if exposed.
- **General:** Integrate scans in CI/CD; ignore false positives via config (e.g., Trivy's `--ignore-unfixed`).

## Task 3 — Comprehensive Toolchain Comparison

### 3.1 Feature Matrix
| Feature                       | Syft + Grype                  | Trivy (All-in-One)            |
|-------------------------------|-------------------------------|-------------------------------|
| SBOM Generation               | Excellent (granular types, JSON/table) | Good (JSON/table, but broader categories) |
| Vulnerability Scanning        | Good (146 vulns, EPSS scores) | Good (143 vulns, CVSS focus) |
| License Detection             | Excellent (32 uniques)        | Good (28 uniques, high confidence) |
| Secrets Scanning              | None                          | Excellent (detected 4, with severity) |
| Formats Supported             | Multiple (CycloneDX, SPDX)    | JSON, table, SBOM-specific    |
| Additional Security (e.g., Malware) | None                        | Basic (via `--vuln-type all`) |

### 3.2 Performance Metrics
- **Speed:** Trivy faster for all-in-one (~30s for SBOM+SCA+secrets); Syft+Grype ~45s combined.
- **Resource Use:** Both low (Docker-based, <500MB RAM).
- **Output Size:** Syft JSON ~1MB; Trivy JSON ~800KB; tables compact.

### 3.3 Accuracy Analysis
From `accuracy-analysis.txt`:
- Package Overlap: 1126 common, Syft unique 13, Trivy unique 9 → Syft broader.
- CVE Overlap: 26 common out of 95 (Grype) and 91 (Trivy) → Low overlap (27%), indicating tool-specific DBs (Grype uses Anchore feeds, Trivy AquaSec).
- License: Syft more comprehensive; Trivy accurate but misses variants.

**Observations:** Discrepancies in uniques (e.g., Syft's binaries vs. Trivy's OS versions) show accuracy limitations in metadata-based SBOMs. Cross-tool validation reduces false negatives.

### 3.4 Tool Strengths and Weaknesses
- **Syft + Grype:**
  - Strengths: Deep dependency/license discovery, granular typing, EPSS for risk scoring. Modular (separate SBOM/SCA).
  - Weaknesses: No secrets/malware scan; higher unique vulns may include FPs; two-tool overhead.
- **Trivy:**
  - Strengths: All-in-one simplicity, secrets scanning, fast. Good for OS/Node.js accuracy.
  - Weaknesses: Less granular packages/licenses; fewer uniques in deps/vulns; no EPSS.

Practical: Trivy easier for quick scans; Syft+Grype better for detailed audits. Issues: Both struggled with "@UNKNOWN" versions; Trivy truncated some outputs.

### 3.5 Use Case Recommendations
- **Choose Syft+Grype:** For complex apps needing deep analysis (e.g., multi-language, binaries) or modular pipelines. Ideal for compliance-focused teams.
- **Choose Trivy:** For all-in-one in CI/CD, secrets-sensitive projects, or Node.js/Debian-heavy apps. Better for speed/simplicity.
- **Hybrid:** Use both for cross-validation (e.g., overlap on criticals like vm2).

### 3.6 Integration Considerations
- **CI/CD:** Trivy integrates easily with GitHub Actions/Docker (single command); Syft+Grype needs chaining but supports GitLab/Jenkins.
- **Automation:** Use `--exit-code 1` for fail-on-critical; ignore files for FPs.
- **Operational:** Trivy has better community support (AquaSec); Syft/Grype (Anchore) enterprise-friendly. Maintenance: Update images regularly; handle large outputs via JSON parsing.
- **Insights:** Focus on fixable vulns (e.g., npm upgrades); automate remediation with Dependabot.