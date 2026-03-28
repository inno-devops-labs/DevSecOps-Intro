# Lab 4 Submission: Syft+Grype vs Trivy

## Data Sources
- `labs/lab4/analysis/sbom-analysis.txt`
- `labs/lab4/analysis/vulnerability-analysis.txt`
- `labs/lab4/comparison/accuracy-analysis.txt`
- `labs/lab4/comparison/{common-packages.txt,syft-only.txt,trivy-only.txt,grype-cves.txt,trivy-cves.txt}`
- `labs/lab4/syft/{juice-shop-syft-native.json,grype-vuln-results.json}`
- `labs/lab4/trivy/{juice-shop-trivy-detailed.json,trivy-vuln-detailed.json,trivy-licenses.json,trivy-secrets.txt}`

## Package Type Distribution Comparison (Syft vs Trivy)
| Tool | Package Types | Counts | Total |
|---|---|---:|---:|
| Syft | `npm`, `deb`, `binary` | `npm=1128`, `deb=10`, `binary=1` | `1139` |
| Trivy | `node-pkg`, `debian` | `node-pkg=1125`, `debian=10` | `1135` |

Observations:
- Syft reports one extra package type (`binary`) and 4 more total packages.
- Both tools strongly agree on ecosystem composition (mostly Node.js + small Debian OS layer).

## Dependency Discovery Analysis
- Common package detections: `1126`
- Syft-only detections: `13`
- Trivy-only detections: `9`
- Conclusion: Syft found slightly more dependency records overall (`1139` vs `1135`), while Trivy still detected a few packages Syft missed.

Quality differences:
- Syft captured a `binary` runtime dependency (`node@22.18.0`) and more distro-specific version strings (for example Debian revision suffixes).
- Trivy included a couple of unique Node dependencies (for example `portscanner@2.2.0`, `toposort-class@1.0.1`) and also normalizes some OS package versions.
- Practical outcome: treat Syft as slightly broader for SBOM completeness, and Trivy as a strong cross-check.

## License Discovery Analysis
- Syft unique license types: `32`
- Trivy unique license types: `28`
- Trivy compliance categories: `restricted=30`, `reciprocal=2`, `forbidden=1`, `unknown=10`, `notice=1068`, `unencumbered=3`

Conclusion:
- Syft found more/broader raw license expressions.
- Trivy provided better compliance context by assigning policy categories and severities to licenses.

## SCA Tool Comparison (Vulnerability Detection Capabilities)
Severity distribution:

| Tool | Critical | High | Medium | Low | Negligible |
|---|---:|---:|---:|---:|---:|
| Grype (from Syft SBOM) | 11 | 86 | 32 | 3 | 12 |
| Trivy | 10 | 81 | 34 | 18 | 0 |

Coverage comparison:
- Unique vulnerability IDs found by Grype: `93`
- Unique vulnerability IDs found by Trivy: `91`
- Common IDs between both: `26`
- Grype-only IDs: `67`
- Trivy-only IDs: `65`

Conclusion:
- Grype detected slightly more critical/high issues in this run.
- Trivy detected a similarly large but different set of vulnerabilities, so using both improves coverage.

## Critical Vulnerabilities Analysis (Top 5 + Remediation)
| Vulnerability | Package (Installed) | Evidence | Remediation |
|---|---|---|---|
| `CVE-2023-32314` | `vm2@3.9.17` | Trivy critical (CVSS up to 10.0), Grype critical (`GHSA-whpj-8f3w-67p5`) | Upgrade to `vm2>=3.9.18` immediately; prefer latest `3.10.x`. |
| `CVE-2023-37466` | `vm2@3.9.17` | Trivy critical (CVSS up to 10.0), Grype critical (`GHSA-cchq-frgv-rjh5`) | Upgrade to `vm2>=3.10.0` (or latest). |
| `CVE-2025-15467` | `libssl3@3.0.17-1~deb12u2` | Trivy critical (CVSS 9.8), Grype critical | Upgrade OS package to `3.0.18-1~deb12u2` or newer base image. |
| `CVE-2015-9235` | `jsonwebtoken@0.1.0/0.4.0` | Trivy critical (CVSS up to 9.8), Grype critical (`GHSA-c7hr-j4mj-j2w6`) | Upgrade to `jsonwebtoken>=4.2.2` minimum; target modern maintained major (`>=9`) to reduce additional JWT risks. |
| `CVE-2023-46233` | `crypto-js@3.3.0` | Trivy critical (CVSS 9.1), Grype critical (`GHSA-xwcq-pm8m-c4vf`) | Upgrade to `crypto-js>=4.2.0`. |

## License Compliance Assessment
High-risk license indicators from Trivy:
- `forbidden`: `WTFPL` (`truncate-utf8-bytes`) flagged as `CRITICAL`.
- `restricted` (30 entries): multiple `GPL-*` and `LGPL-*` licenses.
- `reciprocal` (2 entries): `MPL-2.0`.

Notable patterns:
- `LGPL-3.0-only` appears across many `web3*` packages.
- Syft also shows copyleft-heavy footprint (`GPL/LGPL` family entries) and a few ambiguous entries (`ad-hoc`, `public-domain`, hash-like license values).

Compliance recommendations:
1. Block `forbidden` licenses in CI (start with `WTFPL` finding).
2. Require legal review for `restricted` and `reciprocal` categories before production release.
3. Prefer permissive-license alternatives for copyleft-heavy transitive dependencies where feasible.
4. Maintain an allow/deny license policy file and fail builds on policy violations.

## Additional Security Features (Secrets Scanning Results)
Trivy secrets scan found `4` findings:
- `HIGH`: Asymmetric private key in `/juice-shop/build/lib/insecurity.js:47`
- `HIGH`: Asymmetric private key in `/juice-shop/lib/insecurity.ts:23`
- `MEDIUM`: JWT token in `/juice-shop/frontend/src/app/app.guard.spec.ts:38`
- `MEDIUM`: JWT token in `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:61`

Syft+Grype did not provide secret scanning in these artifacts.

Recommended actions:
1. Rotate and revoke exposed private keys.
2. Remove hardcoded secrets/tokens from source and build artifacts.
3. Add pre-commit + CI secret scanning gates.

## Accuracy Analysis (Quantified Overlap)
Package detection:
- Intersection: `1126`
- Union: `1148` (`1126 + 13 + 9`)
- Jaccard overlap: `98.08%`
- Syft overlap rate: `98.86%` (`1126/1139`)
- Trivy overlap rate: `99.21%` (`1126/1135`)

Vulnerability detection:
- Intersection: `26`
- Union: `158` (`93 + 91 - 26`)
- Jaccard overlap: `16.46%`
- Grype common-rate: `27.96%` (`26/93`)
- Trivy common-rate: `28.57%` (`26/91`)

Interpretation:
- Package discovery is highly consistent between tools.
- Vulnerability overlap is low due to different advisory sources, namespaces, and matching logic.

## Tool Strengths and Weaknesses
Syft + Grype strengths:
- Very strong SBOM generation depth and package metadata.
- Grype provides useful prioritization context (risk/EPSS in table output).
- Slightly higher critical/high vulnerability count in this lab.

Syft + Grype weaknesses:
- No built-in secrets findings in the provided workflow.
- License output is rich but less policy-oriented unless post-processed.

Trivy strengths:
- Unified scanner for vulnerabilities, licenses, and secrets.
- License categories/severity are immediately actionable for compliance policy.
- Found meaningful secret exposures in code/build artifacts.

Trivy weaknesses:
- Slightly fewer dependencies and criticals than Syft+Grype in this dataset.
- Vulnerability set differs significantly from Grype, so single-tool usage may miss issues.

## Use Case Recommendations
Choose Syft+Grype when:
- SBOM quality and dependency inventory depth are the primary goal.
- You want EPSS/risk-oriented vulnerability triage from Grype outputs.

Choose Trivy when:
- You want one tool for SCA + license policy + secrets scanning.
- You need simpler CI/CD integration with a single scanner binary/workflow.

Best practice for production:
- Use both in layered mode: Syft+Grype for SBOM/SCA depth, Trivy for broader security controls and policy gating.

## Integration Considerations (CI/CD and Operations)
CI/CD design:
1. Generate SBOM via Syft on each build artifact/image.
2. Scan SBOM/image with Grype for vulnerability depth.
3. Run Trivy for vulnerability cross-check + license + secrets policies.
4. Gate merges/releases on thresholds (`critical/high vuln`, `forbidden/restricted license`, `any secrets`).

Operational considerations:
- Normalize vulnerability identifiers (CVE/GHSA/etc.) before dashboards/SLAs, because raw overlap is low.
- Keep scanner DB updates frequent to reduce stale results.
- Store scan artifacts (`json`, `table`, policy decisions) for auditability and trend analysis.
