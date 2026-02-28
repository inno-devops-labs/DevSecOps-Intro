# Lab 4 - SBOM Generation and SCA Comparison

## Scope
- Target image: `bkimminich/juice-shop:v19.0.0`
- SBOM tools: `Syft`, `Trivy`
- SCA tools: `Grype`, `Trivy`

## Task 1 - SBOM Generation with Syft and Trivy

### Generated Artifacts
- Syft:
  - `labs/lab4/syft/juice-shop-syft-native.json`
  - `labs/lab4/syft/juice-shop-syft-table.txt`
  - `labs/lab4/syft/juice-shop-licenses.txt`
- Trivy:
  - `labs/lab4/trivy/juice-shop-trivy-detailed.json`
  - `labs/lab4/trivy/juice-shop-trivy-table.txt`
- Analysis:
  - `labs/lab4/analysis/sbom-analysis.txt`

### Package Type Distribution
| Tool | Package types and counts | Total |
|---|---|---:|
| Syft | `npm: 1128`, `deb: 10`, `binary: 1` | 1139 |
| Trivy | `Node.js: 1125`, `debian OS pkgs: 10` | 1135 |

### Dependency Discovery Analysis
- Common packages detected by both tools: `1126`
- Packages only in Syft: `13`
- Packages only in Trivy: `9`
- Observation: Syft discovered slightly more package entries and richer artifact typing (`binary/deb/npm`), while Trivy grouped package classes more coarsely.

### License Discovery Analysis
- Syft unique license values found: `32`
- Trivy unique license values found: `28`
- Observation: Syft found broader license metadata coverage. Trivy still provided useful OS vs Node package split for license review.

## Task 2 - SCA with Grype and Trivy

### Generated Artifacts
- Grype:
  - `labs/lab4/syft/grype-vuln-results.json`
  - `labs/lab4/syft/grype-vuln-table.txt`
- Trivy:
  - `labs/lab4/trivy/trivy-vuln-detailed.json`
  - `labs/lab4/trivy/trivy-secrets.txt`
  - `labs/lab4/trivy/trivy-licenses.json`
- Analysis:
  - `labs/lab4/analysis/vulnerability-analysis.txt`

### SCA Tool Comparison (Vulnerability Counts)
| Severity | Grype | Trivy |
|---|---:|---:|
| Critical | 11 | 10 |
| High | 60 | 81 |
| Medium | 31 | 34 |
| Low | 3 | 18 |
| Negligible | 12 | 0 |

### Top 5 Critical Findings and Remediation
| Vulnerability | Package | Installed | Fixed | Risk | Remediation |
|---|---|---|---|---|---|
| CVE-2025-15467 | `libssl3` | `3.0.17-1~deb12u2` | `3.0.18-1~deb12u2` | OpenSSL CMS parsing RCE/DoS risk | Rebuild image with patched Debian base and pin updated OpenSSL packages |
| CVE-2023-32314 | `vm2` | `3.9.17` | `3.9.18` | Sandbox escape | Upgrade `vm2` immediately or remove sandbox dependency |
| CVE-2023-37466 | `vm2` | `3.9.17` | `3.10.0` | Sandbox escape via Promise handling | Upgrade to patched version and add runtime isolation controls |
| CVE-2015-9235 | `jsonwebtoken` | `0.1.0/0.4.0` | `4.2.2` | Token verification bypass | Upgrade `jsonwebtoken` to current maintained version and enforce algorithm allowlist |
| CVE-2023-46233 | `crypto-js` | `3.3.0` | `4.2.0` | Weak PBKDF2 defaults | Upgrade to fixed version and enforce strong KDF parameters |

### License Compliance Assessment
- Risky/compliance-sensitive license families found: `GPL`, `LGPL`, `GPL-1`, `GPL-2`, `GPL-3`, `LGPL-2.1`, `LGPL-3.0`.
- Additional review-needed license values: `ad-hoc`, `public-domain`, and mixed-license expressions.
- Recommendations:
  - Maintain an allow/deny policy for copyleft licenses in production builds.
  - Track package-level exceptions with legal approval.
  - Re-check licenses in CI on every dependency update.

### Additional Security Features - Secret Scanning
- Trivy secret scanner reported findings in Juice Shop source (for example test JWT token patterns and embedded private-key material).
- Interpretation: this is expected for a deliberately vulnerable training target, but in real production images such findings should block release.

## Task 3 - Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### Accuracy Analysis
| Metric | Value |
|---|---:|
| Common packages | 1126 |
| Syft-only packages | 13 |
| Trivy-only packages | 9 |
| Grype CVEs | 90 |
| Trivy CVEs | 91 |
| Common CVEs | 26 |

### Tool Strengths and Weaknesses
| Approach | Strengths | Weaknesses |
|---|---|---|
| Syft + Grype | Strong SBOM detail and good control over dedicated steps | More moving parts; DB/update plumbing overhead |
| Trivy all-in-one | One tool for vuln/secrets/licenses and straightforward CI integration | Less granular SBOM metadata than Syft in this run |

### Use Case Recommendations
- Choose `Syft + Grype` when you need:
  - High SBOM fidelity and explicit toolchain separation
  - Independent SBOM lifecycle from vulnerability scanning
- Choose `Trivy` when you need:
  - Fast all-in-one scans in CI/CD
  - Consistent vuln + secret + license checks from one command set

### Integration Considerations
- CI/CD:
  - Cache vulnerability databases to avoid repeated 80MB+ downloads per run.
  - Export JSON artifacts on each pipeline for auditability.
- Operations:
  - Normalize severity naming across tools before SLA mapping.
  - Use overlap metrics (common/unique CVEs) to tune triage confidence.

## Challenges and Resolutions
- Challenge: `anchore/grype` DB update endpoint (`toolbox-data.anchore.io`) was not reachable in this environment.
- Resolution: used a DB-bundled Grype image (`stianovrevage/grype-with-db`) to complete required Grype outputs while keeping scan logic and output format Grype-compatible.
- Challenge: Trivy DB downloads are slow on first run.
- Resolution: persisted Trivy cache under `labs/lab4/trivy/cache` and used `--skip-db-update` for subsequent scans.
