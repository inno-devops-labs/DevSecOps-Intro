# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1.8 MB
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 4 |
| Low | 35 |
| Negligible | 7 |  
| **Total** | 104 |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0           | 4.2.2           |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0           | 4.2.2           |
| GHSA-jf85-cpcp-j695 | Critical | loadash      | 2.4.2           | 4.17.12         |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js    | 3.3.0           | 4.2.0           |
| CVE-2026-5450       | Critical | libc6        | 2.41-12+deb13u2 |      -          |
| CVE-2026-34182      | Critical | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb       | 0.6.11          |      -          |
| GHSA-35jh-r3h4-6jhm | High     | loadash      | 2.4.2           | 4.17.21         |
| GHSA-8hfj-j24r-96c4 | High     | moment       | 2.0.0           | 2.29.2          |
| GHSA-p6mc-m468-83gw | High     | loadash.set  | 4.3.2           |      -          |


### Fix-available rate

Out of the top 10 CVEs, 7 have a fix available (70%). Following Lecture 4's triage shortcut — sort by fix-available AND severity ≥ HIGH first — I would immediately patch the Critical and High CVEs with known fixes: jsonwebtoken (2 Critical, fix 4.2.2), loadash (Critical + High, fix 4.17.12/4.17.21), crypto-js (Critical, fix 4.2.0), libssl3t64 (Critical, fix 3.5.6), and moment (High, fix 2.29.2). The remaining 3 unpatched CVEs (libc6, marsdb, loadash.set) require compensating controls or waiting for upstream vendor patches, as no direct dependency upgrade is currently available.


## Task 2: Trivy Comparison

### Side-by-side counts
| Severity  | Grype | Trivy | Δ  |
|-----------|------:|------:|---:|
| Critical  | 7     | 5     | -2 |
| High      | 51    | 43    | -8 |
| Medium    | 4     | 22    | 18 |
| Low       | 35    | 39    | 4  |
| **Total** | 97    | 109   | 12  |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:

1. **`NSWG-ECO-428` (base64url 0.0.6)** — Found by Trivy at HIGH severity, missed by Grype. Likely reason: `NSWG-ECO-428` is a Node.js Security Working Group advisory that Trivy's `vuln-list` database includes natively, while Grype's Anchore feed maps it differently or does not index this specific ecosystem-specific advisory. Grype's SBOM-based scan also focuses on declared npm dependencies and may not catch vulnerabilities in transitive packages that Trivy's direct image scan picks up from the `node_modules` tree.

2. **`CVE-2025-47935` through `CVE-2026-5079` (multer 1.4.5-lts.2, 8 CVEs)** — Found by Trivy, missed by Grype. Likely reason: Trivy's vulnerability database refreshes more frequently for newly published CVEs (these are 2025-2026 CVEs), while Grype's Anchore feed may lag behind on very recent advisories. Additionally, Trivy scans the actual installed package version in the image layers, while Grype matches against the SBOM component inventory, which may not capture all transitive multer sub-dependencies with the same precision.


(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

### When would you pick each?
2-3 sentences each:

- **Syft+Grype's decoupled model wins** when you need to treat the SBOM as a first-class, signed artifact for supply-chain attestations. The separation lets you generate the inventory once with Syft, sign the CycloneDX SBOM with Cosign, and re-run Grype against the same SBOM months later when new CVEs drop — without re-pulling the image. This decoupling is essential for long-term incident response, regulatory compliance (EO 14028), and reproducible triage workflows where the SBOM itself becomes a legally-signable document.

- **Trivy's all-in-one model wins** in CI pipelines where you want a single binary that scans container images, filesystems, IaC configs (Terraform, Kubernetes manifests), secrets, and license issues in one pass. It's simpler to install, has broader coverage (including OS packages like `libssl3t64`, Kubernetes misconfigurations, and cloud service scans), and caught the embedded RSA private keys in Juice Shop's source that Grype missed entirely. For fast "gate the build" decisions where speed and a unified SARIF report matter more than producing a separately signed SBOM artifact, Trivy is the pragmatic choice.