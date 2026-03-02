# Lab 4 Submission - SBOM Generation & Software Composition Analysis

## Student / Context
- Name: `Danil Fishchenko`
- Branch: `feature/lab4`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Scan date: `2026-03-02`
- Toolchain:
  - `anchore/syft:latest`
  - `anchore/grype:latest`
  - `aquasec/trivy:latest`

## Task 1 - SBOM Generation with Syft and Trivy

### 1.1 Environment setup
```bash
mkdir -p labs/lab4/{syft,trivy,comparison,analysis}
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```

### 1.2 SBOM generation commands

#### Syft
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 \
  -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 \
  -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt
```

#### Trivy
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0
```

### 1.3 Output verification
Generated artifacts:
- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab4/syft/juice-shop-syft-table.txt`
- `labs/lab4/syft/juice-shop-licenses.txt`
- `labs/lab4/trivy/juice-shop-trivy-detailed.json`
- `labs/lab4/trivy/juice-shop-trivy-table.txt`

SBOM sizes:
- Syft native JSON: `3,665,408` bytes
- Trivy detailed JSON: `1,334,298` bytes

### 1.4 Package type distribution

Syft package types (from native SBOM):
- `npm`: `1128`
- `deb`: `10`
- `binary`: `1`
- **Total**: `1139`

Trivy package detection (from detailed JSON):
- `Node.js (lang-pkgs)`: `1125`
- `Debian OS packages (os-pkgs)`: `10`
- **Total**: `1135`

Observations:
- Both tools strongly agree on dependency inventory scale (difference only `4` packages in raw totals).
- Syft includes additional metadata-like pseudo-artifacts (`baz@UNKNOWN`, `false_main@UNKNOWN`, etc.) that Trivy does not list.

### 1.5 Dependency discovery analysis
Raw package-set comparison (`name@version`):
- Detected by both: `1126`
- Only Syft: `13`
- Only Trivy: `9`

Examples:
- Syft-only: `node@22.18.0`, `libssl3@3.0.17-1~deb12u2`, `false_main@UNKNOWN`
- Trivy-only: `libssl3@3.0.17`, `portscanner@2.2.0`, `toposort-class@1.0.1`

Interpretation:
- Major discrepancy is **version normalization** for Debian packages (e.g., `3.0.17-1~deb12u2` vs `3.0.17`).
- Small discrepancy also comes from tool-specific package cataloging rules (Syft pseudo-artifacts vs Trivy package filtering).

### 1.6 License discovery analysis
Unique license types:
- Syft: `32`
- Trivy license scanner: `28`

Most frequent licenses (Trivy license scan):
- `MIT`: `878`
- `ISC`: `143`
- `LGPL-3.0-only`: `19`
- `BSD-3-Clause`: `14`
- `Apache-2.0`: `13`

Assessment:
- Syft gives slightly richer raw license diversity.
- Trivy provides structured license results integrated with package scan flow and easier downstream policy checks.

## Task 2 - SCA with Grype and Trivy

### 2.1 SCA execution

#### Grype (SBOM-driven)
```bash
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json > labs/lab4/syft/grype-vuln-results.json

docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table > labs/lab4/syft/grype-vuln-table.txt
```

#### Trivy (image-driven)
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --scanners secret --format table \
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --scanners license --format json \
  --output /tmp/labs/lab4/trivy/trivy-licenses.json \
  bkimminich/juice-shop:v19.0.0
```

### 2.2 Vulnerability severity comparison

| Tool | Critical | High | Medium | Low | Negligible | Total |
|---|---:|---:|---:|---:|---:|---:|
| Grype | 11 | 88 | 32 | 3 | 12 | 146 |
| Trivy | 10 | 81 | 34 | 18 | 0 | 143 |

Key point:
- Both tools identify a similar high-risk profile with large `CRITICAL+HIGH` volume.

### 2.3 Top 5 most critical findings and remediation

| Rank | Vulnerability | Package | Installed | Fixed | Why critical | Remediation |
|---:|---|---|---|---|---|---|
| 1 | `CVE-2023-32314` | `vm2` | `3.9.17` | `3.9.18` | Sandbox escape (RCE class risk) | Upgrade `vm2` to `>=3.9.18`, run regression tests for sandbox behavior |
| 2 | `CVE-2023-37466` | `vm2` | `3.9.17` | `3.10.0` | Sandbox bypass via Promise handler path | Upgrade `vm2` to `>=3.10.0` (prefer latest patched) |
| 3 | `CVE-2023-37903` | `vm2` | `3.9.17` | `N/A` | Sandbox escape via custom inspect path | Replace/avoid `vm2` where possible; add runtime isolation/deny untrusted code execution |
| 4 | `CVE-2015-9235` | `jsonwebtoken` | `0.1.0/0.4.0` | `4.2.2` | Token verification bypass (auth integrity risk) | Upgrade `jsonwebtoken` to `>=4.2.2` (prefer modern maintained major), add JWT alg allowlist tests |
| 5 | `CVE-2025-15467` | `libssl3` | `3.0.17-1~deb12u2` | `3.0.18-1~deb12u2` | OpenSSL RCE/DoS surface in crypto stack | Rebuild image on updated Debian base with patched OpenSSL |

### 2.4 Additional security features - secrets scanning
Trivy secret scan findings:
- Total findings: `4`
- Severity split: `HIGH=2`, `MEDIUM=2`
- Locations include:
  - `/juice-shop/lib/insecurity.ts`
  - `/juice-shop/build/lib/insecurity.js`
  - test spec files with JWT examples

Assessment:
- Findings align with intentionally vulnerable/demo content in Juice Shop.
- In real production images, these would require immediate clean-up, history purge, and key rotation.

### 2.5 License compliance assessment
Potentially risky licenses (counted entries):
- `GPL-family`: `9`
- `LGPL-family`: `21`
- `WTFPL (strict Name == "WTFPL")`: `1`
- `WTFPL-containing expressions (Name contains "WTFPL")`: `4`
- `ad-hoc`: `1`

Counting method is documented in:
- `labs/lab4/analysis/license-risk-metrics.txt`

Risk-based compliance recommendations:
- Define allowed/restricted license policy (SPDX-driven) in CI.
- Manually review `ad-hoc`, strict `WTFPL`, and composite expressions containing `WTFPL`.
- For copyleft packages (`GPL/LGPL`), validate distribution model and legal obligations before release.

## Task 3 - Toolchain Comparison: Syft+Grype vs Trivy

### 3.1 Accuracy and coverage metrics
From generated comparison files:
- Packages detected by both tools: `1126`
- Packages only in Syft: `13`
- Packages only in Trivy: `9`
- CVEs found by Grype (raw method): `95`
- CVEs found by Trivy: `91`
- Common CVEs (raw method): `26`

### 3.2 Strengths and weaknesses

| Dimension | Syft + Grype | Trivy |
|---|---|---|
| SBOM richness | Strong Syft native metadata detail | Good package-centric metadata |
| Vulnerability scanning | Strong SBOM-oriented workflows, extra risk context in Grype | Strong all-in-one image scanning, very convenient |
| License scanning | Via SBOM metadata and downstream processing | Native built-in scanner and consistent output model |
| Secrets scanning | Not primary focus | Built-in secret scanning in same toolchain |
| Operational simplicity | Two-tool chain (more flexible, more moving parts) | Single tool (simpler CI onboarding) |

### 3.3 Use-case recommendations
- Choose **Syft+Grype** when:
  - You need SBOM-first pipelines and deep artifact-level control.
  - You want to decouple SBOM generation from vulnerability matching.
- Choose **Trivy** when:
  - You need fast all-in-one onboarding (vuln + secret + license).
  - You prefer minimal CI complexity and single CLI integration.

### 3.4 Integration considerations (CI/CD)
Recommended practical model:
1. Generate SBOM on every build (`Syft` or Trivy SBOM mode).
2. Scan image on every PR with Trivy (`vuln,secret,license`).
3. Run Grype as second opinion in nightly jobs for drift/coverage checks.
4. Fail gates:
   - Block on any `CRITICAL` vulnerability unless approved exception exists.
   - Block on secrets `HIGH`.
   - Block on disallowed licenses (`ad-hoc`, policy-denied GPL classes depending on distribution).

## Bonus - Extended Analysis and Hardening Add-ons

### B1. Identifier normalization bonus (important for fair comparison)
Raw CVE overlap (`26`) is misleading because Grype frequently reports `GHSA-*` as primary IDs while Trivy reports `CVE-*`.

Expanded method (including Grype `relatedVulnerabilities[].id` CVEs):
- Expanded Grype CVE set: `93`
- Common CVEs with Trivy: `85`

Conclusion:
- True practical overlap is high after identifier harmonization.
- Always normalize advisory IDs before declaring "tool disagreement".

### B2. Prioritized remediation roadmap
- **P0 (24h):** Patch `vm2`, `jsonwebtoken`, `libssl3`; block new critical findings in CI.
- **P1 (7d):** Resolve repeated high-volume packages (`minimatch`, `tar`, `libc6` chains) through dependency updates/rebase.
- **P2 (30d):** Establish formal license allow/deny policy and secret-baseline suppression policy for test fixtures.

### B3. Execution notes / issues encountered
- Parallel execution of two Trivy scans can race on temp files (`/tmp/trivy-*`); secret scan was rerun sequentially and succeeded.
- Trivy DB refresh was performed during runs, so exact counts may drift on future dates as advisories evolve.
- Grype reproducibility can be environment-dependent: if DB download fails (for example, TLS handshake timeout to `grype.anchore.io`), full local re-generation may fail even when existing artifacts are valid.
- Existing `labs/lab4/syft/grype-vuln-results.json` is valid and includes fresh DB metadata (`built: 2026-03-02T06:29:29Z`, `valid: true`), which can be verified via `.descriptor.db.status`.

## Files delivered
- `labs/submission4.md`
- `labs/lab4/syft/*`
- `labs/lab4/trivy/*`
- `labs/lab4/analysis/*`
- `labs/lab4/comparison/*`
