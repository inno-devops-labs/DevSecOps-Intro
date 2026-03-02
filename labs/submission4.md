# Lab 4 - SBOM Generation and SCA Comparison

## Scope and Target

- Target image: `bkimminich/juice-shop:v19.0.0`
- Analysis date: `2026-03-02`
- Tools:
  - `anchore/syft:latest`
  - `anchore/grype:latest`
  - `aquasec/trivy:latest`

## Commands Used

```bash
# Setup
mkdir -p labs/lab4/{syft,trivy,comparison,analysis}
docker pull anchore/syft:latest
docker pull anchore/grype:latest
docker pull aquasec/trivy:latest

# SBOM generation
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  anchore/syft:latest bkimminich/juice-shop:v19.0.0 \
  -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  anchore/syft:latest bkimminich/juice-shop:v19.0.0 \
  -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  aquasec/trivy:latest image --format json --list-all-pkgs \
  --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  aquasec/trivy:latest image --format table --list-all-pkgs \
  --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  bkimminich/juice-shop:v19.0.0

# Vulnerability and additional scans
docker run --rm -v "$(pwd):/tmp" anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json -o json \
  > labs/lab4/syft/grype-vuln-results.json

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  aquasec/trivy:latest image --format json \
  --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  aquasec/trivy:latest image --scanners secret --format table \
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  aquasec/trivy:latest image --scanners secret --format json \
  --output /tmp/labs/lab4/trivy/trivy-secrets.json \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd):/tmp" \
  aquasec/trivy:latest image --scanners license --format json \
  --output /tmp/labs/lab4/trivy/trivy-licenses.json \
  bkimminich/juice-shop:v19.0.0
```

## Task 1 - SBOM Generation with Syft and Trivy

### 1.1 Package Type Distribution

- Syft artifacts: `1139`
  - `npm`: `1128`
  - `deb`: `10`
  - `binary`: `1`
- Trivy packages: `1135`
  - Node.js packages: `1125`
  - Debian packages: `10`

### 1.2 Dependency Discovery Analysis

- Shared package entries (name+version): `988`
- Only Syft: `13`
- Only Trivy: `9`
- Observed pattern:
  - Syft reports several versions as `UNKNOWN` (for example `hashids-esm@UNKNOWN`), which affects exact matching.
  - Trivy normalizes some Debian versions differently (`libc6@2.36` vs `2.36-9+deb12u10`), reducing overlap even when they represent the same package family.

Conclusion: both tools provide strong dependency coverage; Syft exposes richer package taxonomy while Trivy output is simpler for quick counting.

### 1.3 License Discovery Analysis

- Unique license types:
  - Syft: `32`
  - Trivy: `28`
- Dominant licenses in Node ecosystem:
  - `MIT`, `ISC`, `BSD-*`, `Apache-2.0`
- Notable restrictive/copyleft licenses present:
  - `GPL-2.0-only`, `GPL-3.0-only`, `LGPL-*`

Conclusion: Syft delivered slightly broader license diversity; Trivy provided good package-linked license extraction with less variety.

## Task 2 - SCA with Grype and Trivy

### 2.1 SCA Tool Comparison (Vulnerability Detection)

- Grype severity counts:
  - Critical: `11`
  - High: `88`
  - Medium: `32`
  - Low: `3`
  - Negligible: `12`
- Trivy severity counts:
  - CRITICAL: `10`
  - HIGH: `81`
  - MEDIUM: `34`
  - LOW: `18`
- Unique vulnerability IDs:
  - Grype: `95`
  - Trivy: `91`
  - Common: `26`

Interpretation: both tools find serious risk; Grype showed slightly higher unique vulnerability count, while Trivy integrated vuln + secret + license in one runner.

### 2.2 Critical Vulnerabilities (Top 5) and Remediation

1. `CVE-2023-32314` (`vm2 3.9.17`, CVSS 10.0)
   - Fix: upgrade to `3.9.18` or newer.
2. `CVE-2023-37466` (`vm2 3.9.17`, CVSS 10.0)
   - Fix: upgrade to `3.10.0` or newer.
3. `CVE-2023-37903` (`vm2 3.9.17`, CVSS 10.0)
   - Fix: no fixed version in report (`N/A`); replace `vm2` usage or isolate/remove dependent feature.
4. `CVE-2026-22709` (`vm2 3.9.17`, CVSS 10.0)
   - Fix: upgrade to `3.10.2` or newer.
5. `CVE-2015-9235` (`jsonwebtoken 0.1.0/0.4.0`, CVSS 9.8)
   - Fix: upgrade to `4.2.2` or newer.

Priority recommendation: urgently remove/upgrade `vm2` and `jsonwebtoken` paths due to multiple critical RCE/sandbox-escape class issues.

### 2.3 License Compliance Assessment

Potential compliance-risk licenses detected:

- `GPL-2.0-only`
- `GPL-3.0-only`
- `LGPL-*` variants
- `ad-hoc` (requires manual legal review)
- `public-domain` (jurisdiction-dependent constraints)

Recommendations:

- Add policy gates in CI (deny/block for disallowed licenses).
- Require legal review for `ad-hoc`/custom declarations.
- Track copyleft dependencies and separate them from distributable proprietary components when needed.

### 2.4 Additional Security Features (Secrets Scanning)

Trivy secret scan findings: `4` potential secrets.

Detected paths:

- `/juice-shop/build/lib/insecurity.js`
- `/juice-shop/frontend/src/app/app.guard.spec.ts`
- `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts`
- `/juice-shop/lib/insecurity.ts`

Assessment: findings likely include intentionally insecure/demo material in Juice Shop, but still demonstrate that secret scanning should run in CI and be paired with allowlists for known training/demo cases.

## Task 3 - Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1 Accuracy Analysis

- Package overlap is high (`988` shared), but normalization differences impact exact-match metrics.
- Vulnerability overlap is partial (`26` common out of `95` Grype and `91` Trivy IDs), so single-tool blind spots are possible.
- Cross-tool validation is valuable for critical triage.

### 3.2 Tool Strengths and Weaknesses

- Syft + Grype strengths:
  - Strong SBOM detail and package metadata.
  - Good vulnerability depth and risk-oriented output.
- Syft + Grype weaknesses:
  - Two-tool workflow increases orchestration and maintenance overhead.
- Trivy strengths:
  - One tool for vulnerabilities, secrets, and licenses.
  - Easy CI/CD integration with unified command model.
- Trivy weaknesses:
  - Simplified package typing in this run (`unknown` in Type field), less granular SBOM detail vs Syft native output.

### 3.3 Use Case Recommendations

- Choose `Syft + Grype` when:
  - You need richer SBOM metadata and deeper package intelligence.
  - You want independent SBOM generation and vulnerability matching stages.
- Choose `Trivy` when:
  - You need fast operational adoption and one-command scans.
  - You want combined vuln + secret + license checks in CI with minimal setup.

### 3.4 Integration Considerations (CI/CD and Operations)

- For production pipelines, combine both approaches:
  - Use Syft to generate canonical SBOM artifacts for audit/compliance.
  - Run Trivy for broad integrated controls (vuln + secret + license).
  - Optionally run Grype on Syft SBOM for second-opinion vulnerability correlation.
- Practical pipeline controls:
  - Fail build on `CRITICAL` and selected `HIGH` severities.
  - Enforce license policy thresholds.
  - Publish SBOM and scan reports as build artifacts.
  - Track remediation SLAs (for example: critical in 24-72h).

## Issues Encountered

- Initial blocker: Docker daemon was not running (`dockerDesktopLinuxEngine` pipe missing).
- Resolution: started Docker Desktop, reran full scan chain successfully.

## Generated Artifacts

- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab4/syft/juice-shop-syft-table.txt`
- `labs/lab4/syft/juice-shop-licenses.txt`
- `labs/lab4/syft/grype-vuln-results.json`
- `labs/lab4/syft/grype-vuln-table.txt`
- `labs/lab4/trivy/juice-shop-trivy-detailed.json`
- `labs/lab4/trivy/juice-shop-trivy-table.txt`
- `labs/lab4/trivy/trivy-vuln-detailed.json`
- `labs/lab4/trivy/trivy-secrets.txt`
- `labs/lab4/trivy/trivy-secrets.json`
- `labs/lab4/trivy/trivy-licenses.json`
- `labs/lab4/analysis/sbom-analysis.txt`
- `labs/lab4/analysis/vulnerability-analysis.txt`
- `labs/lab4/comparison/accuracy-analysis.txt`
- `labs/lab4/comparison/*.txt` (package and CVE overlap lists)
