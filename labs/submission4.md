# Lab 4 — SBOM Generation & Software Composition Analysis


## 1. SBOM Generation

### 1.1 Syft

**Command used:**
```bash
docker run --rm -v $(pwd):/app anchore/syft \
  bkimminich/juice-shop:v19.0.0 \
  -o cyclonedx-json > labs/lab4/syft/juice-shop-syft-native.json
```

- **Format:** CycloneDX JSON  
- **Number of components:** 1001

**Example component:**
```json
{
  "name": "express",
  "version": "4.21.2",
  "licenses": [{ "license": { "id": "MIT" } }]
}
```

### 1.2 Trivy

**Command used:**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/app aquasec/trivy:latest image \
  --format cyclonedx \
  --output labs/lab4/trivy/juice-shop-trivy-detailed.json \
  bkimminich/juice-shop:v19.0.0
```

- **Format:** CycloneDX JSON  
- **Number of components:** 997

**Example component:**
```json
{
  "name": "lodash",
  "version": "4.17.21",
  "licenses": [{ "license": { "id": "MIT" } }]
}
```

---

## 2. Vulnerability Analysis (SCA)

### 2.1 Grype (based on Syft SBOM)

**Command used:**
```bash
docker run --rm -v $(pwd):/app anchore/grype \
  sbom:/app/labs/lab4/syft/juice-shop-syft-native.json \
  --output json > labs/lab4/syft/grype-vuln-results.json
```

**Results:**
- **Total vulnerabilities:** 65
- **Critical:** 8
- **High:** 21
- **Medium:** 23
- **Low:** 1
- Negligible/Other: 12

**Example findings:**
- GHSA-whpj-8f3w-67p5 — vm2 3.9.17 — CVSS 9.8 (Critical)
- CVE-2025-4802 — libc6 2.36-9+deb12u10 — CVSS 7.8 (High)

### 2.2 Trivy

**Command used:**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/app aquasec/trivy:latest image \
  --format json --list-all-pkgs \
  --output labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0
```

**Results:**
- **Total vulnerabilities:** 70
- **Critical:** 8
- **High:** 23
- **Medium:** 23
- **Low:** 16

**Example findings:**
- CVE-2023-37466 — vm2 3.9.17 — CVSS 10 (Critical)
- CVE-2024-29415 — ip 2.0.1 — CVSS 9.8 (High)

**License summary (from `trivy-licenses.json`):**
- MIT — **883** packages
- Apache-2.0 — **16** packages
- GPL-3.0 — **1** packages

---

## 3. Toolchain Comparison

| Feature / Capability         | Syft + Grype                         | Trivy                          |
|-----------------------------|--------------------------------------|--------------------------------|
| SBOM generation             | ✅ Syft (CycloneDX, SPDX)            | ✅ CycloneDX                   |
| Vulnerability scanning      | ✅ Grype                              | ✅ built-in                    |
| License detection           | limited                            | ✅ full                        |
| Secret scanning             | ❌                                    | ✅                             |
| Config & misconfig detection| ❌                                    | ✅                             |
| Ease of use                 | Two separate tools                    | Single binary                  |
| CI/CD integration           | Good (but two steps)                  | Very simple (one step)         |
| Speed                       | Slightly faster on SBOM+scan split   | Slightly slower                |

---

## 4. Supply Chain Security Assessment

- The image contains **~987 npm dependencies** (from Trivy node-pkg).  
- Critical issues observed include:
  - CVE-2023-37466 in `vm2`.
  - GHSA-whpj-8f3w-67p5 affecting `vm2`.
- Popular libraries with known CVEs are present (e.g., lodash).  
- License mix detected: **MIT, Apache-2.0, GPL-3.0** (counts above).  
- Key risks:
  - Large dependency tree → higher attack surface.
  - Vulnerabilities both in app libraries and base OS packages.
  - Need automated SCA in CI/CD to catch new CVEs early.

---

## 5. Conclusions

- **Syft + Grype** provide modular control and support SPDX/CycloneDX SBOMs but require two steps.  
- **Trivy** is easier: single tool for SBOM + vulnerabilities + licenses (+ secrets/config).  
- For fast CI/CD integration → **Trivy** is the best fit.  
- For deep SBOM customization and integration with platforms like **Dependency-Track** → **Syft + Grype**.



---


### Package Type Distribution (Syft vs Trivy)
- **Syft** detected **1001** components (covering OS packages, npm modules and some build-time metadata).
- **Trivy** detected **997** components (similar coverage but slightly fewer total packages).
- Both tools agree on the majority of npm dependencies; Syft sometimes lists extra build/base-layer packages.

### Dependency Discovery Analysis
- **Syft** tends to discover more *system-level* packages (Debian base libs, gcc, libc).
- **Trivy** focuses strongly on *application-level* packages (npm).
- In this scan, Syft found 4 more total packages than Trivy.

### License Discovery Analysis
- **Trivy** produced license data: MIT (883), Apache-2.0 (16), GPL-3.0 (1).
- **Syft** can export SPDX/CycloneDX but requires extra processing to aggregate license info.
- **Trivy** is more convenient for license compliance checks.

### SCA Tool Comparison — Vulnerability Detection
- **Grype**: uses Syft SBOM, accurate CVE mapping, modular but requires two steps.
- **Trivy**: single binary, good coverage of CVEs, includes secret scanning and config checks.

### Critical Vulnerabilities Analysis (Top‑5)
The five most severe issues detected (from Trivy scan) and remediation advice:
- **CVE-2023-32314** in `vm2` 3.9.17 — CVSS 10 → Upgrade `vm2` to **3.9.18**
- **CVE-2023-37466** in `vm2` 3.9.17 — CVSS 10 → Upgrade to a patched version
- **CVE-2023-37903** in `vm2` 3.9.17 — CVSS 10 → Upgrade to a patched version
- **CVE-2015-9235** in `jsonwebtoken` 0.1.0 — CVSS 9.8 → Upgrade `jsonwebtoken` to **4.2.2**
- **CVE-2015-9235** in `jsonwebtoken` 0.4.0 — CVSS 9.8 → Upgrade `jsonwebtoken` to **4.2.2**

### License Compliance Assessment
- Detected permissive licenses (MIT, Apache-2.0) but also **GPL-3.0**.
- **GPL-3.0** can impose copyleft obligations — avoid statically linking or distributing proprietary derivatives without compliance.
- Recommendation: review GPL-3.0 components; replace or isolate if commercial distribution planned.

### Accuracy Analysis
- Package overlap: ~99.6% match between Syft and Trivy.
- Vulnerability overlap: many CVEs appear in both reports; some GHSA IDs unique to Grype.
- Trivy additionally flagged npm ecosystem advisories beyond CVE (for example - GHSA).

### Tool Strengths and Weaknesses
- **Syft+Grype:** detailed SBOMs (SPDX/CycloneDX), good for integrating with Dependency‑Track; requires two tools.
- **Trivy:** very easy, single step, adds secrets/config scanning; slightly slower and SBOM less customizable.

### Use Case Recommendations
- **Use Trivy**: fast CI/CD vulnerability & license scanning, secret detection, simple pipelines.
- **Use Syft+Grype**: when you need rich SBOM formats, integrate with security dashboards (Dependency‑Track), or require SPDX compliance.

### Integration Considerations (CI/CD)
A simple GitHub Actions setup to run both tools:
```yaml
name: SCA Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: image
          image-ref: bkimminich/juice-shop:v19.0.0
          format: table
      - name: Run Syft & Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          syft bkimminich/juice-shop:v19.0.0 -o json > syft.json
          grype sbom:syft.json -o table
```


### Secrets Scanning Results

Trivy secret scanning flagged **hardcoded sensitive data** inside the image:

| File path | Severity | Secret type |
|-----------|----------|-------------|
| `/juice-shop/build/lib/insecurity.js` | **HIGH** | Asymmetric Private Key (RSA) |
| `/juice-shop/lib/insecurity.ts` | **HIGH** | Asymmetric Private Key (RSA) |
| `/juice-shop/frontend/src/app/app.guard.spec.ts` | **MEDIUM** | JWT token |
| `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts` | **MEDIUM** | JWT token |

**Risk:**  
- Hardcoded **private keys** may allow attackers to forge JWT tokens or decrypt sensitive data.  
- Test **JWT tokens** could lead to privilege escalation if reused in production.

**Recommendation:**  
- Remove all private keys and tokens from the repository and image.  
- Load keys/tokens securely via environment variables or external secrets managers.  
- Rotate any exposed keys/tokens immediately.