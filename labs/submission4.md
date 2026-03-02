# Lab 4 Submission — SBOM Generation & Software Composition Analysis

**Author:** ellilin
**Date:** 2026-03-02
**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SBOM Generation with Syft and Trivy

### 1.1 Package Type Distribution

| Metric | Syft | Trivy |
|--------|------|-------|
| **Total Packages** | 1,139 | 1,135 |
| **NPM Packages** | 1,128 | 1,125 |
| **Debian Packages** | 10 | 10 |
| **Binary** | 1 | - |

**Analysis:**
Both tools detected similar numbers of packages with Syft finding 4 more packages than Trivy. The package distribution is dominated by npm packages (Node.js dependencies), which is expected for a Node.js application like OWASP Juice Shop.

### 1.2 Dependency Discovery Analysis

**Packages detected by both tools:** 1,126
**Packages only detected by Syft:** 13
**Packages only detected by Trivy:** 9

**Packages unique to Syft:**
```
baz@UNKNOWN
browser_field@UNKNOWN
false_main@UNKNOWN
gcc-12-base@12.2.0-14+deb12u1
hashids-esm@UNKNOWN
invalid_main@UNKNOWN
libc6@2.36-9+deb12u10
libgcc-s1@12.2.0-14+deb12u1
libgomp1@12.2.0-14+deb12u1
libssl3@3.0.17-1~deb12u2
libstdc++6@12.2.0-14+deb12u1
node@22.18.0
tzdata@2025b-0+deb12u1
```

**Packages unique to Trivy:**
```
gcc-12-base@12.2.0
libc6@2.36
libgcc-s1@12.2.0
libgomp1@12.2.0
libssl3@3.0.17
libstdc++6@12.2.0
portscanner@2.2.0
toposort-class@1.0.1
tzdata@2025b
```

**Key Observations:**
1. **Version format differences:** Syft uses full Debian package versions (e.g., `12.2.0-14+deb12u1`) while Trivy uses shorter versions (e.g., `12.2.0`)
2. **UNKNOWN packages:** Syft detected several packages with `UNKNOWN` versions, indicating it found package references that couldn't be fully resolved
3. **Unique discoveries:** Trivy found `portscanner@2.2.0` and `toposort-class@1.0.1` that Syft missed
4. **Node.js detection:** Syft explicitly detected the Node.js binary (`node@22.18.0`) as a separate package

### 1.3 License Discovery Analysis

| Tool | Unique License Types |
|------|---------------------|
| Syft | 32 |
| Trivy | 28 |

**Top Licenses Detected:**

| License | Syft Count | Trivy Count |
|---------|-----------|-------------|
| MIT | 890 | 878 |
| ISC | 143 | 143 |
| BSD-3-Clause | 16 | 14 |
| Apache-2.0 | 15 | 12 |
| LGPL-3.0 | 19 | 19 |
| BSD-2-Clause | 12 | 12 |

**Analysis:**
- Syft discovered more license types overall (32 vs 28)
- Both tools identified MIT as the dominant license, reflecting the npm ecosystem's preference
- Syft detected some license expressions that Trivy didn't capture (e.g., `Apache2`, `GPL`, `GPL-1`, `GPL-1+`)
- The "sha256:..." entry in Syft's results indicates hash-based license references that weren't resolved

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### 2.1 SCA Tool Comparison

| Severity | Grype | Trivy |
|----------|-------|-------|
| **Critical** | 11 | 10 |
| **High** | 88 | 81 |
| **Medium** | 32 | 34 |
| **Low** | 3 | 18 |
| **Negligible/Unknown** | 12 | - |
| **Total** | 146 | 143 |

**Analysis:**
- Grype detected slightly more vulnerabilities overall (146 vs 143)
- Grype found more Critical and High severity issues
- Trivy reported significantly more Low severity vulnerabilities (18 vs 3)
- The severity distribution is similar, with High severity being the most common category

### 2.2 Critical Vulnerabilities Analysis (Top 5)

#### CVE-2025-15467 (OpenSSL)
| Attribute | Details |
|-----------|---------|
| **Package** | libssl3@3.0.17-1~deb12u2 |
| **Severity** | Critical |
| **Title** | OpenSSL: Remote code execution or Denial of Service via oversized Initialization Vector in CMS parsing |
| **Fix Available** | 3.0.18-1~deb12u2 (Trivy) / No fix reported (Grype) |
| **Remediation** | Upgrade to libssl3 >= 3.0.18-1~deb12u2 |

#### CVE-2023-46233 (crypto-js)
| Attribute | Details |
|-----------|---------|
| **Package** | crypto-js@3.3.0 |
| **Severity** | Critical |
| **Title** | PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard |
| **Fix Available** | 4.2.0 |
| **Remediation** | Upgrade crypto-js to version 4.2.0 or later |

#### CVE-2015-9235 (jsonwebtoken)
| Attribute | Details |
|-----------|---------|
| **Package** | jsonwebtoken@0.1.0, jsonwebtoken@0.4.0 |
| **Severity** | Critical |
| **Title** | Verification step bypass with an altered token |
| **Fix Available** | 4.2.2 |
| **Remediation** | Upgrade jsonwebtoken to version 4.2.2 or later |

#### CVE-2019-10744 (lodash)
| Attribute | Details |
|-----------|---------|
| **Package** | lodash@2.4.2 |
| **Severity** | Critical |
| **Title** | Prototype pollution in defaultsDeep function leading to modifying properties |
| **Fix Available** | 4.17.12 |
| **Remediation** | Upgrade lodash to version 4.17.12 or later |

#### vm2 Multiple Vulnerabilities
| CVE | Package | Fix Version | Description |
|-----|---------|-------------|-------------|
| CVE-2023-32314 | vm2@3.9.17 | 3.9.18 | Sandbox Escape |
| CVE-2023-37466 | vm2@3.9.17 | 3.10.0 | Promise handler sanitization bypass |
| CVE-2023-37903 | vm2@3.9.17 | No fix | Custom inspect function sandbox escape |
| CVE-2026-22709 | vm2@3.9.17 | 3.10.2 | Sandbox Escape |

**Remediation for vm2:** The vm2 library is deprecated and has multiple unpatched vulnerabilities. Consider removing it entirely or finding an alternative sandbox solution.

### 2.3 License Compliance Assessment

**Risky Licenses Detected (GPL/LGPL Family):**

| License | Severity | Affected Packages |
|---------|----------|-------------------|
| GPL-2.0-or-later | HIGH | base-files, gcc-12-base |
| GPL-3.0-only | HIGH | gcc-12-base |
| GPL-2.0-only | HIGH | gcc-12-base, libc6, netbase, fuzzball |
| LGPL-2.0-or-later | HIGH | gcc-12-base |
| LGPL-2.1-only | HIGH | libc6 |
| LGPL-3.0-only | HIGH | web3 ecosystem (19 packages) |
| GPL-1.0-only/or-later | HIGH | libssl3 |

**Compliance Recommendations:**
1. **For Proprietary Software:** Review all GPL-licensed packages carefully - they may require source code disclosure
2. **LGPL Packages:** Generally acceptable for dynamic linking, but verify compliance requirements
3. **web3 Ecosystem:** The 19 LGPL-3.0 packages from the web3 library family are used for Ethereum interaction - ensure proper dynamic linking
4. **OS Packages:** Debian system packages (libc6, libssl3, gcc-12-base) are typically acceptable for container base images

### 2.4 Additional Security Features — Secrets Scanning

**Trivy Secrets Scan Results:**
- **Secrets Found:** 0 (No secrets detected)
- The scan examined all files in the container image for potential secret exposure
- No API keys, passwords, or tokens were exposed in the image

**Note:** This is a positive security indicator for the Juice Shop image, suggesting no sensitive credentials were accidentally embedded.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1 Accuracy Analysis

#### Package Detection Overlap

```
┌─────────────────────────────────────────────────────────────┐
│                 Package Detection Results                    │
├─────────────────────────────────────────────────────────────┤
│  ████████████████████████████████████████████████  1,126    │
│  ████████████████████████████████████████████████████ 1,139 │
│                      Syft: 1,139 total                      │
│                     Trivy: 1,135 total                       │
│                      Both: 1,126 (98.9% overlap)            │
└─────────────────────────────────────────────────────────────┘
```

#### Vulnerability Detection Overlap

| Metric | Count |
|--------|-------|
| **CVEs found by Grype** | 95 |
| **CVEs found by Trivy** | 91 |
| **Common CVEs** | 26 (27.4% overlap) |
| **Grype-only CVEs** | 69 |
| **Trivy-only CVEs** | 65 |

**Key Finding:** While package detection has 98.9% overlap, vulnerability detection shows only 27.4% overlap. This significant difference is attributed to:
1. **Different vulnerability databases:** Grype uses Anchore's database, Trivy uses its own
2. **CVE vs GMSA:** Grype reports GitHub Security Advisories (GHSAs) alongside CVEs
3. **Version matching logic:** Different algorithms for determining vulnerable versions

### 3.2 Tool Strengths and Weaknesses

#### Syft + Grype (Specialized Toolchain)

| Strengths | Weaknesses |
|-----------|------------|
| More detailed SBOM metadata | Two separate tools to maintain |
| Better license detection (32 vs 28 types) | More complex CI/CD integration |
| Native JSON format with extensive fields | Requires SBOM generation before scanning |
| Unknown version detection | Slightly longer total execution time |
| Strong ecosystem integration (Anchore) | No built-in secrets scanning |
| Better at detecting binary packages | |

#### Trivy (All-in-One Solution)

| Strengths | Weaknesses |
|-----------|------------|
| Single tool for all scans | Less detailed SBOM metadata |
| Built-in secrets scanning | Fewer license types detected |
| Built-in license compliance | Simpler output format |
| Faster for quick assessments | Misses some binary packages |
| Simpler CI/CD integration | |
| Active community (CNCF project) | |
| Misconfiguration scanning | |

### 3.3 Use Case Recommendations

#### Choose Syft + Grype when:
1. **Compliance-focused environments** requiring detailed SBOMs (NTIA, SLSA requirements)
2. **License compliance is critical** - better license detection
3. **Supply chain security** - need to generate and store SBOMs for attestation
4. **Integration with Anchore Enterprise** - native compatibility
5. **Research and forensics** - more detailed package metadata

#### Choose Trivy when:
1. **Quick security assessments** - all-in-one scanning
2. **CI/CD pipeline simplicity** - single tool to configure
3. **Secrets detection required** - built-in capability
4. **Container security** - includes misconfiguration scanning
5. **Kubernetes security** - cluster scanning capabilities
6. **Resource-constrained environments** - faster execution

### 3.4 Integration Considerations

#### CI/CD Pipeline Integration

**Syft + Grype Pipeline:**
```yaml
# Requires two steps
- name: Generate SBOM
  run: docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD:/tmp anchore/syft:latest \
    $IMAGE -o syft-json=/tmp/sbom.json

- name: Scan SBOM
  run: docker run --rm -v $PWD:/tmp anchore/grype:latest \
    sbom:/tmp/sbom.json -o json > grype-results.json
```

**Trivy Pipeline:**
```yaml
# Single step
- name: Scan Image
  run: docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD:/tmp aquasec/trivy:latest image \
    --format json --output /tmp/trivy-results.json $IMAGE
```

#### Operational Considerations

| Factor | Syft+Grype | Trivy |
|--------|-----------|-------|
| **Number of images to pull** | 2 | 1 |
| **Database updates** | 2 (Grype DB) | 1 (Trivy DB) |
| **Output formats** | Multiple per tool | Multiple from single tool |
| **GitHub Actions** | Separate actions | Single action |
| **SBOM standards** | SPDX, CycloneDX, Syft JSON | CycloneDX, SPDX, JSON |

### 3.5 Summary Recommendation

For this Juice Shop assessment, both toolchains provided valuable insights:

1. **For comprehensive analysis:** Use both tools and compare results (as done in this lab)
2. **For production CI/CD:** Trivy offers simpler integration with adequate coverage
3. **For compliance requirements:** Syft+Grype provides more detailed SBOMs and attestation support
4. **For critical applications:** Consider using both in parallel to maximize vulnerability coverage

The 27.4% CVE overlap suggests that using both tools provides significantly better security coverage than either alone.

---

## Files Generated

| File | Description |
|------|-------------|
| `labs/lab4/syft/juice-shop-syft-native.json` | Syft SBOM in native JSON format |
| `labs/lab4/syft/juice-shop-syft-table.txt` | Syft SBOM in table format |
| `labs/lab4/syft/juice-shop-licenses.txt` | Extracted licenses from Syft |
| `labs/lab4/syft/grype-vuln-results.json` | Grype vulnerability scan results |
| `labs/lab4/syft/grype-vuln-table.txt` | Grype vulnerability table |
| `labs/lab4/trivy/juice-shop-trivy-detailed.json` | Trivy detailed JSON output |
| `labs/lab4/trivy/juice-shop-trivy-table.txt` | Trivy table output |
| `labs/lab4/trivy/trivy-vuln-detailed.json` | Trivy vulnerability scan |
| `labs/lab4/trivy/trivy-secrets.txt` | Trivy secrets scan |
| `labs/lab4/trivy/trivy-licenses.json` | Trivy license scan |
| `labs/lab4/analysis/sbom-analysis.txt` | SBOM component analysis |
| `labs/lab4/analysis/vulnerability-analysis.txt` | Vulnerability analysis |
| `labs/lab4/comparison/accuracy-analysis.txt` | Tool accuracy comparison |
| `labs/lab4/comparison/syft-packages.txt` | Syft package list |
| `labs/lab4/comparison/trivy-packages.txt` | Trivy package list |
| `labs/lab4/comparison/common-packages.txt` | Common packages |
| `labs/lab4/comparison/syft-only.txt` | Syft-unique packages |
| `labs/lab4/comparison/trivy-only.txt` | Trivy-unique packages |
| `labs/lab4/comparison/grype-cves.txt` | Grype CVE list |
| `labs/lab4/comparison/trivy-cves.txt` | Trivy CVE list |
