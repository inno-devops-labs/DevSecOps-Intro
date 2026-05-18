# Lab 4 — SBOM Generation & Software Composition Analysis

## Task 1 — SBOM Generation with Syft and Trivy (4 pts)

### 1.1 SBOM Generation Commands

```bash
# Syft SBOM generation
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/tmp" anchore/syft:latest bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# Trivy SBOM generation
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}:/tmp" aquasec/trivy:latest image --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json --list-all-pkgs bkimminich/juice-shop:v19.0.0
```

### 1.2 Package Type Distribution

**Syft Package Counts by Type:**
```
binary: 1
deb: 10
npm: 1128
```

**Trivy Package Counts by Type:**
```
bkimminich/juice-shop:v19.0.0 (debian 12.11) - unknown: 10
Node.js - unknown: 1125
```

### 1.3 License Analysis

**Syft License Distribution:**
*No license data found in Syft SBOM*

**Trivy License Distribution (OS Packages):**
| License | Count |
|---------|-------|
| ad-hoc | 1 |
| Apache-2.0 | 1 |
| Artistic-2.0 | 2 |
| GFDL-1.2-only | 1 |
| GPL-1.0-only | 1 |
| GPL-1.0-or-later | 1 |
| GPL-2.0-only | 3 |
| GPL-2.0-or-later | 2 |
| GPL-3.0-only | 1 |
| LGPL-2.0-or-later | 1 |
| LGPL-2.1-only | 1 |
| public-domain | 1 |

**Trivy License Distribution (Node.js):**
| License | Count |
|---------|-------|
| (BSD-2-Clause OR MIT OR Apache-2.0) | 1 |
| (MIT OR Apache-2.0) | 2 |
| (MIT OR WTFPL) | 1 |
| (WTFPL OR MIT) | 1 |
| 0BSD | 1 |
| Apache-2.0 | 12 |
| BlueOak-1.0.0 | 5 |
| BSD-2-Clause | 12 |
| BSD-3-Clause | 14 |
| GPL-2.0-only | 1 |
| ISC | 143 |
| LGPL-3.0-only | 19 |
| MIT | 878 |
| MIT/X11 | 2 |
| MPL-2.0 | 2 |
| Unlicense | 2 |
| WTFPL | 1 |
| WTFPL OR ISC | 1 |

### 1.4 Observations

**Dependency Discovery:** 
- Syft detected 1 binary, 10 deb packages, and 1128 npm packages
- Trivy detected 10 OS packages and 1125 Node.js packages
- Both tools show similar counts for package types, with Trivy providing better categorization by separating OS and application packages

**License Discovery:**
- Syft did not extract license information in the SBOM
- Trivy provided comprehensive license data for both OS packages and Node.js dependencies
- Trivy identified 12 distinct license types for OS packages and 18+ license types for Node.js, with MIT being the most common (878 occurrences)

---

## Task 2 — Software Composition Analysis (3 pts)

### 2.1 Vulnerability Analysis

**Grype Vulnerabilities by Severity:**
| Severity | Count |
|----------|-------|
| Critical | 11 |
| High | 44 |
| Medium | 31 |
| Low | 3 |
| Negligible | 12 |

**Trivy Vulnerabilities by Severity:**
| Severity | Count |
|----------|-------|
| CRITICAL | 10 |
| HIGH | 39 |
| MEDIUM | 33 |
| LOW | 18 |

### 2.2 Critical Vulnerabilities

**Top 5 Critical Vulnerabilities (Grype):**
1. `GHSA-whpj-8f3w-67p5` | vm2@3.9.17 | vm2 Sandbox Escape vulnerability
2. `GHSA-g644-9gfx-q4q4` | vm2@3.9.17 | vm2 Sandbox Escape vulnerability
3. `GHSA-c7hr-j4mj-j2w6` | jsonwebtoken@0.1.0 | Verification Bypass in jsonwebtoken
4. `GHSA-c7hr-j4mj-j2w6` | jsonwebtoken@0.4.0 | Verification Bypass in jsonwebtoken
5. `GHSA-cchq-frgv-rjh5` | vm2@3.9.17 | vm2 Sandbox Escape vulnerability

**Top 5 Critical Vulnerabilities (Trivy):**
1. `CVE-2025-15467` | libssl3@3.0.17-1~deb12u2 | OpenSSL: Remote code execution or Denial of Service via oversized Initialization Vector in CMS parsing
2. `CVE-2023-46233` | crypto-js@3.3.0 | crypto-js: PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
3. `CVE-2015-9235` | jsonwebtoken@0.1.0 | nodejs-jsonwebtoken: verification step bypass with an altered token
4. `CVE-2015-9235` | jsonwebtoken@0.4.0 | nodejs-jsonwebtoken: verification step bypass with an altered token
5. `CVE-2019-10744` | lodash@2.4.2 | nodejs-lodash: prototype pollution in defaultsDeep function leading to modifying properties

### 2.3 Secrets and License Scanning

**Trivy Secrets Scan Results:**
*No secrets found in the image*

**License Compliance Assessment:**
The application uses a wide variety of open source licenses. Most packages use permissive licenses (MIT, BSD, Apache-2.0) which are safe for commercial use. However, there are some GPL family licenses (GPL-2.0, GPL-3.0, LGPL-3.0) that may require disclosure of source code if the application is distributed. A legal review is recommended for packages under GPL licenses.

**Recommendations:**
1. Update vulnerable packages: jsonwebtoken, vm2, crypto-js, lodash
2. Review GPL-licensed packages for compliance requirements
3. Implement automated vulnerability scanning in CI/CD pipeline

---

## Task 3 — Toolchain Comparison (3 pts)

### 3.1 Package Detection Comparison

| Metric | Count |
|--------|-------|
| Syft total packages | 1139 (1 binary + 10 deb + 1128 npm) |
| Trivy total packages | 1135 (10 OS + 1125 Node.js) |
| Packages detected by both tools | ~1130 (similar counts) |
| Packages only detected by Syft | ~3 npm packages |
| Packages only detected by Trivy | ~0 |

### 3.2 Vulnerability Detection Comparison

| Metric | Count |
|--------|-------|
| CVEs found by Grype | ~100 (11 Critical, 44 High, 31 Medium) |
| CVEs found by Trivy | ~100 (10 Critical, 39 High, 33 Medium) |
| Common CVEs | Many shared vulnerabilities (jsonwebtoken, vm2, lodash) |

### 3.3 Tool Strengths and Weaknesses

| Aspect | Syft + Grype | Trivy |
|--------|--------------|-------|
| **SBOM Generation** | Detailed package listing, binary detection | Better categorization (OS vs application) |
| **License Detection** | Limited license information | Comprehensive license data for all packages |
| **Vulnerability Scanning** | More Critical findings (11 vs 10) | More detailed vulnerability descriptions |
| **Secrets Detection** | Not available | Built-in secrets scanning |
| **Ease of Use** | Two tools to manage | All-in-one solution |
| **Integration** | Specialized for each task | Single tool for multiple functions |

### 3.4 Use Case Recommendations

**When to choose Syft+Grype:**
- When you need specialized SBOM generation with binary detection
- When you want to integrate with Anchore's ecosystem
- When you prefer best-of-breed tools for each task

**When to choose Trivy:**
- When you want an all-in-one solution for security scanning
- When you need built-in secrets and license detection
- When you prefer simpler CI/CD integration with a single tool
- For most common use cases, Trivy provides comprehensive functionality

---

## Challenges & Solutions

### Challenge 1: PowerShell jq command issues
**Solution:** Created separate .jq files for complex queries to avoid escaping problems in PowerShell

### Challenge 2: Trivy JSON output parsing
**Solution:** Used jq with file-based queries to extract specific data from nested JSON structures

### Challenge 3: Understanding vulnerability severity differences
**Solution:** Cross-referenced findings between Grype and Trivy to identify common critical vulnerabilities

---

## Generated Artifacts

### SBOM Files
- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab4/syft/juice-shop-syft-table.txt`
- `labs/lab4/trivy/juice-shop-trivy-detailed.json`

### Vulnerability Scan Reports
- `labs/lab4/syft/grype-vuln-results.json`
- `labs/lab4/trivy/trivy-vuln-detailed.json`
- `labs/lab4/trivy/trivy-licenses.json`

### Comparison & Analysis Outputs
- `labs/lab4/comparison/accuracy-analysis.txt`
- `labs/lab4/comparison/common-packages.txt`
- `labs/lab4/comparison/grype-cves.txt`
- `labs/lab4/comparison/syft-only.txt`
- `labs/lab4/comparison/trivy-only.txt`
- `labs/lab4/analysis/sbom-analysis.txt`
- `labs/lab4/analysis/vulnerability-analysis.txt`

---

## Conclusion

Lab 4 successfully demonstrated SBOM generation and Software Composition Analysis using both specialized (Syft+Grype) and all-in-one (Trivy) toolchains. Key findings include:
- Both tools effectively identify packages and vulnerabilities
- Trivy provides better license detection out-of-the-box
- Critical vulnerabilities found in jsonwebtoken, vm2, and other dependencies require immediate remediation
- For most use cases, Trivy's all-in-one approach is more practical