# SBOM Generation & Software Composition Analysis

## SBOM Generation with Syft and Trivy

### Package Type Distribution

| Tool   | Package Type      | Count |
|--------|-------------------|-------|
| Syft   | npm               | 1128  |
| Syft   | deb               | 10    |
| Syft   | binary            | 1     |
| Trivy  | Node.js (npm)     | 1125  |
| Trivy  | OS packages (deb) | 10    |

**Observation:** Syft detected 1128 npm packages, while Trivy detected 1125 – a difference of 3 packages. This discrepancy likely arises from how each tool handles certain metadata (e.g., devDependencies, optional packages, or packages embedded in binary files). Both tools correctly identified the 10 Debian packages from the base image.

### License Discovery

**Syft licenses** (unique occurrences):  
- MIT: 890  
- ISC: 143  
- BSD-3-Clause: 16  
- Apache-2.0: 15  
- BSD-2-Clause: 12  
- LGPL-3.0: 19  
- ... (other licenses with lower counts)

**Trivy licenses (OS packages):**  
- GPL-2.0-only: 3  
- Artistic-2.0: 2  
- Apache-2.0: 1  
- GFDL-1.2-only: 1  
- ... (various GPL/LGPL variants)

**Trivy licenses (Node.js packages):**  
- MIT: 878  
- ISC: 143  
- LGPL-3.0-only: 19  
- Apache-2.0: 12  
- BSD-3-Clause: 14  
- ... (similar to Syft, but counts differ slightly)

**Analysis:** Both tools extracted license information from package metadata. Syft reported slightly more MIT-licensed packages (890 vs 878), likely due to the 3 extra npm packages it found. The license distribution is dominated by permissive licenses (MIT, ISC, BSD), which is typical for modern JavaScript applications. A few packages use copyleft licenses (LGPL, GPL), which could require attention if the application were distributed commercially.

### Dependency Discovery

- **Total packages detected:** Syft – 1139 (1128 npm + 10 deb + 1 binary), Trivy – 1135 (1125 npm + 10 deb).
- **Packages unique to Syft:** 13 (npm packages that Trivy missed).
- **Packages unique to Trivy:** 9 (npm packages that Syft missed).

**Conclusion:** Syft provides a slightly more comprehensive SBOM for this image, particularly for npm packages. The differences highlight the importance of using multiple tools or regularly updating vulnerability databases to ensure complete coverage. For compliance purposes, the extra packages found by Syft could be critical if they contain vulnerabilities or restrictive licenses.

## Software Composition Analysis with Grype and Trivy

### Vulnerability Detection Summary

| Severity   | Grype | Trivy |
|------------|-------|-------|
| Critical   | 11    | 10    |
| High       | 88    | 81    |
| Medium     | 32    | 34    |
| Low        | 3     | 18    |
| Negligible | 12    | –     |

**Note:** Grype reported 12 “Negligible” vulnerabilities, which Trivy does not classify separately. Trivy found more low‑severity issues (18 vs 3) and slightly fewer critical/high ones, possibly due to different severity scoring or database freshness.

### Top 5 Critical Vulnerabilities

| Tool   | CVE ID / GHSA ID          | Package         | Version   | Description                                                                 | Recommendation                |
|--------|---------------------------|-----------------|-----------|-----------------------------------------------------------------------------|-------------------------------|
| Grype  | GHSA-whpj-8f3w-67p5       | vm2             | 3.9.17    | vm2 Sandbox Escape vulnerability                                            | Upgrade vm2 to patched version|
| Grype  | GHSA-g644-9gfx-q4q4       | vm2             | 3.9.17    | Another vm2 sandbox escape                                                  | Upgrade vm2                   |
| Grype  | GHSA-c7hr-j4mj-j2w6       | jsonwebtoken    | 0.1.0     | Verification Bypass in jsonwebtoken                                         | Update to >= 9.0.0            |
| Grype  | GHSA-c7hr-j4mj-j2w6       | jsonwebtoken    | 0.4.0     | Same issue affects multiple versions                                        | Update to >= 9.0.0            |
| Grype  | GHSA-cchq-frgv-rjh5       | vm2             | 3.9.17    | Additional vm2 sandbox escape                                               | Upgrade vm2                   |
| Trivy  | CVE-2025-15467            | libssl3         | 3.0.17-1  | OpenSSL: Remote code execution or DoS via oversized IV in CMS parsing       | Update libssl3                |
| Trivy  | CVE-2023-46233            | crypto-js       | 3.3.0     | PBKDF2 1000x weaker than specified                                          | Upgrade crypto-js             |
| Trivy  | CVE-2015-9235             | jsonwebtoken    | 0.1.0     | Verification bypass with altered token                                      | Update jsonwebtoken           |
| Trivy  | CVE-2015-9235             | jsonwebtoken    | 0.4.0     | Same issue                                                                  | Update jsonwebtoken           |
| Trivy  | CVE-2019-10744            | lodash          | 2.4.2     | Prototype pollution in defaultsDeep function                                | Update lodash                 |

**Observation:** Both tools highlight critical issues in the same packages (`vm2`, `jsonwebtoken`, `crypto-js`, `lodash`), confirming the severity of these vulnerabilities.

### Secrets and License Scanning

- **Secrets scan (Trivy):** No secrets were found in the image. This is expected for a publicly available application like Juice Shop.
- **License compliance (Trivy):** The license scan identified 28 unique license types (Syft found 32). Both tools flagged GPL‑licensed packages, which could pose legal risks if the application is redistributed. The most common licenses are MIT, ISC, BSD, and Apache‑2.0 – all permissive and safe for most use cases.

### Analysis

Grype (using the Syft SBOM) and Trivy produced similar vulnerability counts, with minor differences likely due to database update timing and severity classification. Trivy’s additional scanners (secrets, licenses) provide extra value in a single tool, while Grype’s integration with Syft allows for a modular SBOM‑first approach. The high number of critical and high vulnerabilities in this deliberately vulnerable application reinforces the need for regular SCA in real‑world projects.

## Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### Accuracy & Coverage

- **Packages detected by both tools:** 1126  
- **Packages only detected by Syft:** 13  
- **Packages only detected by Trivy:** 9  

- **CVEs found by Grype:** 95  
- **CVEs found by Trivy:** 91  
- **Common CVEs:** 26  

**Interpretation:** The package overlap is high (≈99%), but each tool misses a handful of packages. The low CVE overlap (only 26 out of ~95) is striking – it suggests that the tools use different vulnerability databases or matching logic. Grype might be picking up CVEs that Trivy doesn’t (and vice versa), meaning that relying on a single tool could leave blind spots. In practice, using both tools or periodically cross‑checking results would improve coverage.

### Strengths and Weaknesses

| Aspect                  | Syft + Grype                              | Trivy                                      |
|-------------------------|-------------------------------------------|--------------------------------------------|
| **SBOM formats**        | Multiple (SPDX, CycloneDX, JSON, table)   | CycloneDX, JSON, table                     |
| **Vulnerability DB**    | Based on multiple sources (NVD, GitHub)   | Also multiple sources, often very fresh    |
| **Additional scanners** | None (Grype only vulnerabilities)         | Secrets, IaC, licenses, misconfigurations  |
| **Integration effort**  | Two tools to install/update               | Single binary                              |
| **Speed**               | Moderate (SBOM generation + scan)         | Fast (all-in-one)                          |
| **Package coverage**    | Slightly higher for npm (1128 vs 1125)    | Slightly lower, but still excellent        |
| **CVE coverage**        | 95 CVEs (different set)                   | 91 CVEs (different set)                    |

### Use Case Recommendations

- **Choose Syft+Grype if:**  
  - You need to produce SBOMs in specific formats (e.g., SPDX for regulatory compliance).  
  - You already use Syft in your build process and want a dedicated vulnerability scanner.  
  - You prefer a modular approach where each tool does one thing well.

- **Choose Trivy if:**  
  - You want a single tool for multiple security checks (vulnerabilities, secrets, IaC).  
  - You are integrating into CI/CD and value simplicity.  
  - You need fast scans with minimal configuration.

- **For maximum coverage:** Consider running both tools periodically and comparing results. The low CVE overlap (only 26 common) shows that each tool catches issues the other misses.
