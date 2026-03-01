# SBOM Generation & Software Composition Analysis

## Task 1 — SBOM Generation with Syft and Trivy

### Syft vs Trivy comparison

The two tools produced very similar overall results, but with small structural differences in classification.

Syft identified 1,139 total artifacts, distributed as follows:
- 1,128 npm packages
- 10 Debian (deb) OS packages
- 1 binary artifact

Trivy reported 1,135 total packages, categorized as:
- 1,125 Node.js packages
- 10 Debian OS packages


**Syft Strengths:**
- More detailed metadata per package
- Better file location tracking
- Comprehensive license information extraction
- Native SBOM format optimized for downstream analysis

**Trivy Strengths:**
- Integrated vulnerability data in SBOM
- Faster scanning (all-in-one approach)
- Better OS package detection
- Built-in CVE database integration

**Conclusion:**
Syft provides more granular SBOM data suitable for compliance and detailed analysis, while Trivy offers a more streamlined approach with immediate security context

### License Discovery Analysis

**License Detection Comparison:**

Both tools successfully extracted license information from the Juice Shop dependencies:

**Common Licenses Found:**
- MIT License (most common in npm ecosystem)
- Apache-2.0
- BSD variants (2-Clause, 3-Clause)
- ISC
- GPL variants

**Syft License Extraction:**
- Extracts licenses directly from package metadata
- Provides license expressions (e.g "MIT OR Apache-2.0")
- Better handling of SPDX identifiers

**Trivy License Extraction:**
- Integrates license data with vulnerability information
- Provides license compliance scanning
- Can flag risky licenses (GPL, AGPL)

**Key Finding:**
License discovery was comprehensive in both tools. For compliance-focused workflows, Syft's detailed license metadata is preferable. For security-first workflows, Trivy's integrated approach is more efficient

### Software Composition Analysis with Grype and Trivy
#### Package Detection

- Detected by both tools: 988 packages
- Only in Syft: 13
- Only in Trivy: 9

Package discovery is highly aligned. Differences are minor and likely caused by cataloging logic, version normalization, and dependency classification differences

#### Vulnerability Detection

| Severity   | Grype | Trivy |
|-----------|-------|-------|
| Critical  | 11    | 10    |
| High      | 86    | 81    |
| Medium    | 32    | 34    |
| Low       | 3     | 18    |
| Negligible| 12    | -     |
| Total findings | **144** | **143** |

- Grype: 93 unique CVEs
- Trivy: 91 unique CVEs
- Common findings: 26

Severity distribution is similar (Critical/High counts nearly equal), but CVE overlap is limited. Each tool uses different vulnerability databases, resulting in complementary findings

#### Conclusion
Running both tools improves coverage

### Toolchain Comparison: Syft+Grype vs Trivy All-in-One
#### Tool Strengths and Weaknesses
##### Syft + Grype

Strengths:
- Rich SBOM metadata (PURLs, locations, licenses)
- Strong license visibility (32 license types)
- Reusable SBOM for compliance workflows

Weaknesses:
- Two-step process
- No built-in secret scanning
- Slightly higher operational overhead

##### Trivy

Strengths:
- All-in-one (SBOM, vulns, licenses, secrets)
- Simple CI integration
- Single command execution

Weaknesses:
- Slightly fewer license distinctions (28 types)
- Limited CVE overlap with Grype
- Use Case Recommendations

#### Summary
- Syft + Grype: Best for compliance-focused environments requiring persistent SBOMs and detailed metadata
- Trivy: Best for fast CI/CD scanning with minimal setup.
- **Combined**: Recommended for critical images to maximize vulnerability coverage.

### Integration Considerations
- Trivy: Easier CI integration, supports fail-on-severity.
- Syft + Grype: Requires two steps but enables SBOM reuse and artifact storage.

Both support JSON output for automation and policy enforcement.

**Overall**: Trivy offers operational simplicity; Syft + Grype provides stronger SBOM-centric and compliance-oriented workflows.