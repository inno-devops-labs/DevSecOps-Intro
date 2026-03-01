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

