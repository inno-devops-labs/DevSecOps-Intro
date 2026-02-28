# Lab 4 — SBOM Generation & Software Composition Analysis

## Task 1 — SBOM Generation with Syft and Trivy

### 1. Package Type Distribution

Both tools successfully generated SBOMs for the image.

Key quantitative comparison:
- Packages detected by both tools: 1126
- Packages only detected by Syft: 13
- Packages only detected by Trivy: 9

This indicates:
- Very high overlap in package detection (~99% similarity).
- Minor differences likely due to:
    - Package classification logic
    - Metadata parsing differences
    - Handling of nested Node.js dependencies

Trivy report summary shows:
- OS base: `debian 12.11`
- OS vulnerabilities: 27
- Node packages: large number, but 0 vulnerabilities reported for most direct Node packages

Syft provides a more artifact-centric SBOM structure, including:
- Package type
- Version
- Location
- License metadata
- Dependency relationships (more explicit in native JSON)

### 2. Dependency Discovery Analysis

### Syft

Strengths:
- Very detailed artifact-level metadata
- Clear separation by package type
- More explicit dependency relationship modeling
- Native JSON format optimized for downstream tools (e.g., Grype)

Weakness:
- Requires separate vulnerability scanner (Grype)

### Trivy

Strengths:
- Detects OS and language packages in one run
- Automatically categorizes results (`os-pkgs`, `lang-pkgs`)
- Easier quick overview via table output

Weakness:
- Less explicit dependency graph modeling compared to Syft
- JSON structure less SBOM-focused, more scan-oriented

### Conclusion

For pure SBOM quality and extensibility: Syft provides slightly more structured and SBOM-focused output

For convenience and quick inspection: Trivy is more operationally efficient

### 3. License Discovery Analysis

From the generated reports:
- Syft identified license information directly at artifact level.
- Trivy required separate license scanning mode.

Both tools detected multiple license types.

Observations:
- Syft associates licenses per package directly in SBOM.
- Trivy separates license scanning into a dedicated scanner.
- Trivy distinguishes between OS package licenses and Node.js licenses.

Conclusion:
- Syft is better for SBOM-first workflows
- Trivy is better for compliance-first workflows integrated into CI

## Task 2 — Software Composition Analysis with Grype and Trivy

### 1. SCA Tool Comparison

Quantitative results:
- CVEs found by Grype: **93**
- CVEs found by Trivy: **91**
- Common CVEs detected by both: **26**

This indicates:
- Large differences in vulnerability databases and matching logic
- Significant non-overlap in reported vulnerabilities

Severity comparison:
- Trivy detected 27 OS vulnerabilities (Debian base)
- Grype reported slightly higher total CVE count

This highlights an important supply-chain security insight: Different scanners rely on different vulnerability databases and matching heuristics. Using only one tool may produce blind spots.

### 2. Critical Vulnerabilities Analysis

Most critical findings were located in Debian base image packages.

Top risk categories observed:
- OpenSSL-related issues
- libc-related vulnerabilities
- System library CVEs inherited from base image

Remediation recommendations:
- Update base image to latest Debian patch level.
- Regularly rebuild image to inherit upstream security fixes.
- Minimize OS-level packages in production containers.
- Consider distroless or minimal base images where possible.

Risk assessment:
- Vulnerabilities are primarily inherited from base image.
- No high-risk Node.js application-layer vulnerabilities detected.
- Risk exposure depends on container runtime hardening and network exposure.

### 3. License Compliance Assessment

Observations:
- Multiple license types detected across Node.js ecosystem.
- Common licenses likely include:
    - MIT
    - Apache-2.0
    - ISC
    - BSD variants

Risk assessment:
- These licenses are generally permissive.
- No immediate GPL-family high-risk compliance conflicts observed in summary.

Recommendations:
- Maintain automated license scanning in CI.
- Define organizational policy for:
    - Copyleft licenses
    - Strong reciprocal licenses
- Generate SBOMs per release and archive them.

### 4. Additional Security Features

Trivy also supports:
- Secret scanning
- License scanning
- Misconfiguration scanning (not used in this lab)

Secret scan result:
- No secrets detected in the container image.

This demonstrates Trivy’s broader DevSecOps coverage compared to Syft+Grype.

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 1. Accuracy Analysis

Package detection:
- Both tools: 1126
- Syft only: 13
- Trivy only: 9

Vulnerability detection:
- Grype: 93 CVEs
- Trivy: 91 CVEs
- Common: 26

Key insight – There is surprisingly low CVE overlap relative to total count, suggesting:
- Different advisory databases
- Different matching strategies
- Different severity normalization approaches

### 2. Tool Strengths and Weaknesses

### Syft + Grype

Strengths:
- Clean separation of concerns (SBOM vs SCA)
- SBOM reusable across multiple scanners
- More flexible integration pipelines
- Better for security teams with mature processes

Weaknesses:
- Requires managing two tools
- Slightly more operational overhead

### Trivy (All-in-One)

Strengths:
- Single binary / single container
- Covers vulnerabilities, licenses, secrets
- Simple CI integration
- Faster setup

Weaknesses:
- Less modular
- SBOM output less structured for advanced workflows

### 3. Use Case Recommendations

| Use Case                       | Recommended Tool |
| ------------------------------ | ---------------- |
| CI quick security gate         | Trivy            |
| Compliance-driven organization | Trivy            |
| SBOM-first architecture        | Syft             |
| Advanced SCA pipeline          | Syft + Grype     |
| Multi-tool validation strategy | Use both         |

Best practice recommendation: In high-security environments, use Syft to generate SBOMs and scan them with multiple scanners (Grype + additional tools). Trivy can serve as a fast CI guardrail.

### 4. Integration Considerations

### Trivy
- Simple GitHub Actions integration
- Single job for vulnerability + license + secret scan
- Low operational complexity

### Syft + Grype

- Better for:
    - Artifact signing
    - SBOM attestation
    - Supply chain security frameworks (SLSA)
- Enables “scan once, analyze many times” strategy