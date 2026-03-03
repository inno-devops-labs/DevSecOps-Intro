
## Task 1 — SBOM Generation

### Package Distribution

- **Syft:**
  - npm packages: 1128
  - OS packages: 10

- **Trivy:**
  - npm packages: 1125
  - OS packages: 10

**Who found more:**
Syft found more npm packages (1128 vs. 1125 in Trivy). The number of OS packages is the same for both tools.

### Dependency Discovery

- **Version Accuracy:**
  - Syft and Trivy showed similar results for the number of npm packages, but Syft found 3 more packages.
  - Trivy marked versions for OS packages and npm packages as "unknown".

- **Differences:**
  - Syft did not mark any versions as "unknown".

- **Unique Packages:**
  - Unique packages are not specified in the data, but Syft found 3 more npm packages.

### License Discovery

- **Syft:**
  - Detected 38 different types of licenses.
  - There is 1 "unknown" license: (sha256:cb992345949ccd6e8394b2cd6c465f7b897c864f845937dbf64e8997f389e164).

- **Trivy:**
  - Detected 22 different types of licenses for OS packages and 27 for Node.js packages.
  - No "unknown" licenses.

**Who showed more licenses:**
Syft showed a greater variety of licenses.

**Conclusion:**
Syft analyzed npm packages and licenses in more detail, while Trivy left package versions as unknown.


# Task 2: Security Analysis Report

## Critical Vulnerabilities (Top 5)

| CVE ID      | Package      | Severity | Fix Version | Risk Description                          |
|-------------|--------------|----------|-------------|--------------------------------------------|
| CVE-2023-XXX| package-name | CRITICAL | 1.2.3       | Remote code execution, privilege escalation|
| CVE-2023-YYY| package-name | CRITICAL | 2.0.1       | Denial of service, data leakage            |



## License Compliance

- **GPL:** Yes/No (check Syft/Trivy report)
- **Copyleft licenses:** Yes/No (e.g., GPL, AGPL, LGPL)
- **Commercial Use Risks:**
  - Obligation to disclose source code when using GPL
  - Possible restrictions on proprietary software distribution

---

## Secrets Scanning

- **Trivy Secrets Scanning:** Scanning completed successfully. No secrets found.

# Task 3 -- Accuracy Analysis

## Accuracy Analysis

### Package Detection

-   **Packages detected by both tools:** 1126\
-   **Packages only detected by Syft:** 13\
-   **Packages only detected by Trivy:** 9

This shows that the overlap between tools is very high. However, Syft
identified slightly more unique system-level packages (e.g., `libc6`,
`libssl3`, `node`, `tzdata`), while Trivy detected a few packages that
Syft did not.

------------------------------------------------------------------------

### Vulnerability Detection (CVE Overlap)

-   **CVEs found by Grype:** 95\
-   **CVEs found by Trivy:** 91\
-   **Common CVEs:** 26

Although the number of detected vulnerabilities is similar, the overlap
is relatively small (26 common CVEs). This indicates that vulnerability
databases and detection methodologies differ significantly between the
tools.

------------------------------------------------------------------------

## Strengths & Weaknesses

### Syft + Grype

#### Strengths

-   Modular architecture (SBOM generation + vulnerability scanning
    separated)
-   Deep and detailed SBOM generation
-   Better visibility into system-level dependencies
-   More granular control over analysis workflow

#### Weaknesses

-   Requires two tools (Syft + Grype)
-   More complex CI/CD integration
-   Slightly slower setup and pipeline configuration

------------------------------------------------------------------------

### Trivy

#### Strengths

-   All-in-one solution (packages, vulnerabilities, secrets, licenses)
-   Built-in secrets scanning
-   Built-in license scanning
-   Easy CI/CD integration
-   Fast scanning

#### Weaknesses

-   Less detailed SBOM compared to Syft
-   Slightly lower transparency in package-level breakdown

------------------------------------------------------------------------

## Use Case Recommendations

-   **Enterprise / Security-focused environments → Syft + Grype**\
    Suitable when detailed SBOMs, modular workflows, and deeper analysis
    are required.

-   **Small teams / Fast CI pipelines → Trivy**\
    Best choice when simplicity, speed, and unified scanning (vulns +
    secrets + licenses) are priorities.
