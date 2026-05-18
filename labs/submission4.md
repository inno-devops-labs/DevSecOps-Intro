# Lab 4 — SBOM Generation & Software Composition Analysis

### Overview

In this lab, Software Bills of Materials (SBOMs) were generated for the
OWASP Juice Shop container image (`bkimminich/juice-shop:v19.0.0`).
Software Composition Analysis (SCA) was then performed using different
toolchains to evaluate dependency and vulnerability coverage.

Tools used:

- Syft (SBOM generation)
- Grype (vulnerability scanning)
- Trivy (SBOM + vulnerability + license scanning)

## Task 1 — SBOM Generation and Analysis

SBOMs were generated using Syft and Trivy for `bkimminich/juice-shop:v19.0.0`.

Artifacts:
- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab4/syft/juice-shop-syft-table.txt`
- `labs/lab4/trivy/juice-shop-trivy-detailed.json`
- `labs/lab4/trivy/juice-shop-trivy-table.txt`
- `labs/lab4/analysis/sbom-analysis.txt`

### SBOM Analysis

Syft and Trivy both detected application and operating system packages, but they structure the results differently. Syft provides a detailed SBOM-focused artifact model, while Trivy combines package inventory with vulnerability and license scanning features.

Package and license summaries are stored in:

```text
labs/lab4/analysis/sbom-analysis.txt
```

### License Discovery Analysis

License information was extracted from both tools. License compliance is important because restrictive or unclear licenses may create legal and operational risk. For production use, packages with unknown, custom, or copyleft licenses should be reviewed before release.

## Task 2 — Software Composition Analysis

SCA was performed with Grype and Trivy.

Artifacts:

- `labs/lab4/syft/grype-vuln-results.json`
- `labs/lab4/syft/grype-vuln-table.txt`
- `labs/lab4/trivy/trivy-vuln-detailed.json`
- `labs/lab4/trivy/trivy-secrets.txt`
- `labs/lab4/trivy/trivy-licenses.json`
- `labs/lab4/analysis/vulnerability-analysis.txt`

### Vulnerability Analysis

Both Grype and Trivy detected vulnerabilities identified by CVE IDs and advisories. The severity distribution and top findings are summarized in`labs/lab4/analysis/vulnerability-analysis.txt`

Critical and high findings should be prioritized first. Remediation should include upgrading affected packages to fixed versions, rebuilding the image, and rescanning to confirm that CVEs are resolved.

### License Compliance Assessment

License risk was reviewed using Syft and Trivy license outputs.License compliance risk should be assessed before using dependencies in production. Packages with missing or unusual license metadata require manual review.

### Secrets Scanning

Trivy secrets scanning was executed and saved to: `labs/lab4/trivy/trivy-secrets.txt`

Secrets scanning helps detect accidentally committed credentials, tokens, private keys, and other sensitive data.

## Task 3 — Toolchain Comparison

Toolchain comparison data was generated in:
`labs/lab4/comparison/accuracy-analysis.txt`

### Accuracy and Coverage

The comparison includes:
- packages detected by both tools
- packages only detected by Syft
- packages only detected by Trivy
- CVEs detected by Grype
- CVEs detected by Trivy
- common CVEs between both scanners

### Tool Strengths and Weaknesses

Syft + Grype:
- Strong SBOM-focused workflow
- Good for separating inventory generation from vulnerability analysis
- Useful when SBOM artifacts must be stored or passed between pipeline stages

Trivy:
- Convenient all-in-one scanner
- Supports vulnerabilities, licenses, secrets, and package inventory
- Easier to integrate quickly into CI/CD

### Recommendations

Use Syft + Grype when the goal is a dedicated SBOM-first workflow and when SBOM artifacts need to be preserved. Use Trivy when a single integrated scanner is preferred for fast CI/CD checks covering vulnerabilities, licenses, and secrets.