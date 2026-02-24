# Lab 4 — SBOM Generation & SCA

Target: `bkimminich/juice-shop:v19.0.0`

## Task 1 — SBOM Generation (Syft vs Trivy)

### Artifacts
**Syft**
- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab4/syft/juice-shop-syft-table.txt`

**Trivy**
- `labs/lab4/trivy/juice-shop-trivy-detailed.json`
- `labs/lab4/trivy/juice-shop-trivy-table.txt`

### Package type distribution + licenses
See generated analysis:
- `labs/lab4/analysis/sbom-analysis.txt`

Key notes:
- Syft provides a detailed SBOM with artifact types and license fields in the native JSON format.
- Trivy provides package listing grouped by scan targets/classes and can list all packages with `--list-all-pkgs`.

## Task 2 — SCA (Grype vs Trivy)

### Artifacts
**Grype**
- `labs/lab4/syft/grype-vuln-results.json`
- `labs/lab4/syft/grype-vuln-table.txt`

**Trivy**
- `labs/lab4/trivy/trivy-vuln-detailed.json`

### Vulnerability summary
See generated analysis:
- `labs/lab4/analysis/vulnerability-analysis.txt`

Key notes:
- Grype scans vulnerabilities from the Syft SBOM (SBOM-driven workflow).
- Trivy scans the container image directly (integrated scanner).

## Task 3 — Toolchain Comparison (Syft+Grype vs Trivy)

### Quantitative overlap
See generated comparison:
- `labs/lab4/comparison/accuracy-analysis.txt`
- `labs/lab4/comparison/common-packages.txt`
- `labs/lab4/comparison/syft-only.txt`
- `labs/lab4/comparison/trivy-only.txt`

### Practical comparison

**Syft + Grype**
Pros:
- Strong SBOM generation and detailed metadata (good for SBOM-first pipelines)
- Modular: SBOM generation and vuln scanning are separable

Cons:
- Requires multiple tools and artifacts to manage

**Trivy**
Pros:
- All-in-one: SBOM-ish package inventory + vulnerability scanning in one tool
- Simple CI/CD integration

Cons:
- SBOM detail/structure can be less explicit than Syft native JSON for deeper SBOM analysis

## Conclusion / Recommendation
- Use **Syft + Grype** when you want SBOM-first workflows, more detailed SBOM metadata, and modular scanning stages.
- Use **Trivy** when you want a fast, all-in-one scanner for CI/CD with minimal setup.
