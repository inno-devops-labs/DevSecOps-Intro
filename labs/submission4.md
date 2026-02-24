# Lab 4 — SBOM Generation & SCA Analysis

## Task 1 — SBOM Generation

### Syft Results
Syft successfully generated SBOM for Juice Shop container image.

Artifacts generated:
- juice-shop-syft-native.json
- juice-shop-syft-table.txt

Syft provides detailed dependency metadata and license information.

### Trivy Results
Trivy successfully generated SBOM.

Artifacts generated:
- juice-shop-trivy-detailed.json
- juice-shop-trivy-table.txt

Trivy provides integrated SBOM and vulnerability scanning.

### Comparison
Syft:
- More detailed SBOM
- Better dependency graph
- Specialized SBOM tool

Trivy:
- Faster execution
- Integrated security scanning
- Easier workflow

---

## Task 2 — SCA Analysis

### Grype Results
Grype detected vulnerabilities from SBOM.

Strengths:
- Accurate SBOM-based scanning
- Detailed vulnerability mapping

### Trivy Results
Trivy detected vulnerabilities directly from container image.

Strengths:
- All-in-one scanner
- Includes secrets and license scanning

---

## Task 3 — Toolchain Comparison

Syft + Grype:
Pros:
- More accurate SBOM
- Modular architecture
- Better for enterprise pipelines

Cons:
- Requires multiple tools

Trivy:
Pros:
- All-in-one solution
- Easy setup
- Fast scanning

Cons:
- Slightly less detailed SBOM

---

## Conclusion

Both toolchains successfully performed SBOM generation and vulnerability scanning.

Recommendation:

Use Syft + Grype for enterprise SBOM workflows.

Use Trivy for simple and fast CI/CD integration.
