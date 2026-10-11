# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: 1.5M
- `juice-shop.spdx.json` component count: 911

### Grype severity breakdown (paste table or JSON)

Grype didn't work. I got the error:
```
$ grype sbom:labs/lab4/juice-shop.cdx.json \
  -o json --file labs/lab4/grype-from-sbom.json

 ✔ Vulnerability DB                [validating]  [0020]  WARN error updating db

[0020] ERROR failed to load vulnerability db: database does not exist
```
I tried to fix it but didn't succeed. I don't know what's wrong.



## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | - | 5 | 5 |
| High | - | 43 | 43 |
| Medium | - | 22 | 22 |
| Low | - | 39 | 39 |
| **Total** | - | 109 | 109 |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:
1. CVE ID + tool that found it + tool that missed it
2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?

(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

### When would you pick each?
2-3 sentences each:
- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8)
- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig)

**Syft + Grype (decoupled) wins when:**
You need an SBOM as an attestation. One SBOM can be generated once and re-scanned over time as new CVEs are published, without re-pulling the image.

**Trivy (all-in-one) wins when:**
You want a simple, single step in CI/CD that covers not only CVEs but also IaC misconfigurations, secrets, and license issues. Trivy is easier to integrate into a pipeline because one tool does many things, and it doesn't require maintaining separate SBOM artifacts.