# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1832321 bytes
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | |

### Fix-available rate
Out of the top 10 CVEs, 7 have a fix available. This suggests that a significant portion of the most critical risks can be mitigated through simple version updates, confirming that the triage shortcut of focusing on fix-available and high/critical severity vulnerabilities is highly effective for rapid risk reduction.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 104 | 109 | +5 |

### Why the difference?
1. **GHSA-23c5-xmqv-rm74**: Found by Grype, missed by Trivy. Likely due to Grype's deeper integration with GitHub Security Advisories for npm packages.
2. **CVE-2016-1000223**: Found by Trivy, missed by Grype. Likely due to Trivy's different vulnerability database sources or more inclusive matching rules for older CVEs.

### When would you pick each?
- **Syft+Grype's decoupled model wins** when you need a persistent record of software components (SBOM) that can be scanned repeatedly as new vulnerabilities are discovered without needing the original image. It is essential for supply chain attestations and compliance.
- **Trivy's all-in-one win** when speed and simplicity are prioritized in CI/CD pipelines. It provides a broader security scope, including not just vulnerabilities but also misconfigurations, secrets, and IaC issues in a single pass.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.6
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:58e7b4d3-...",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T22:50:00Z",
      "tools": [
        {
          "component": {
            "name": "Syft",
            "version": "1.45.1"
          }
        }
      ]
    }
  }
}
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, it is signing the in-toto statement that binds the specific container image digest to the CycloneDX SBOM. This proves the claim that the signed SBOM is an accurate and untampered inventory of the components present in that exact version of the image.
