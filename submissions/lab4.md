# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1.8 MB
- `juice-shop.spdx.json` component count: 908

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 50 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 103 |

### Top 10 CVEs (paste from jq output)
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
Out of the top 10 most critical vulnerabilities, 7 have a fix available. Following the triage shortcut (prioritizing fix-available AND severity ≥ HIGH), our immediate priority should be bumping the versions of these 7 packages. This approach delivers the maximum risk reduction with the minimal engineering effort, leaving the unpatchable vulnerabilities (like `marsdb` and `libc6`) for deeper architectural review or compensating controls.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 50 | 43 | -7 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 103 | 109 | +6 |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:

1. **CVE-2026-5450 (libc6)** — Found by Grype (Critical), missed by Trivy. 
   **Why:** Grype often performs raw version-string matching against the NVD database. Trivy, however, aggregates data directly from vendor-specific OVAL streams (like the Debian Security Tracker). Trivy likely recognizes that this specific Debian 13.4 build is either unaffected by default configuration or the vendor has marked it as "ignored", effectively filtering out the false positive.

2. **CVE-2015-9235 vs GHSA-c7hr-j4mj-j2w6 (jsonwebtoken)** — Found by both, but under completely different IDs.
   **Why:** Grype relies heavily on the GitHub Security Advisory (GHSA) database for NPM packages extracted via the Syft SBOM. Trivy uses its own mapping algorithm to resolve the vulnerability back to the original MITRE CVE ID. This shows how different database priorities cause reporting discrepancies and complicate vulnerability deduplication.

*(Note: Additionally, Trivy detected hardcoded RSA Private Keys as a HIGH vulnerability because it scans the actual filesystem of the image, whereas Grype only scans the decoupled SBOM package list).*

### When would you pick each?
2-3 sentences each:
- **When does Syft+Grype's decoupled model win?** This model excels when you need SBOMs as standalone artifacts for compliance, software supply chain security, or digital signatures (attestations like in Lab 8). It also allows you to continuously monitor for new CVEs by scanning the lightweight 1.8MB SBOM daily without needing to pull the heavy multi-gigabyte Docker image every time.
- **When does Trivy's all-in-one win?** Trivy is ideal for a fast, simple, and unified CI/CD pipeline step where developers need immediate feedback. Because it scans the image directly, its scope is much broader, catching not just package CVEs, but also hardcoded secrets, misconfigured infrastructure-as-code (Dockerfile flaws), and exposed environment variables in a single run.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.6"
- `bomFormat`: "CycloneDX"

### Image digest captured
- `docker inspect ... RepoDigests`: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (first 30 lines)
```
{
  "_type": "[https://in-toto.io/Statement/v1](https://in-toto.io/Statement/v1)",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "[https://cyclonedx.org/bom/v1.6](https://cyclonedx.org/bom/v1.6)",
  "predicate": {
    "$schema": "[http://cyclonedx.org/schema/bom-1.6.schema.json](http://cyclonedx.org/schema/bom-1.6.schema.json)",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:abaf0ba3-5e90-4beb-8b40-a500d88aa45a",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-17T12:38:11+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.44.0"
          }
        ]
      },
      "component": {
```


### What this enables in Lab 8
By signing this specific `in-toto v1` Statement using Cosign, we are cryptographically binding the CycloneDX SBOM (the `predicate`) to the exact compiled container image digest (the `subject`). This creates a verifiable attestation that proves to consumers that this exact list of dependencies was generated for this exact image build, preventing tampering or supply chain substitution between the build and deployment phases.
