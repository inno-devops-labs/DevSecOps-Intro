# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: 1504963
- `juice-shop.spdx.json` component count: 911

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical |     5 |
| High |    39 |
| Medium |    24 |
| Low |     4 |
| Negligible |     0 |
| **Total** |    72 |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix      |
|-----|---------|--|-----------|----------|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0     | 4.2.0    |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0     | 4.2.2    |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0     | 4.2.2    |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2     | 4.17.12  |
| GHSA-5mrr-rgp6-x4gr | CRITICAL | marsdb | 0.6.11    | null     |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6     | \>=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3     | 6.0.0    |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1     | 4.1.1    |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0     | 9.0.0    |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0     | \>=4.2.2 |


### Fix-available rate
Out of the top 10 CVEs, how many have a fix available? What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
*sort by fix-available AND severity ≥ HIGH first*.)

Out of the top 10 CVEs, 9 have a fix available and 1 doesn't. This indicates that the majority of critical and high vulnerabilities can be remediated through updates, so patching should be prioritized immediately. Vulnerabilities with severity ≥ HIGH and available fixes should be addressed first, as they provide the highest risk reduction with the least effort.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy |  Δ |
|----------|------:|------:|---:|
| Critical |     5 |     5 |  0 |
| High |    39 |    40 |  1 |
| Medium |    24 |    22 | -2 |
| Low |     4 |    35 | 31 |
| **Total** |    72 |    98 | 26 |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:
1. CVE ID + tool that found it + tool that missed it
2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?

(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

1. CVE-2019-9192 was detected by Trivy but not by Grype. This is likely due to differences in vulnerability database coverage and update cadence, as Trivy may include certain Debian or OS-level advisories that are not yet present or mapped in Grype’s database.
2. CVE-2026-27171 was detected by Trivy but missed by Grype. This could be explained by differences in package matching rules or how each tool correlates SBOM components with vulnerabilities, as well as possible variations in fix-version awareness and advisory sources.
### When would you pick each?
2-3 sentences each:
- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8)
- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig)

**Syft + Grype:**
The decoupled approach is preferable when SBOMs are treated as first-class artifacts, such as for compliance, auditing, or attestation workflows. It allows generating the SBOM once and reusing it across multiple tools and stages, improving reproducibility and traceability. This model fits well in secure supply chain scenarios where SBOMs are signed and stored.

**Trivy:**
Trivy is a better choice for simpler CI/CD pipelines where ease of use and speed are important. It provides an all-in-one solution that scans images, dependencies, IaC, secrets, and misconfigurations in a single step. This makes it ideal for quick security checks and broad coverage without managing separate tools.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.6"
- `bomFormat`: "CycloneDX"

### Image digest captured
- `docker inspect ... RepoDigests`: fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)
```
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "08ffcb35ac68abc7dfe9c6abf7ac9eced211983a464f819799fd2ababf1e81f9"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:7d238965-ebcd-4a65-af14-ed7b719c5a67",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-15T18:07:33+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.45.1"
          }
        ]
      },
      "component": {
```

### What this enables in Lab 8
1 paragraph: when Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`,
what specifically is being signed and what claim does it prove? (Reference Lecture 8 slide 9.)

When Lab 8 runs cosign attest --type cyclonedx --predicate juice-shop-attestation.json ..., Cosign is digitally signing the entire SBOM predicate (the CycloneDX BOM describing all components, dependencies, and the OS) and binding it to the specific container image identified by its digest. As referenced in Lecture 8 slide 9, this creates a verifiable cryptographic claim that proves the image's exact software composition at build time including every npm package, system library, and their versions - was attested by the signer. This enables consumers to cryptographically verify that the SBOM genuinely matches the image they're running, preventing tampering or mismatches between the declared and actual components.