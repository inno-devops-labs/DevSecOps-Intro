# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1834859
- `juice-shop.spdx.json` component count: 909

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
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 |  |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 |  |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 |  |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-gjcw-v447-2w7q | High | jws | 0.2.6 | 3.0.0 |

### Fix-available rate
Out of the top 10 CVEs, 7 have a fix available. According to Lecture 4's triage shortcut: *sort by fix-available AND severity ≥ HIGH first*, the vulnerabilities with high/critical severities having fixes available should be updated first _(higher risk reduction)_. Vulnerabilities without an available fix should be monitored and mitigated through compensating controls until a patch becomes available.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 50 | 42 | -8 |
| Medium | 35 | 39 | 4 |
| Low | 4 | 22 | 18 |
| **Total** | 96 | 108 | 12 |

### Why the difference?
1. `CVE-2026-53550` found by Trivy, missed by Grype.  
    Why: Trivy may have a more frequently updated or differently sourced vulnerability database, so the CVE appears earlier than in Grype.
2. `CVE-2025-57349` found by Trivy, missed by Grype.  
    Why: Differences in vulnerability matching and data normalization. Trivy may match the CVE using broader advisory data, while Grype may not associate it with the package due to incomplete or ambiguous version range metadata.

### When would you pick each?
- Syft + Grype's decoupled model wins in SBOM-as-an-attestation cases. SBOM is a structured, signed artifact describing the software components of a build, which can be used as verifiable evidence of what is inside an image and to support supply-chain verification.

- Trivy's all-in-one approach wins in CI pipelines: it provides a single tool that performs scanning without an intermediate SBOM generation step. Additionally, it covers a broader security scope, including IaC, secrets, and misconfigurations, making it simpler to integrate and operate in CI workflows.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.5
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

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
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:ea57c49e-66d4-4b8b-bcaa-c5664bcd0622",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-17T21:25:30+03:00",
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
According to Lecture 8, "A **signature** proves _who_. An **attestation** proves _what_." When an attestation is signed by Cosign, the signature proves who issued the attestation and that it has not been tampered with. Meanwhile, the attestation proves which components and dependencies are part of the build.