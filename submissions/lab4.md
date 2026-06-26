# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `labs/lab4/juice-shop.cdx.json` component count: `3069`
- `labs/lab4/juice-shop.cdx.json` size: `365 MB image scanned; JSON saved in `labs/lab4/juice-shop.cdx.json``
- `labs/lab4/juice-shop.spdx.json` package count: `909`

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

### Top 10 CVEs / advisories

| CVE / Advisory | Severity | Package | Installed | Fix |
|---|---|---|---:|---|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 |  |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 |  |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 |  |

### Fix-available rate

Out of the top 10 findings, 7 have a fix available. That means the most useful first step is not to chase every issue in severity order, but to prioritize the high-severity findings that already have remediation paths. In practice, the best triage shortcut is: fix-available first, then severity ≥ HIGH, then everything else.

## Task 2: Trivy Comparison

### Trivy severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |
| Medium | 39 |
| Low | 22 |
| **Total** | **109** |

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **104** | **109** | **+5** |

### Why the difference?

The two scanners do not use the same matching and advisory sources, so they do not always agree on the same package-to-vulnerability mapping. In this run, Grype reported several GHSA advisories that Trivy did not, while Trivy surfaced some older CVEs that were not present in Grype’s SBOM-based result. That difference is expected when the database refresh cadence, package matching logic, and advisory normalization are not identical.

Two concrete examples from this run:

1. `GHSA-23c5-xmqv-rm74` — found by **Grype**, not found by **Trivy**.  
   Likely reason: Grype’s advisory mapping and GHSA normalization matched the affected package/version more aggressively, while Trivy did not surface the same advisory in this scan.

2. `CVE-2015-9235` — found by **Trivy**, not found by **Grype**.  
   Likely reason: Trivy’s image scan included a CVE entry that did not appear in Grype’s SBOM-based result, either because of database differences or because the package was normalized differently by the two tools.

### When would I pick each?

I would pick **Syft + Grype** when I want a reusable SBOM as the long-term source of truth. That model is better for attestation, repeatable rescans, and later labs such as signing and verification.

I would pick **Trivy** when I want a fast all-in-one CI step. It is convenient because it can scan images directly and also cover other security checks in the same toolchain.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: `1.6`
- `bomFormat`: `CycloneDX`

### Image digest captured

- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate

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
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:666c5759-807c-4196-aa3d-a62c1236bc0a",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T17:30:48+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "[not provided]"
          }
        ]
      }
    }
  }
}
```

### What this enables in Lab 8

This attestation signs the CycloneDX SBOM for `bkimminich/juice-shop:v20.0.0`. The claim is that the SBOM content belongs to that exact image digest, so later verification can prove which image inventory was signed and prevent mix-ups between different image builds or tags.
