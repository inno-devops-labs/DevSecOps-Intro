# Lab 4 - Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: `3068`
- `juice-shop.cdx.json` size: `1.7M`
- `juice-shop.spdx.json` component count: `909`

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 50 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **103** |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
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
Out of the top 10 CVEs, 7 have a fix available. That suggests the first patching priority should be the subset that is both high-severity and already fixable, because those issues offer the fastest risk reduction with the least operational debate. Following Lecture 4's triage shortcut, I would sort first by `severity >= HIGH` and then by whether a fixed version already exists, instead of spending early effort on findings that still have no vendor remediation.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Delta |
|----------|------:|------:|------:|
| Critical | 7 | 5 | -2 |
| High | 50 | 43 | -7 |
| Medium | 35 | 39 | 4 |
| Low | 4 | 22 | 18 |
| **Total** | **103** | **109** | **6** |

### Why the difference?
1. `GHSA-35jh-r3h4-6jhm` was reported by **Grype** for `lodash 2.4.2`, while **Trivy** did not report that exact identifier. The most likely reason is different advisory-source mapping and identifier normalization: Grype often preserves GitHub Security Advisory IDs directly, while Trivy may represent a related underlying issue under a CVE-based record instead of the GHSA identifier.
2. `CVE-2015-9235` was reported by **Trivy** for `jsonwebtoken 0.1.0` and `0.4.0`, while **Grype** did not report that exact identifier. The likely explanation is again a database and aliasing difference: Grype surfaced the package risk under `GHSA-c7hr-j4mj-j2w6`, while Trivy chose the CVE identifier for what is probably the same or closely overlapping vulnerability record.

### When would you pick each?
- **Syft + Grype** wins when I want a decoupled workflow where the SBOM becomes a reusable artifact. That matters for attestation, re-scanning the same inventory when a new CVE drops, and later supply-chain steps like Lab 8 where the SBOM itself is part of the signed evidence.
- **Trivy** wins when I want a simpler all-in-one CI step with less tooling glue. It is especially convenient when I also care about adjacent checks such as secrets, misconfigurations, or other scan targets beyond just container package vulnerabilities.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: `1.6`
- `bomFormat`: `CycloneDX`

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

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
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:bb4b36ed-123f-418e-bab4-4e983e1a43bc",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-18T00:23:46+03:00",
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
        "bom-ref": "9a5566eb61b934e9",
        "type": "container",
        "name": "bkimminich/juice-shop",
```

### What this enables in Lab 8
In Lab 8, `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...` will sign an in-toto statement whose subject is the exact Juice Shop image digest and whose predicate is the full CycloneDX SBOM. The claim being made is not just "this image exists," but "this exact image digest is associated with this exact dependency inventory," which makes the SBOM portable as supply-chain evidence and verifiable later by other tools or reviewers.
