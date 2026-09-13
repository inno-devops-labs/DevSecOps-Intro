# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1832094 bytes (~1.8M)
- `juice-shop.spdx.json` component count: 909
- Tools: Syft 1.49.0, Grype 0.116.0, CycloneDX `specVersion` 1.5

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 11 |
| High | 60 |
| Medium | 46 |
| Low | 7 |
| Negligible | 7 |
| **Total** | **131** |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | *(none / won't fix)* |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 4.4.19 | 7.5.19 |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 6.2.1 | 7.5.19 |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 7.5.15 | 7.5.19 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | *(none)* |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-mp2f-45pm-3cg9 | Critical | decompress | 4.2.1 | *(none)* |

### Fix-available rate
Out of the top 10 Critical findings, **7 have a fix** and **3 do not**. Using Lecture 4’s triage shortcut (*sort by fix-available AND severity ≥ HIGH first*), the immediate patch queue is: `libssl3t64`, `tar`, `jsonwebtoken`, and `lodash`. Items without a fix (`libc6` won't-fix, `marsdb`, `decompress`) stay tracked as accepted risk or need package replacement, not a blind “upgrade everything” pass.

## Task 2: Trivy Comparison

Tools: Trivy 0.52.2 (lab pin notes v0.69.x; DB refreshed 2026-07-26). Scan filter: `LOW,MEDIUM,HIGH,CRITICAL`.

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 11 | 9 | -2 |
| High | 60 | 44 | -16 |
| Medium | 46 | 49 | +3 |
| Low | 7 | 23 | +16 |
| **Total** | **131** | **125** | **-6** |

Note: Grype also reported 7 Negligible; Trivy’s severity filter excluded Negligible.

### Why the difference?
1. **CVE-2026-48937** — found by **Grype**, missed by **Trivy** (exact ID). Grype matched the Node.js **binary** runtime in the image SBOM; Trivy’s image scan did not emit this Node runtime CVE ID. Likely different package-matching rules for language runtimes vs OS/app packages.
2. **NSWG-ECO-428** (`base64url`) — found by **Trivy**, missed by **Grype** (exact ID). Trivy includes the NSWG advisory namespace; Grype’s match set did not include that ID (different DB / advisory sources). Broader pattern: many npm issues appear as `GHSA-*` in Grype and `CVE-*` in Trivy (ID aliasing), so raw ID diffs overstate true disagreement.

### When would you pick each?
- **Syft+Grype (decoupled):** When you need an SBOM as a durable inventory/attestation (Lab 8 Cosign), and want to re-scan the same BOM when new CVEs drop without rebuilding/re-pulling the image.
- **Trivy (all-in-one):** When CI wants one step covering vulns + secrets + misconfig/IaC with simpler wiring and a single tool to maintain.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.5
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 30 lines of `juice-shop-attestation.json`)
```
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop",
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
    "serialNumber": "urn:uuid:6147972f-a448-46a7-9692-394ab29a5f3f",
    "version": 1,
    "metadata": {
      "timestamp": "2026-07-26T21:37:50+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.49.0"
          }
        ]
      },
      "component": {
        ...
```

### What this enables in Lab 8
`cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...` signs an in-toto Statement whose **subject** is the image digest and whose **predicate** is the full CycloneDX SBOM. That proves “this exact image digest was attested to contain this software inventory,” so Lab 8 (and later consumers) can verify provenance of the BOM independently of regenerating Syft output.
