# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **3069**
- `juice-shop.cdx.json` size: **1832321 bytes** (~1.8 MB)
- `juice-shop.spdx.json` component count: **909**

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | — |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | — |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | — |

### Fix-available rate
Out of the top 10 CVEs, **7 have a fix available** (4.2.2, 4.17.12, 4.2.0, 3.5.6-1~deb13u2, 4.17.21, 2.29.2); 3 have no published fix (CVE-2026-5450, GHSA-5mrr-rgp6-x4gr, GHSA-p6mc-m468-83gw). Per Lecture 4's triage shortcut, patch cadence should prioritize **fix-available AND severity ≥ HIGH first** — meaning jsonwebtoken, lodash, crypto-js, and libssl3t64 upgrades come before unfixable Criticals like marsdb, which require compensating controls (remove/replace the package) rather than a version bump.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **104** | **109** | **+5** |

*(Trivy does not report a Negligible tier; its total covers CRITICAL/HIGH/MEDIUM/LOW only.)*

### Why the difference?

1. **GHSA-35jh-r3h4-6jhm** — found by **Grype**, missed by **Trivy**
   - Package: `lodash@2.4.2`, severity High, fix: 4.17.21
   - Likely reason: Grype's npm advisory matching links this GHSA to the transitive lodash copy in the SBOM component list; Trivy scans the image filesystem directly and may deduplicate or miss this advisory ID when the same package version is already matched under a different CVE/GHSA alias.

2. **CVE-2019-25225** — found by **Trivy**, missed by **Grype**
   - Package: `sanitize-html@1.4.2`, severity Medium, fix: 2.0.0-beta
   - Likely reason: Trivy's vulnerability DB (Trivy DB v2, updated 2026-06-18) includes this older CVE for sanitize-html; Grype's v6.1.7 DB may not map this CVE to the exact package version in the CycloneDX SBOM, or uses a different advisory ID for the same underlying issue.

### When would you pick each?

- **Syft+Grype (decoupled)** wins when you need a **persistent SBOM artifact** that can be re-scanned when new CVEs drop without re-pulling the image — exactly the Lab 8 Cosign attestation pattern where the signed SBOM proves "this is what was in the image at build time."
- **Trivy (all-in-one)** wins when you want a **single CI step** that scans images, filesystems, IaC, secrets, and misconfigs in one tool — simpler pipeline, broader scope, but the SBOM is ephemeral unless you explicitly export it.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **1.5**
- `bomFormat`: **CycloneDX**

### Image digest captured
- `docker inspect ... RepoDigests`: **bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0**

### Attestation predicate (first 30 lines of juice-shop-attestation.json)
```
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
    "serialNumber": "urn:uuid:5db347ad-121e-4c4f-8885-8b6f682127b3",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-18T23:16:55+03:00",
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
      ...
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, Cosign signs the **in-toto Statement** binding the CycloneDX SBOM (predicate) to the specific image digest (subject). The attestation proves: *"the signer attests that image sha256:fd58bdc9… contained exactly these 3069 components at the time of scanning."* This is a supply-chain claim verifiable by anyone with the public key — not just a scan report, but a cryptographically linked provenance record.
