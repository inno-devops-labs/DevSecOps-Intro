# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1,832,332 bytes (~1.83 MB)
- `juice-shop.spdx.json` size: 3,160,184 bytes (~3.16 MB)

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 50 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 103 |

By fix status: 88 fixed, 15 not-fixed.

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (none) |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (none) |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | (none) |

### Fix-available rate
Out of the top 10 CVEs, 7 have a fix available and 3 do not (libc6, marsdb, lodash.set). Following Lecture 4's triage shortcut — sort by fix-available AND severity ≥ HIGH first — the immediate priority is the jsonwebtoken, lodash, crypto-js, and libssl3t64 findings, since these are both critical/high severity and have a direct upgrade path with no engineering tradeoff. The three unfixed findings (libc6, marsdb, lodash.set) require either a base-image bump, a dependency replacement, or accepting the risk with compensating controls, which is a slower remediation track.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 50 | 42 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 103 (incl. 7 Negligible) | 108 | +5 |

### Why the difference?

**1. CVE-2015-9235 (jsonwebtoken) — found by Grype, missed in Trivy's critical bucket but actually present**
Both tools flag jsonwebtoken 0.1.0/0.4.0, but Trivy lists this finding without the same severity weighting Grype applies — Trivy's table shows it under CRITICAL too, but bundles additional advisories (CVE-2022-23539, NSWG-ECO-17) under the same package that Grype's matcher treats as separate match entries with different counts. The likely cause is differing CVE database refresh cadence: Grype pulls from the GitHub Advisory Database + NVD with its own daily sync, while Trivy primarily uses Aqua's `trivy-db` mirror, so the exact set of advisories attached to a package version can diverge by a few days.

**2. CVE-2026-45447 (libssl3t64) — found by Trivy, not in Grype's top 10**
Trivy's OS-level scan flagged `libssl3t64` for CVE-2026-45447 (a heap use-after-free in PKCS7_verify), while Grype's top-10 for the same package only surfaced CVE-2026-34182. This is likely a package-matching rule difference: Grype's matcher for Debian packages sometimes deduplicates multiple CVEs against the same binary into a single highest-severity entry, while Trivy's `trivy-db` lists each CVE against the Debian security tracker individually, so the same installed version can show more distinct CVE rows in Trivy's output.

### When would you pick each?

Syft+Grype's decoupled model wins when the SBOM itself needs to become a durable artifact — for example, when it will be signed and attached as a Cosign attestation (as in this lab's bonus task and Lab 8), or when the same inventory needs to be re-scanned repeatedly as new CVEs are published without re-pulling or re-building the image each time.

Trivy's all-in-one model wins when speed and breadth in a single CI step matter more than artifact reuse — it scans the image directly and also covers IaC misconfigurations and embedded secrets in one pass (as seen here, where it caught the RSA private key in `insecurity.js`), which is convenient for a quick pre-merge gate where you don't need a separately stored SBOM.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: `1.6`
- `bomFormat`: `CycloneDX`

(Already above the 1.5 minimum required by Cosign/Lab 8, so no regeneration with `cyclonedx-json@1.5` was needed.)

### Image digest captured
```
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

Note: this digest was captured after re-pulling the image fresh (the locally cached image had been removed between sessions), so it differs from the digest Syft reported at SBOM-generation time (`sha256:e791a8e0...`). This is expected — the registry can repack the manifest for the same tag over time, and the digest used in the attestation should always reflect the currently pulled image.

### Attestation predicate (first 30 lines)
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
    "serialNumber": "urn:uuid:cae6227a-3867-41f5-a20a-b762e5c0b5ff",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-17T09:55:57+03:00",
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
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, Cosign wraps this in-toto Statement in a DSSE envelope and signs it with the project's signing key, then pushes the signed attestation to the registry alongside the image. What is being signed is not just the raw SBOM file but the binding between a specific image digest (the `subject`) and a specific software inventory (the `predicate`) — the claim being made is "the artifact identified by this exact sha256 digest is composed of precisely these components, as cataloged at this timestamp." Anyone who later pulls the image can verify the signature and trust that the SBOM has not been swapped or tampered with after the fact, which is the foundation for downstream policy checks (e.g. "block deploy if the attested SBOM contains a component with a Critical CVE").
