# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1,832,332 bytes (~1.8 MB)
- `juice-shop.spdx.json` component count: 909 packages

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

Status breakdown: 89 fixed, 15 not-fixed, 0 ignored.

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (none — won't fix) |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (none) |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | (none) |

### Fix-available rate
Out of the top 10 (all 7 Criticals + 3 Highs), 7 out of 10 have a fix available — the 3 without one are `libc6` (vendor marked "won't fix"), `marsdb`, and `lodash.set` (both abandoned/unmaintained packages with no patched release). Applying Lecture 4's triage shortcut — sort by fix-available AND severity ≥ HIGH first — the priority list is: bump `jsonwebtoken` to 4.2.2, `lodash` to 4.17.21 (covers both the Critical and High lodash findings), `crypto-js` to 4.2.0, and

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 104 (incl. 7 Negligible) | 109 | +5 |

### Why the difference?

**CVE 1 — found by Trivy, missed by Grype: hardcoded RSA private key in `lib/insecurity.ts` / `build/lib/insecurity.js`.** Trivy's secret scanner flagged this as a HIGH "AsymmetricPrivateKey" finding. Grype never finds this at all because Grype only does SCA (matching known packages against CVE databases) — it has no secret-scanning capability, since it works purely from the SBOM's component list, not the actual file contents. This is the clearest divergence: it's not a database freshness issue, it's a fundamentally different scanner category.

**CVE 2 — found by Grype, missed by Trivy in the HIGH/CRITICAL table: `GHSA-p6mc-m468-83gw` (lodash.set prototype pollution).** Grype lists this as a HIGH severity finding via the GHSA advisory ID with no fix version. Trivy's JSON shows the same underlying issue (`CVE-2020-8203`) but with no severity assigned in the table output (it printed as `affected` status with a blank severity column), meaning it likely got filtered out of my `--severity HIGH,CRITICAL` table view even though the JSON technically captured it. This points to Trivy and Grype using different advisory ID schemes (GHSA vs CVE) for the same underlying issue, and different severity-assignment logic when the upstream advisory doesn't carry an explicit CVSS score.

### When would you pick each?

**Syft+Grype (decoupled) wins** when the SBOM itself needs to be a long-lived, signable artifact — exactly what Lab 8 needs. Since the SBOM is generated once and can be rescanned against an updated Grype DB at any time without re-pulling or re-analyzing the image, this is the right model for supply-chain attestation and "did the new Log4Shell-style CVE affect anything I shipped six months ago" questions.

**Trivy (all-in-one) wins** as a single CI step where you want vulnerability scanning, secret scanning, misconfig scanning, and even IaC scanning in one tool call with one config. For a quick "is this image safe to push" gate in a pipeline, Trivy's broader scope (it caught a real hardcoded private key that Grype structurally cannot detect) makes it the stronger default, even though it doesn't produce a separately reusable SBOM artifact the way the Syft+Grype split does.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.6
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'`: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

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
    "serialNumber": "urn:uuid:391f02e6-aff8-489c-abbc-863c7b8a9a27",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T11:20:26+03:00",
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
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json --key ... bkimminich/juice-shop:v20.0.0`, it wraps this in-toto statement in a DSSE envelope and signs it with the private key, then pushes the signed attestation to the registry alongside the image. What's actually being signed is the cryptographic binding between the exact image digest (`subject.digest.sha256`) and the exact dependency inventory captured in `predicate` — not the image tag, which is mutable, but the immutable content hash. The resulting claim, verifiable by anyone with the public key via `cosign verify-attestation`, is: "the entity holding this private key asserts that the image identified by this specific sha256 digest contains exactly this set of 908 packages, generated by Syft 1.45.1 at this timestamp." This is the foundation for supply-chain trust — a downstream consumer can verify the SBOM hasn't been swapped or tampered with after the fact, and can re-run Grype against the signed SBOM at any future point to check for newly disclosed CVEs without needing to re-pull or re-trust the image itself.