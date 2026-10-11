# Lab 4 - Submission

Scan snapshot: 2026-06-19, using Syft 1.45.1, Grype 0.114.0, and Trivy 0.71.1 against `bkimminich/juice-shop:v20.0.0`. Grype was run with `--by-cve`; its vulnerability DB was built at `2026-06-19T08:08:25Z`.

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1.7 MiB
- `juice-shop.spdx.json` package count: 909
- SPDX version: 2.3

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

### Top 10 CVE-labelled findings

The results are ordered by severity and then Grype risk. The critical `GHSA-5mrr-rgp6-x4gr` finding is not included because this table intentionally contains CVE-labelled records.

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2015-9235 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | Critical | lodash | 2.4.2 | 4.17.12 |
| CVE-2023-46233 | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | Not available |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2021-23337 | High | lodash | 2.4.2 | 4.17.21 |
| CVE-2022-24785 | High | moment | 2.0.0 | 2.29.2 |
| CVE-2020-8203 | High | lodash.set | 4.3.2 | Not available |
| CVE-2017-18214 | High | moment | 2.0.0 | 2.19.3 |

### Fix-available rate

Eight of the top ten findings have a known fixed version, so they are the first patch candidates. Following Lecture 4's triage shortcut, I would prioritize fix-available findings with severity at least High, starting with the Critical upgrades; the two findings without a fix need compensating controls, exposure review, and continued monitoring rather than being allowed to block all patchable work.

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Delta (Trivy - Grype) |
|----------|------:|------:|----------------------:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **104** | **109** | **+5** |

### Why the difference?

The unique-ID comparison produced no Grype-only IDs and four Trivy-only IDs. Only one of the four is a CVE; the other three are Node.js Security WG advisories, so inventing a second divergent CVE would misrepresent this database snapshot.

1. `CVE-2025-57349` was reported by Trivy for `messageformat@2.3.0` as Low with fix `3.0.0-beta.0`, but Grype did not report it. Both databases were current on the scan date, so the likely cause is different advisory ingestion or affected-version matching for the GitHub advisory rather than simply a stale database.
2. `NSWG-ECO-428` was reported only by Trivy as a High-severity Node.js Security WG record for `base64url@0.0.6`. This is not a CVE: both tools also report the related `GHSA-rvg8-pwq2-xj7q`, while Trivy retains the legacy NSWG record as an additional finding and assigns it a different severity. This demonstrates source normalization and deduplication differences rather than a vulnerability that Grype completely missed.

### When would I pick each?

Syft + Grype wins when the inventory must be a durable, reusable artifact. The SBOM can be stored, attested, rescanned as databases change, and signed in Lab 8 without pulling or rebuilding the image again.

Trivy wins for a compact CI control because one tool scans the image and can also cover secrets, IaC, and misconfigurations. It is simpler to operate when a separate SBOM lifecycle or attestation is not required.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: `1.6`
- `bomFormat`: `CycloneDX`
- `metadata.timestamp`: `2026-06-19T14:10:17+03:00`
- `metadata.tools`: Syft 1.45.1

### Image digest captured

- `docker image inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate

First 30 lines of `juice-shop-attestation.json`:

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
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:8f689745-bc6b-49ec-8a69-9d1d39ac66f6",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T14:10:17+03:00",
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

The in-toto statement binds the complete CycloneDX predicate to the immutable Juice Shop image digest. A Cosign attestation in Lab 8 will sign the claim that this SBOM describes that exact image, allowing a verifier to check the issuer and artifact binding; it does not claim that the listed components are vulnerability-free.
