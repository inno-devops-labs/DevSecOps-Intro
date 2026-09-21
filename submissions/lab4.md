# Lab 4 Submission

## Task 1: SBOM generation and Grype analysis

Syft cataloged 908 packages. The generated CDX document contains
3068 components with `specVersion` 1.7, while the SPDX document contains 909
package records. CDX represents discovered packages, executables, and
nested inventory elements as components. SPDX records packages separately and
expresses other evidence through different fields and relationships, so the two
top-level counts are not directly equivalent.

Artifacts:

`labs/lab4/juice-shop.cdx.json`
`labs/lab4/juice-shop.spdx.json`

### Grype results

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total** | **183** |

Grype reported 156 findings with an available fix and 27 without one.

### Top 10 findings by severity

| # | Severity | Vulnerability | Package | Installed | Fixed version |
|---:|---|---|---|---|---|
| 1 | Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0 | 4.2.2 |
| 2 | Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.4.0 | 4.2.2 |
| 3 | Critical | GHSA-jf85-cpcp-j695 | lodash | 2.4.2 | 4.17.12 |
| 4 | Critical | CVE-2026-63073 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| 5 | Critical | GHSA-mp2f-45pm-3cg9 | decompress | 4.2.1 | No fix listed |
| 6 | Critical | GHSA-xwcq-pm8m-c4vf | crypto-js | 3.3.0 | 4.2.0 |
| 7 | Critical | CVE-2026-34182 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| 8 | Critical | GHSA-23hp-3jrh-7fpw | tar | 4.4.19 | 7.5.19 |
| 9 | Critical | GHSA-23hp-3jrh-7fpw | tar | 6.2.1 | 7.5.19 |
| 10 | Critical | GHSA-23hp-3jrh-7fpw | tar | 7.5.15 | 7.5.19 |

Nine of the ten highest-severity matches have a fixed version. These upgrades
should be prioritized and tested for compatibility. The `decompress` finding
has no fix listed, so it requires investigation of reachability and possible
removal or replacement of the dependency, followed by compensating controls
and continued monitoring.

## Task 2: Grype and Trivy comparison

For a direct comparison, Grype's seven `Negligible` findings were excluded
because the Trivy command requested only LOW through CRITICAL severities.

| Severity | Grype | Trivy | Trivy − Grype |
|---|---:|---:|---:|
| Critical | 14 | 10 | -4 |
| High | 85 | 64 | -21 |
| Medium | 65 | 68 | +3 |
| Low | 12 | 31 | +19 |
| **Comparable total** | **176** | **173** | **-3** |

The raw Grype total is 183 when its seven `Negligible` findings are included.
Trivy reported 173 findings.

### Findings that differed

1. **CVE-2026-48617** was reported by Grype for the `node` 24.15.0 binary with
High severity, but it was not reported by Trivy. Syft included the standalone
Node executable in the SBOM, and Grype matched it using its binary package
matcher and vulnerability database. Trivy's direct image scan did not
produce the same match.

2. **CVE-2025-57349** was reported only by Trivy for `messageformat` 2.3.0.
Trivy classified it as Low severity and listed `3.0.0-beta.0` as the fixed
version. The finding was absent from all strings in the Grype result. This
indicates a difference in advisory ingestion or ecosystem package matching
between the vulnerability databases at scan time.

Identifier normalization also affects a simple ID comparison. For example,
Trivy reports `CVE-2015-9235`, while Grype uses
`GHSA-c7hr-j4mj-j2w6` as the primary identifier and stores
`CVE-2015-9235` as a related vulnerability. These are the same underlying
finding rather than a scanner disagreement.

### When to use each approach

Syft plus Grype is useful when the SBOM must be stored as an independent
artifact, rescanned later without pulling the image again, or attached to an
image as a supply-chain attestation. In Lab 8, Cosign signs and attaches this
CDX SBOM to the image as an attestation.

Trivy is useful when a CI pipeline needs a simpler all-in-one image scanning
command and may also use Trivy's secret, configuration, and IaC scanners.
Using both scanners can expose database, identifier, and package-matching
differences.

## Bonus

The following jq command wrapped the complete CDX SBOM in an in-toto
statement:

```bash
jq \
  --arg name "$IMAGE_REF" \
  --arg digest "$IMAGE_SHA256" \
  '{
    "_type": "https://in-toto.io/Statement/v0.1",
    "subject": [{
      "name": $name,
      "digest": {"sha256": $digest}
    }],
    "predicateType": "https://cyclonedx.org/bom",
    "predicate": .
  }' \
  labs/lab4/juice-shop.cdx.json \
  > labs/lab4/juice-shop-attestation.json
```

The statement uses registry digest
`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.
The digest identifies the exact immutable image content, while the tag
`v20.0.0` can later be moved to a different image.

The statement claims that its subject image is associated with the embedded
CDX SBOM. After it is signed, a consumer or an admission policy can
verify the producer and detect modification of the subject digest or SBOM.
It does not prove that the image is vulnerability-free or that every SBOM
component is trustworthy.

First 20 lines of `labs/lab4/juice-shop-attestation.json`:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:d617647c-36a2-45af-9f04-633d294ce2eb",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-21T08:32:42+03:00",
      "tools": {
```
