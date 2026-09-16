# Lab 4 — SBOM Generation and SCA

## Task 1

### SBOM counts

Commands:

```bash
syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json
jq '.components | length' labs/lab4/juice-shop.cdx.json
jq '.packages   | length' labs/lab4/juice-shop.spdx.json
jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
```

| Format | Field | Value |
|---|---:|---:|
| CycloneDX | `.components | length` | 3068 |
| SPDX | `.packages | length` | 909 |
| CycloneDX | `specVersion` | 1.7 |

CycloneDX and SPDX disagree because they count different inventory units. CycloneDX models a broad component graph, including many transitive npm dependencies and other artifacts as separate components, while SPDX's package list is a narrower package-oriented view of the same image.

### Grype severity table

Command:

```bash
GRYPE_DB_AUTO_UPDATE=false grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
```

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 64 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 0 |
| **Total** | **182** |

### Top ten findings

| Severity | ID | Package | Fix |
|---|---|---|---|
| Critical | GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.1.0` | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.4.0` | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | `lodash@2.4.2` | 4.17.12 |
| Critical | CVE-2026-63073 | `libssl3t64@3.5.5-1~deb13u2` | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | `decompress@4.2.1` | none listed |
| Critical | GHSA-xwcq-pm8m-c4vf | `crypto-js@3.3.0` | 4.2.0 |
| Critical | CVE-2026-34182 | `libssl3t64@3.5.5-1~deb13u2` | 3.5.6-1~deb13u2 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@4.4.19` | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@6.2.1` | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@7.5.15` | 7.5.19 |

9 of the top 10 have a fix available. Given only severity and fix availability, I would patch the fixable Critical findings first: update `jsonwebtoken`, `lodash`, `crypto-js`, `tar`, and Debian `libssl3t64` before spending time on the no-fix `decompress` finding.

## Task 2

### Trivy severity table

Command:

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output labs/lab4/trivy.json
```

| Severity | Grype | Trivy | Delta (Trivy - Grype) |
|---|---:|---:|---:|
| CRITICAL | 14 | 10 | -4 |
| HIGH | 85 | 64 | -21 |
| MEDIUM | 64 | 68 | +4 |
| LOW | 12 | 30 | +18 |
| NEGLIGIBLE | 7 | 0 | -7 |
| UNKNOWN | 0 | 0 | 0 |
| **Total** | **182** | **172** | **-10** |

Unique advisory IDs: Grype found 156, Trivy found 145. 52 IDs appear in both lists, 104 appear only in Grype, and 93 appear only in Trivy.

### Divergent identifiers

Grype-only: `CVE-2026-48617` on `node@24.15.0` as a binary component. The likely cause is package ecosystem and matching coverage: Grype detects the embedded Node runtime binary from the SBOM and matches it to Node advisories, while Trivy's image result did not report `node` as a vulnerable package.

Trivy-only: `CVE-2015-9235` on `jsonwebtoken@0.1.0` and `jsonwebtoken@0.4.0`. Grype does flag vulnerable `jsonwebtoken`, but under GHSA identifiers such as `GHSA-c7hr-j4mj-j2w6`; this is best explained by different advisory sources and ID mapping, where Trivy reports the CVE and Grype prefers the GitHub Security Advisory ID.

### Decoupled inventory vs. all-in-one scan

The decoupled Syft plus Grype approach is worth the extra moving part when the SBOM is itself a deliverable: the same inventory can be rescanned later without pulling the image, imported into later vulnerability-management work, and signed in Lab 8 as a CycloneDX attestation. Trivy is the better answer for a quick CI gate when I need one command that catalogs and scans the image immediately. The tradeoff is that Trivy's JSON result is a scan report, while the CycloneDX SBOM is reusable supply-chain evidence that can be attached to the image digest.

## Bonus

### `jq` command

```bash
DIGEST_HEX=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | sed 's/.*sha256://')
jq -n --arg digest "$DIGEST_HEX" --slurpfile pred labs/lab4/juice-shop.cdx.json '
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {"sha256": $digest}
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": $pred[0]
}' > labs/lab4/juice-shop-attestation.json
```

First 20 lines:

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
    "serialNumber": "urn:uuid:4085e267-dafb-419b-ab80-6474e89b8cb7",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-16T11:48:24+03:00",
      "tools": {
```

Digest:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

The digest is used instead of the tag because tags are mutable, while the digest pins the exact image manifest that was scanned.

This file claims that the image identified by that digest has the embedded CycloneDX SBOM as its predicate. A verifier such as `cosign verify-attestation`, a CI policy, or an admission controller would check the signed statement before trusting the SBOM. It does not prove the image is vulnerability-free, that the SBOM is perfect, or that the vulnerabilities were fixed; it only binds this inventory claim to this image digest.
