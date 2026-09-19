# Lab 4 — SBOM Generation and Software Composition Analysis

## Task 1

Component counts and spec version, read directly from the generated files:

- `labs/lab4/juice-shop.cdx.json`: `components | length` = **3069**
- `labs/lab4/juice-shop.spdx.json`: `packages | length` = **909**
- CycloneDX `specVersion` = **1.7**

**Why the two counts disagree:** CycloneDX and SPDX model "a thing in the image" differently. CycloneDX's `components` array includes every distinct package occurrence it finds across all ecosystems (npm, deb, binary, etc.), including multiple versions of the same package installed side by side and metadata-only entries (e.g. the root application component). SPDX's `packages` array is coarser — it de-duplicates more aggressively and groups some nested/transitive npm packages differently, so the same filesystem produces roughly a third as many top-level "packages" as CycloneDX "components".

Severity table (from `grype-from-sbom.json`, `.matches[].vulnerability.severity` grouped):

| Severity | Count |
|---|---|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total** | **183** |

Top ten findings, ranked Critical → High → Medium → Low → Negligible → Unknown:

| Severity | ID | Package@Version | Fix |
|---|---|---|---|
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken@0.1.0 | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken@0.4.0 | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | lodash@2.4.2 | 4.17.12 |
| Critical | CVE-2026-63073 | libssl3t64@3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | decompress@4.2.1 | (none) |
| Critical | GHSA-xwcq-pm8m-c4vf | crypto-js@3.3.0 | 4.2.0 |
| Critical | CVE-2026-34182 | libssl3t64@3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@4.4.19 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@6.2.1 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@7.5.15 | 7.5.19 |

**Fix availability:** 9 of the 10 rows have a fix version available; only `decompress@4.2.1` (GHSA-mp2f-45pm-3cg9) has no fix listed. Given only the severity and fix columns, I would fix the 9 Critical findings with an available upgrade first — they are both the highest severity and the cheapest to resolve (bump a version, re-test). `decompress` has no fix, so the mitigation there is different: replace or vendor-patch the package, or remove the code path that uses it, since simply waiting for a fix is not an option. It goes last in the immediate upgrade queue precisely because "upgrade" isn't available yet, but it stays flagged for manual follow-up.

## Task 2

Side-by-side severity comparison, Grype (title case) normalized against Trivy (upper case):

| Severity | Grype | Trivy | Delta |
|---|---|---|---|
| Critical | 14 | 10 | +4 |
| High | 85 | 64 | +21 |
| Medium | 65 | 68 | -3 |
| Low | 12 | 31 | -19 |
| Negligible | 7 | 0 | +7 |
| **Total** | **183** | **173** | **+10** |

(Trivy has no "Negligible" bucket — those findings fall into its Low/ignored range, which is part of why the Low counts diverge so much.)

Distinct advisory IDs: Grype 157 unique, Trivy 146 unique.

Two identifiers found by one tool and missed by the other:

- **Grype-only: `CVE-2026-48617`, package `node@24.15.0` (binary).** Grype's SBOM-based scan matches the Node.js binary itself against the Node.js security advisory feed it ships with. Trivy's default scanners target OS packages and a fixed set of language ecosystems (npm, pip, etc.) but do not treat the Node.js runtime binary itself as a scannable "package" the same way, so this Node-runtime CVE never surfaces in its output.
- **Trivy-only: `CVE-2015-9235`, package `jsonwebtoken@0.1.0`/`0.4.0` (npm).** This is an old, low-profile npm advisory. Trivy's vulnerability DB (aggregated from GitHub Advisory Database, NVD, and vendor feeds via `trivy-db`) picked it up, while Grype's matcher for this package/version combination did not surface it — most likely a difference in which advisory source or matching rule (exact-version vs. range) each tool's npm matcher applies for this particular old CVE.

**Decoupled SBOM+scanner vs. all-in-one:** The decoupled approach (Syft generates one SBOM, Grype scans it) is worth the extra moving part when you need to re-scan repeatedly without re-pulling or re-analyzing the image — exactly the point of 4.2: a new CVE drops, and you run Grype against the already-generated `juice-shop.cdx.json` in seconds. It's also worth it when the SBOM itself is a required deliverable, which it is here: Lab 8 takes this same CycloneDX file and signs it as an attestation, something a single all-in-one scan does not produce as a durable, reusable artifact. Trivy's single-binary approach is the better answer when you just need a one-off "is this image safe to ship" verdict with minimal setup and don't need the inventory to persist or be re-scanned or signed later.

## Bonus

`jq` command used to build the attestation:

```bash
DIGEST="fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
jq -n \
  --arg type "https://in-toto.io/Statement/v0.1" \
  --arg name "bkimminich/juice-shop" \
  --arg digest "$DIGEST" \
  --arg predType "https://cyclonedx.org/bom" \
  --slurpfile pred labs/lab4/juice-shop.cdx.json \
  '{
    "_type": $type,
    "subject": [{"name": $name, "digest": {"sha256": $digest}}],
    "predicateType": $predType,
    "predicate": $pred[0]
  }' > labs/lab4/juice-shop-attestation.json
```

The two type strings were not guessed: they were read directly from the Cosign/in-toto-golang source (`in_toto/attestations.go` in `in-toto/in-toto-golang`, the library `cosign`'s `generateCycloneDXStatement` imports) — `StatementInTotoV01 = "https://in-toto.io/Statement/v0.1"` and `PredicateCycloneDX = "https://cyclonedx.org/bom"`.

First 20 lines of the result:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop",
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
    "serialNumber": "urn:uuid:37193a2b-28e5-4fee-9390-179b9134a25e",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-19T19:55:35Z",
```

**Digest signed over:** `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`, obtained via `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'`. The digest is used instead of the tag because a tag like `v20.0.0` is a mutable pointer — someone can push a different image under the same tag later — while the digest is a content hash of the exact bytes that were scanned, so the attestation stays true forever for that specific image, regardless of what the tag points to afterward.

**What this file claims, who checks it, and what it does not prove:** The statement claims "the artifact identified by this exact sha256 digest has the following CycloneDX SBOM as its software inventory." Once Cosign wraps and signs this envelope, anyone with the signer's public key — typically CI/CD or a deployment gate, via `cosign verify-attestation` — can check that the SBOM was produced by a trusted identity and matches the image being deployed. It does **not** prove that the SBOM is complete or accurate (a bug or blind spot in Syft could still miss components), and it says nothing about whether the packages listed are actually vulnerable or safe — that verdict comes from a separate scan (like the Grype/Trivy runs above), not from the attestation itself.
