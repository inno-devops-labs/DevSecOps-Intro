# Lab 4 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (Syft SBOM + Grype) · Task 2 (Trivy comparison) · **Bonus Task** (`juice-shop-attestation.json`, +2 pts)

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

| Format | Count field | Value |
|--------|-------------|------:|
| CycloneDX | `.components \| length` | **3068** |
| SPDX | `.packages \| length` | **909** |
| CycloneDX | `specVersion` | **1.7** |

CycloneDX and SPDX disagree because they inventory different units of the same image: CycloneDX lists a broad set of components (application packages, OS packages, binaries, and nested/transitive artifacts Syft models as separate components), while SPDX’s package list is a narrower, SPDX-oriented package inventory (~900 entries here). Same image, different schema semantics and counting rules — not two conflicting “truths.”

### Grype severity table (from SBOM)

```bash
grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
```

| Severity | Count |
|----------|------:|
| Critical | 14 |
| High | 84 |
| Medium | 61 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 4 |
| **Total** | **182** |

### Top ten findings (severity-ranked)

| Severity | ID | Package | Fix |
|----------|----|---------|-----|
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken@0.1.0 | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken@0.4.0 | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | lodash@2.4.2 | 4.17.12 |
| Critical | CVE-2026-63073 | libssl3t64@3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | decompress@4.2.1 | *(none listed)* |
| Critical | GHSA-xwcq-pm8m-c4vf | crypto-js@3.3.0 | 4.2.0 |
| Critical | CVE-2026-34182 | libssl3t64@3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@4.4.19 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@6.2.1 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@7.5.15 | 7.5.19 |

**Fixes available in this top ten:** **9 of 10** have a fix version (only `decompress@4.2.1` / `GHSA-mp2f-45pm-3cg9` has an empty fix column).

**What I would do first:** start with Critical rows that already have a fix — bump `jsonwebtoken`, `lodash`, `crypto-js`, and `tar` to the listed fixed versions, and refresh the Debian OpenSSL packages (`libssl3t64`) to the fixed versions. Leave the no-fix Critical (`decompress`) for compensating controls / upstream tracking after the fixable Criticals are scheduled.

## Task 2

### Grype vs Trivy severity (normalized to UPPERCASE)

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output labs/lab4/trivy.json
```

| Severity | Grype | Trivy | Delta (Trivy − Grype) |
|----------|------:|------:|----------------------:|
| CRITICAL | 14 | 10 | -4 |
| HIGH | 84 | 64 | -20 |
| MEDIUM | 61 | 67 | +6 |
| LOW | 12 | 31 | +19 |
| NEGLIGIBLE | 7 | 0 | -7 |
| UNKNOWN | 4 | 0 | -4 |
| **Total** | **182** | **172** | **-10** |

Unique advisory IDs: Grype **156**, Trivy **145**.

### One finding each direction

1. **Grype only — `GHSA-23hp-3jrh-7fpw` on `tar@4.4.19` / `6.2.1` / `7.5.15` (Critical).** Related CVE in Grype metadata: `CVE-2026-59873`. Trivy’s ID list does not contain this GHSA. Best explanation: **different advisory identifier / matching rule** — Grype surfaces the GitHub Security Advisory ID for the npm `tar` issue; Trivy may lag on that GHSA entry or key the same issue under another ID/source in this DB snapshot.

2. **Trivy only — `CVE-2015-9235` on `jsonwebtoken@0.1.0` and `0.4.0` (CRITICAL).** Grype does not list `CVE-2015-9235`; it does list other `jsonwebtoken` advisories as GHSAs (e.g. `GHSA-c7hr-j4mj-j2w6`). Best explanation: **different advisory source / ID mapping** — Trivy reports the older NVD CVE for vulnerable `jsonwebtoken`, while Grype’s npm matching prefers GHSA IDs for the same package family, so a naive ID join misses the CVE even when both tools flag the package.

### Decoupled SBOM vs all-in-one

A decoupled inventory (Syft SBOM → Grype) is worth the extra moving part when you need a durable artifact: re-scan next month without re-pulling the image, feed DefectDojo/Lab 10, and — critically for this course — **hand Lab 8 a CycloneDX file to attach as a signed Cosign attestation**. A single binary like Trivy is the better answer for a quick gate in CI when you only care about “fail the build if Critical/High today” and do not need a reusable SBOM. Once Lab 8 signs the SBOM, the inventory itself becomes supply-chain evidence; the scanner results are then optional consumers of that same file.

## Bonus Task — sign-ready attestation (+2 pts)

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

First 20 lines of the result:

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
    "serialNumber": "urn:uuid:de5b1ff6-66f0-4c49-84fa-a5f998faf99e",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-14T18:04:34+03:00",
      "tools": {
```

### Digest

`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` — sign the **digest**, not the tag, because tags are mutable and can be retargeted; the digest pins the exact image bytes the SBOM describes.

### What this file claims / does not prove

This in-toto Statement claims that the subject image digest was inventoried as the embedded CycloneDX BOM (`predicateType` Cosign uses for `--type cyclonedx`). A verifier (Lab 8 / Cosign / a registry policy) checks the signature over this statement to trust that *someone with the signing key* attested that SBOM to that digest. It does **not** prove the image is free of vulnerabilities, that the scanner was run, or that the BOM is complete — only that this inventory was asserted for that digest by the signer.
