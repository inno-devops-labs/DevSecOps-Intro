# Lab 4 — SBOM Generation and Software Composition Analysis

I generated two inventories of `bkimminich/juice-shop:v20.0.0`, scanned the
CycloneDX SBOM with Grype, and compared the results with a Trivy image scan.
All results below come from the same local Linux/amd64 image on 20 September
2026. The branch `feature/lab4` starts at `main` and contains only this lab's
report, two SBOMs, and the unsigned attestation statement.

| Tool | Version |
|---|---|
| Syft | 1.52.0, official Linux container |
| Grype | 0.119.0, Windows/amd64 |
| Trivy | 0.74.0, Windows/amd64 |
| jq | 1.8.1 |
| Docker Engine | 29.2.1, Docker Desktop Linux backend |

The Grype database was built at `2026-09-20T06:27:54Z` (schema `v6.1.9`).
Trivy used database version 2, updated at `2026-09-20T07:08:21.474120123Z`.
These timestamps matter: future scans can return different findings without
any change to the image.

## Task 1

The Windows Syft binary failed while caching image layers because its generated
paths contained a colon. I used the official container for the actual scan,
with both outputs generated from one cataloging run. From the repository root
in PowerShell:

```powershell
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}/labs/lab4:/out" `
  anchore/syft:v1.52.0 docker:bkimminich/juice-shop:v20.0.0 `
  -o cyclonedx-json=/out/juice-shop.cdx.json `
  -o spdx-json=/out/juice-shop.spdx.json

jq '.components | length' labs/lab4/juice-shop.cdx.json
jq '.packages | length' labs/lab4/juice-shop.spdx.json
jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
```

| Measurement | Actual result |
|---|---:|
| CycloneDX components | 3069 |
| SPDX packages | 909 |
| CycloneDX `specVersion` | 1.7 |
| SPDX files, counted separately from packages | 2167 |

The CycloneDX `components` array contains 907 libraries, one application, one
operating system, and 2160 file components, whereas SPDX keeps file records
outside its 909-entry `packages` array. Thus the 2160-entry difference reflects
what these arrays count, not 2160 additional installed packages in one scan.

Both [CycloneDX](../labs/lab4/juice-shop.cdx.json) and
[SPDX](../labs/lab4/juice-shop.spdx.json) are committed, following the submission
instructions and acceptance criteria; the final pitfall saying not to commit
SPDX contradicts those requirements.

I scanned the saved SBOM rather than pulling or rescanning the image:

```powershell
grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
# Keep the same database for the second output.
$env:GRYPE_DB_AUTO_UPDATE = 'false'
grype sbom:labs/lab4/juice-shop.cdx.json -o table --file labs/lab4/grype-from-sbom.txt
Remove-Item Env:GRYPE_DB_AUTO_UPDATE
```

| Severity | Grype matches |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 0 |
| **Total** | **183** |

These are vulnerability/package matches, not distinct advisory IDs. The 183
matches contain 157 distinct IDs; an advisory affecting several installed
versions can produce several rows.

The following are the first ten rows from the assignment's explicit severity
sort: Critical, High, Medium, Low, Negligible, Unknown. I preserved the tool's
order within the same severity rather than introducing an extra ranking.

| Severity | Advisory | Package | Installed version | Fix version |
|---|---|---|---|---|
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0 | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.4.0 | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | lodash | 2.4.2 | 4.17.12 |
| Critical | CVE-2026-63073 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | decompress | 4.2.1 | No fix listed |
| Critical | GHSA-xwcq-pm8m-c4vf | crypto-js | 3.3.0 | 4.2.0 |
| Critical | CVE-2026-34182 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| Critical | GHSA-23hp-3jrh-7fpw | tar | 4.4.19 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar | 6.2.1 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar | 7.5.15 | 7.5.19 |

**Nine of the ten rows have a listed fix.** With only severity and fix
availability to guide triage, I would address the fixable Critical findings
first, rebuilding the image with updated OS packages and dependencies and
testing the result. For example, `libssl3t64` at `3.5.7-1~deb13u2` meets both
listed fix thresholds, while all three affected `tar` versions need attention.
The Critical `decompress` finding has no listed fix, so I would investigate
removal, replacement, or restricting the affected functionality rather than
silently accepting it. The fix column is advisory-specific, not a guarantee
that its minimum version resolves every vulnerability in that package.

## Task 2

I scanned the image with the requested severity filter:

```powershell
trivy image bkimminich/juice-shop:v20.0.0 `
  --severity LOW,MEDIUM,HIGH,CRITICAL `
  --format json --output labs/lab4/trivy.json
```

The comparison normalizes severity names to the same case and counts only
Trivy's `Vulnerabilities` arrays. Trivy's default secret scan also produced
results, which are not included in these vulnerability totals.
Delta means **Trivy minus Grype**.

| Severity | Grype | Trivy | Delta |
|---|---:|---:|---:|
| Critical | 14 | 10 | -4 |
| High | 85 | 64 | -21 |
| Medium | 65 | 68 | +3 |
| Low | 12 | 31 | +19 |
| Negligible | 7 | 0 | -7 |
| Unknown | 0 | 0 | +0 |
| **Total** | **183** | **173** | **-10** |

The all-reported total is 183 versus 173. On the four shared severity levels,
the comparison is 176 versus 173, a delta of -3; Grype's seven Negligible
matches are outside the requested Trivy severity filter. A smaller total is
not evidence that a scanner is more accurate.

After deduplication, Grype reports 157 advisory IDs and Trivy 146. Comparing
the literal IDs gives 104 Grype-only and 93 Trivy-only IDs, but many of these
are GHSA/CVE aliases for the same issue. For example, Grype reports
`GHSA-c7hr-j4mj-j2w6` for `jsonwebtoken`, while Trivy uses `CVE-2015-9235`.
I therefore checked package versions and advisory metadata before choosing
the two differences below.

| Present in | Absent from the other scan | Package and version | Observed evidence and likely cause |
|---|---|---|---|
| Grype | `CVE-2026-48617` | `node@24.15.0` | Grype records a `cpe-match` in `nvd:cpe` for `/nodejs/bin/node`. Trivy's vulnerability results cover Debian packages and npm packages, with no finding for this runtime CVE. This points to a difference in binary discovery or matching coverage in this run. |
| Trivy | `CVE-2025-57349` / `GHSA-xfqm-j7pc-xrfc` | `messageformat@2.3.0` | The package is present in the SBOM, but neither identifier appears in Grype's matches. Grype's database explicitly limits the affected range to `<2.3.0`; Trivy flags `2.3.0` and lists `3.0.0-beta.0` as fixed. This points to different handling of the affected/fixed version boundary, not a missing npm package. |

For the second case, I checked the database directly with:

```powershell
grype db search --pkg messageformat --vuln GHSA-xfqm-j7pc-xrfc -o json
```

The [GitHub advisory](https://github.com/advisories/GHSA-xfqm-j7pc-xrfc)
also lists affected versions `<2.3.0` and patched version `3.0.0-beta.0`.
That inconsistent-looking boundary warrants review before treating Trivy's
finding as confirmed; a scanner disagreement alone does not establish which
result is correct.

Keeping inventory and scanning separate is useful when releases must be
rescanned as advisories change, without downloading each image again.
The saved SBOM also provides an artifact for audit and reuse: Lab 8 signs the
CycloneDX predicate with Cosign and attaches it to the image as an attestation.
A single Trivy command is simpler for a quick local or CI image check when
there is no need to retain an independently reusable inventory.
The split approach adds artifact storage and the responsibility to keep each
SBOM tied to the exact image digest.

The raw Grype JSON/table and Trivy JSON remain local and are excluded from
the PR, as required. Both severity tables and the top ten were calculated
from these files, not copied from example numbers.

## Bonus

The [attestation statement](../labs/lab4/juice-shop-attestation.json) embeds the
entire CycloneDX document as its `predicate`. It is prepared for signing;
no Cosign signature has been created in this lab.

The image digest was read from `docker image inspect` and checked against
the image reference recorded by Trivy:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

I used this jq invocation to create the file (shown in Bash syntax for reliable
quoting; on Windows the same arguments were passed directly to `jq.exe`):

```bash
jq --arg image 'bkimminich/juice-shop:v20.0.0' \
  --arg digest 'fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0' \
  '{_type: "https://in-toto.io/Statement/v0.1",
    subject: [{name: $image, digest: {sha256: $digest}}],
    predicateType: "https://cyclonedx.org/bom", predicate: .}' \
  labs/lab4/juice-shop.cdx.json > labs/lab4/juice-shop-attestation.json
```

The type strings come from [Cosign 3.0.2's statement generator](https://github.com/sigstore/cosign/blob/v3.0.2/pkg/cosign/attestation/attestation.go)
and its [in-toto v0.9.0 constants](https://github.com/in-toto/in-toto-golang/blob/v0.9.0/in_toto/attestations.go).
Cosign uses `https://in-toto.io/Statement/v0.1` and the unversioned
`https://cyclonedx.org/bom`; the assignment's introductory “Statement v1”
label does not match the Cosign behavior its hints and criteria require.

The first 20 lines of the generated file are:

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
    "serialNumber": "urn:uuid:11226de9-ae36-4dee-8a47-138af2ccd3ba",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-20T11:36:32Z",
      "tools": {
```

The digest is the intended signing subject because it identifies immutable
content, whereas a tag can be moved to a different image.

This statement claims that the embedded inventory describes the image named
by that digest. A deployment policy or auditor could check the digest, the
trusted signer's signature after Lab 8, and the SBOM's contents.
The unsigned file alone provides no authenticated claim, and even a valid
signature would not prove that the inventory is complete or that the image
is free of vulnerabilities.
