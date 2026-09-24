# Lab 4 — SBOM Generation and Software Composition Analysis

Branch: `feature/lab4`. Executed on 2026-09-18.

Image: `bkimminich/juice-shop:v20.0.0`, local Linux/amd64 variant.
Repository/index digest from `docker inspect`:
`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.
The archived index identifies the Linux/amd64 manifest as
`sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`;
Trivy reports its config digest as
`sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce`.
These are different digest kinds, not different scanned images. The results cover
Linux/amd64 only, not every platform listed in the index.

Tools: Syft **1.51.1**, Grype **0.118.0**, Trivy **0.74.0** (the repository pins),
jq **1.8.1**, Docker **29.7.2**. Scanners ran in containers with a read-only image
archive instead of access to the Docker socket. Both SBOM formats were emitted
by one Syft invocation, so the inventory and timestamp are shared.

## Task 1

### Inventory and format comparison

| Measurement | Actual value |
| --- | ---: |
| CycloneDX `.components` | 3069 |
| SPDX `.packages` | 909 |
| CycloneDX `specVersion` | 1.7 |
| SPDX `spdxVersion` | SPDX-2.3 |
| SPDX `.files` (separate from packages) | 2167 |

Syft emits 2160 file components, 907 libraries, one application (`node`), and one
operating-system component (`debian`) in CycloneDX, while SPDX places files in a
separate `.files` array rather than counting them in `.packages`.
The package arrays also model the root differently (SPDX includes the container;
CycloneDX puts the container in `metadata.component` and includes Debian as a
component), so these are format-specific object counts, not conflicting counts
of installed dependencies.

### Grype severity counts

Counts below are matching rows, not distinct advisories: one advisory can affect
more than one package. Grype scanned the CycloneDX file, not the image.

| Severity | Matches |
| --- | ---: |
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 0 |
| **Total** | **183** |

Distinct Grype advisory identifiers: **157**.
Database metadata recorded by Grype:

```json
{
  "schemaVersion": "v6.1.9",
  "from": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-09-18T00:31:45Z_1789713015.tar.zst?checksum=sha256%3A5776a9b7190b6e6eccdb47023eb1cb7bffcfc4cb9ed2b11d777484a577ca3336",
  "built": "2026-09-18T06:30:15Z",
  "path": "/cache/6/vulnerability.db",
  "valid": true
}
```

### Top ten (the exact severity ordering from task 4.3)

The sort uses Critical, High, Medium, Low, Negligible, Unknown, retaining original
order inside each severity; no alphabetical severity sort or deduplication.

| Severity | Identifier | Package | Installed version | Fix versions |
| --- | --- | --- | --- | --- |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0 | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.4.0 | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | lodash | 2.4.2 | 4.17.12 |
| Critical | CVE-2026-63073 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | decompress | 4.2.1 | — |
| Critical | GHSA-xwcq-pm8m-c4vf | crypto-js | 3.3.0 | 4.2.0 |
| Critical | CVE-2026-34182 | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| Critical | GHSA-23hp-3jrh-7fpw | tar | 4.4.19 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar | 6.2.1 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar | 7.5.15 | 7.5.19 |

**9/10** rows have a non-empty fix-version list. Given only severity and fix
availability, I would upgrade the fixable Critical findings first, then fixable
High findings; Critical findings without a fix still need containment or removal,
not dismissal. The fix column is a starting point for selecting an upgrade, and
compatibility and the resulting scan must be checked after rebuilding.

## Task 2

### Grype versus Trivy

Delta = Grype minus Trivy. Trivy severity names were normalized to title case.
Trivy was run with LOW,MEDIUM,HIGH,CRITICAL as requested, so its zero values for
Negligible/Unknown mean excluded from this comparison, not proof of absence.

| Severity | Grype | Trivy | Delta |
| --- | ---: | ---: | ---: |
| Critical | 14 | 10 | +4 |
| High | 85 | 64 | +21 |
| Medium | 65 | 68 | -3 |
| Low | 12 | 31 | -19 |
| Negligible | 7 | 0 | +7 |
| Unknown | 0 | 0 | +0 |
| **Total** | **183** | **173** | **+10** |

Trivy distinct advisory identifiers: **146**.
Trivy DB updated at `2026-09-18T07:09:02.741569251Z`, downloaded at
`2026-09-18T19:02:47.025661759Z` (schema 2). Counts are a dated database snapshot,
not the earlier example numbers in `tools/versions.yaml`.

### Divergent identifiers

The raw unique-ID comparison yields 104 identifiers only in Grype and 93 only
in Trivy. These are identifier differences, not 197 independent missed flaws:
Grype often reports a GHSA as the primary identifier and its CVE as a related
identifier, while Trivy reports the CVE.

| Direction | Identifier | Package | Best explanation from the scan evidence |
| --- | --- | --- | --- |
| Grype only | CVE-2026-48617 | `node@24.15.0` | Grype's `stock-matcher` records a `cpe-match` against `nvd:cpe`, using `cpe:2.3:a:nodejs:node.js:24.15.0:*:*:*:*:*:*:*`. Trivy's results contain Debian packages and npm packages, but no finding for the standalone Node binary. The likely cause is runtime-binary detection/matching coverage, rather than a missing npm dependency. |
| Trivy only | CVE-2025-57349 | `messageformat@2.3.0` | Trivy's source is GitHub Security Advisory npm and it lists `3.0.0-beta.0` as fixed. Syft includes `pkg:npm/messageformat@2.3.0`, but Grype has no matching or ignored finding for this package and no related identifier for this CVE. Different advisory/version-range treatment is the likely cause: Trivy's own description says versions **prior to 2.3.0**, which conflicts with flagging 2.3.0. This is a candidate false positive to investigate, not proof that Grype missed an exploitable flaw. |

As an additional source/alias example, Trivy reports `NSWG-ECO-428` for
`base64url@0.0.6` from the Node.js Security Working Group; Grype reports the same
out-of-bounds-read problem as `GHSA-rvg8-pwq2-xj7q`, with the same fix, `3.0.0`.
The different identifier alone therefore does not establish a coverage gap.

### Choosing the workflow

A separate inventory is worth keeping when many images must be rescanned against
new advisories without pulling and unpacking them again, or when the inventory
must be archived and shared across scanners. Lab 8 uses this exact CycloneDX SBOM
as the predicate of a signed Cosign attestation bound to an image digest.
The inventory must still be complete and generated for the right image/platform,
and new vulnerability knowledge requires an updated scanner database.
A single binary such as Trivy is simpler for a small CI pipeline or an ad hoc
image check where managing a separately stored SBOM adds little value.

## Bonus

`labs/lab4/juice-shop-attestation.json` is a **sign-ready, unsigned statement**;
no signature or registry attachment was created in Lab 4. The type strings were
checked against [Cosign 3.0.2's statement generator](https://github.com/sigstore/cosign/blob/v3.0.2/pkg/cosign/attestation/attestation.go)
and [in-toto's constants](https://github.com/in-toto/in-toto-golang/blob/v0.9.0/in_toto/attestations.go):
`_type` is `https://in-toto.io/Statement/v0.1` and `predicateType` is
`https://cyclonedx.org/bom`. This follows the actual Cosign implementation rather
than the contradictory “Statement v1” comment in the lab.

Actual jq command (PowerShell, from the repository root):

```powershell
$lab4Digest = 'fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0'
.venv/lab4/jq.exe -n --arg image 'bkimminich/juice-shop:v20.0.0' --arg digest $lab4Digest --slurpfile sbom labs/lab4/juice-shop.cdx.json '{_type:"https://in-toto.io/Statement/v0.1",subject:[{name:$image,digest:{sha256:$digest}}],predicateType:"https://cyclonedx.org/bom",predicate:$sbom[0]}' > labs/lab4/juice-shop-attestation.json
```

First 20 lines of the generated statement:

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
    "serialNumber": "urn:uuid:a10f445b-f8b8-4364-beb5-80053964ccdf",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-18T19:01:31Z",
      "tools": {
```

The digest prepared for signing is
`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`;
a digest binds immutable content, whereas a tag can be reassigned. As requested,
this is the repository digest from `docker inspect`; the SBOM covers its locally
available Linux/amd64 child, not the unscanned ARM64 child.

The statement claims that its embedded inventory describes the named image at
that digest, with the platform limitation above. A consumer or deployment-policy
verifier would check the trusted signer's signature, subject digest and predicate
in Lab 8; this unsigned file alone authenticates no signer. Even a valid signature
does not prove inventory completeness, absence of vulnerabilities, exploitability,
or that every platform in a multi-platform index was scanned.

## Reproduction and validation

Both scans consumed the same archive created by:

```powershell
docker save bkimminich/juice-shop:v20.0.0 -o .venv/lab4/juice-shop.tar
```

Container commands used these arguments (host bind mounts mapped the archive to
`/image.tar`, `labs/lab4` to `/out`, and the Grype cache to `/cache`):

```text
anchore/syft:v1.51.1 docker-archive:/image.tar -o cyclonedx-json=/out/juice-shop.cdx.json -o spdx-json=/out/juice-shop.spdx.json
anchore/grype:v0.118.0 sbom:/out/juice-shop.cdx.json -o json --file /out/grype-from-sbom.json
anchore/grype:v0.118.0 sbom:/out/juice-shop.cdx.json -o table --file /out/grype-from-sbom.txt
aquasec/trivy:0.74.0 image --input /image.tar --severity LOW,MEDIUM,HIGH,CRITICAL --format json --output /out/trivy.json
```

Grype used `GRYPE_DB_CACHE_DIR=/cache`; its table run reused the same database with
`GRYPE_DB_AUTO_UPDATE=false`. Syft completed successfully offline despite a failed
optional latest-version check. Trivy retained its default secret scan; only
`Vulnerabilities` were counted in these tables, never `Secrets`.

Validation parses all JSON, recomputes severity totals and the top ten, and checks
that the attestation predicate equals the complete CycloneDX document. Both SBOMs
are retained as required by the deliverable and acceptance criteria, overriding
the contradictory final pitfall saying not to commit SPDX. Raw Grype/Trivy outputs
remain local and ignored by Git. The large-file hook exemption names only the
three required generated JSON files; secret/private-key checks remain enabled.
