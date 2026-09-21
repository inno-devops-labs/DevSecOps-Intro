# Lab 4 — SBOM Generation and Software Composition Analysis

The scans below used the course-pinned releases: Syft `1.51.1`, Grype `0.118.0`,
and Trivy `0.74.0`. The target was `bkimminich/juice-shop:v20.0.0` at digest
`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

## Task 1

### SBOM inventory

```console
$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3068
$ jq '.packages | length' labs/lab4/juice-shop.spdx.json
909
$ jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
1.7
```

The counts differ because the two formats model and expose the inventory differently. In this
output, CycloneDX puts 2,159 file entries alongside 907 libraries, one application, and one
operating system in its single `components` array, while SPDX keeps 909 software packages in
`packages` and records 2,166 file entries separately in `files`; therefore comparing only
`.components` with `.packages` does not compare equivalent object classes.

### Grype severity summary

```console
$ jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab4/grype-from-sbom.json
[
  { "severity": "Critical",   "count": 14 },
  { "severity": "High",       "count": 85 },
  { "severity": "Low",        "count": 12 },
  { "severity": "Medium",     "count": 65 },
  { "severity": "Negligible", "count": 7 }
]
```

| Severity | Findings |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 0 |
| **Total** | **183** |

These values are a snapshot from the vulnerability database used on 2026-09-21. They can
change even when the SBOM does not because advisories and severity metadata continue to evolve.

### Top ten findings

The required severity-ranked query produced:

```text
Critical  GHSA-c7hr-j4mj-j2w6  jsonwebtoken@0.1.0       fix: 4.2.2
Critical  GHSA-c7hr-j4mj-j2w6  jsonwebtoken@0.4.0       fix: 4.2.2
Critical  GHSA-jf85-cpcp-j695  lodash@2.4.2             fix: 4.17.12
Critical  CVE-2026-63073        libssl3t64@3.5.5-1~deb13u2  fix: 3.5.7-1~deb13u2
Critical  GHSA-mp2f-45pm-3cg9  decompress@4.2.1         fix:
Critical  GHSA-xwcq-pm8m-c4vf  crypto-js@3.3.0          fix: 4.2.0
Critical  CVE-2026-34182        libssl3t64@3.5.5-1~deb13u2  fix: 3.5.6-1~deb13u2
Critical  GHSA-23hp-3jrh-7fpw  tar@4.4.19               fix: 7.5.19
Critical  GHSA-23hp-3jrh-7fpw  tar@6.2.1                fix: 7.5.19
Critical  GHSA-23hp-3jrh-7fpw  tar@7.5.15               fix: 7.5.19
```

Nine of the ten rows have a fix available. Given only severity and fix availability, I would
first upgrade the fixable Critical findings, grouping repeated rows for the same dependency and
advisory into one remediation change and then rescanning to confirm removal. I would immediately
investigate exposure and compensating controls for the unfixed Critical `decompress` finding,
rather than silently leaving it until a patch appears.

## Task 2

### Grype versus Trivy

Both tables count vulnerability-to-package matches, not distinct advisory identifiers. The
delta is `Grype - Trivy`, after normalising severity case.

| Severity | Grype from SBOM | Trivy from image | Delta |
|---|---:|---:|---:|
| Critical | 14 | 10 | +4 |
| High | 85 | 64 | +21 |
| Medium | 65 | 68 | -3 |
| Low | 12 | 31 | -19 |
| Negligible | 7 | 0 | +7 |
| Unknown | 0 | 0 | 0 |
| **Total** | **183** | **173** | **+10** |

Trivy was invoked with `LOW,MEDIUM,HIGH,CRITICAL`, so its zero in the Negligible row reflects
the requested severity filter as well as the scanners' different severity taxonomies.

### Identifier differences

- **Grype-only ID `GHSA-c7hr-j4mj-j2w6`:** Grype reports this against
  `jsonwebtoken@0.1.0` and `jsonwebtoken@0.4.0`. Trivy does not emit that exact identifier, but
  it reports `CVE-2015-9235` for the same package versions and links back to the GHSA. This is an
  advisory-source and canonical-ID difference, not evidence that Trivy missed the underlying
  vulnerability.
- **Trivy-only ID `CVE-2015-9235`:** Trivy uses this CVE as the primary identifier for the same
  two `jsonwebtoken` installations. Grype instead chooses the GitHub Advisory Database record
  above as primary and carries CVE data through the advisory relationship, so a literal ID-set
  comparison incorrectly makes one shared finding look like two scanner-specific findings.

This result also shows why production comparisons should normalise GHSA-to-CVE aliases before
calling a discrepancy a miss.

### Operational comparison

The decoupled Syft-plus-Grype approach is worth the extra artifact when one immutable inventory
must be scanned repeatedly by several tools, retained for audit, or queried quickly after a new
advisory without pulling and unpacking every image again. That SBOM also becomes a supply-chain
artifact: Lab 8 attaches the CycloneDX document to the image as a signed attestation. Trivy's
single-binary image scan is the better answer for a fast local or CI gate where setup simplicity
matters more than retaining a reusable inventory. In practice I would keep the attested SBOM as
the durable record and still use an all-in-one scan for immediate feedback.

## Bonus

### Sign-ready in-toto statement

I generated the envelope with the immutable digest returned by Docker:

```bash
DIGEST=$(docker image inspect bkimminich/juice-shop:v20.0.0 \
  --format '{{index .RepoDigests 0}}' | sed 's/.*@sha256://')
jq --arg image 'bkimminich/juice-shop:v20.0.0' --arg digest "$DIGEST" \
  '{_type:"https://in-toto.io/Statement/v0.1",
    subject:[{name:$image,digest:{sha256:$digest}}],
    predicateType:"https://cyclonedx.org/bom",
    predicate:.}' \
  labs/lab4/juice-shop.cdx.json > labs/lab4/juice-shop-attestation.json
```

The first 20 lines are:

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
    "serialNumber": "urn:uuid:995a6da5-bc8d-42db-9895-9d1e48f92769",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-21T11:38:58+03:00",
      "tools": {
```

The statement covers digest
`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.
A digest identifies immutable image bytes, whereas the `v20.0.0` tag is a mutable registry
pointer that can later be moved to different content.

The file claims that the identified image has exactly the embedded CycloneDX inventory. In Lab
8, Cosign signs this statement; a deployer, auditor, registry policy, or incident responder can
then verify the signature and query the predicate. The JSON file by itself proves neither who
made the claim nor that the inventory is complete or vulnerability-free; those assurances need
a trusted signature, trustworthy generation process, and separate policy or vulnerability
analysis.
