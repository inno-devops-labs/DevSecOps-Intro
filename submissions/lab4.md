# Lab 4 — SBOM Generation and Software Composition Analysis

Tools: syft 1.52.0, grype 0.119.0, trivy 0.74.0. Target: `bkimminich/juice-shop:v20.0.0`
(digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`).

## Task 1

### SBOM component counts

| File | Format | Count | specVersion |
|------|--------|------:|-------------|
| `juice-shop.cdx.json` | CycloneDX | 3068 components | 1.7 |
| `juice-shop.spdx.json` | SPDX | 909 packages | — |

**Why the two disagree.** CycloneDX (via Syft) inventories *every* component it can resolve — each npm package **and** its transitive dependencies, OS packages, and individual files/binaries — so a Node image with a deep `node_modules` tree explodes to ~3000 entries. SPDX here counts distinct *packages* at a coarser granularity (it collapses file-level and many nested entries into fewer package records), so the same image yields ~900. Same bits, two counting conventions: CycloneDX leans toward maximal component enumeration, SPDX toward package-level records.

### Severity table (Grype, from the SBOM)

| Severity | Count |
|----------|------:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total matches** | **183** |

(183 matches map to 157 unique advisory IDs — the same advisory recurs when several packages in the image are affected.)

### Top ten findings (ranked)

| Severity | ID | Package@version | Fix |
|----------|----|-----------------|-----|
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken@0.1.0 | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken@0.4.0 | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | lodash@2.4.2 | 4.17.12 |
| Critical | CVE-2026-63073 | libssl3t64@3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | decompress@4.2.1 | *(none)* |
| Critical | GHSA-xwcq-pm8m-c4vf | crypto-js@3.3.0 | 4.2.0 |
| Critical | CVE-2026-34182 | libssl3t64@3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@4.4.19 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@6.2.1 | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | tar@7.5.15 | 7.5.19 |

### Fix availability and first action
**9 of the 10 have a fix** (only `decompress@4.2.1` / GHSA-mp2f-45pm-3cg9 has no fixed version). Using only the severity and fix columns, I would **first bump the Critical findings that have a fixed version and are trivial one-line dependency updates** — jsonwebtoken → 4.2.2, lodash → 4.17.12, crypto-js → 4.2.0, tar → 7.5.19, and rebuild the base to pull the patched `libssl3t64`. They are the highest-impact, lowest-effort wins ("Critical + fix available" = do now). The fixless `decompress` Critical goes to a separate track: it needs a mitigation or replacement rather than a version bump, so it can't be closed by patching and shouldn't block the quick wins.

## Task 2

### Grype vs Trivy severity (side by side)

| Severity | Grype | Trivy | Δ (Grype−Trivy) |
|----------|------:|------:|----------------:|
| Critical | 14 | 10 | +4 |
| High | 85 | 64 | +21 |
| Medium | 65 | 68 | −3 |
| Low | 12 | 31 | −19 |
| Negligible | 7 | 0 | +7 |
| **Total** | **183** | **173** | **+10** |

(Grype severities are title-case, Trivy's UPPERCASE; normalised before comparing. Trivy has no "Negligible" bucket, so those land in its Low/none. Comparing distinct advisory IDs: 157 unique in Grype, 146 in Trivy, with 104 IDs only in Grype and 93 only in Trivy — but see below, much of that gap is identifier aliasing, not truly missed vulns.)

### Two divergent identifiers, one each direction

- **`CVE-2026-48617` — found by Grype, missed by Trivy.** Package: **`node@24.15.0`**, detected by Grype as a *binary* artifact. Grype's binary classifier treats the Node.js runtime itself as a versioned product and matches runtime CVEs against it; Trivy's `node-pkg` analyzer inventories npm `package.json` entries and OS packages, not the interpreter binary as its own package, so runtime-level Node CVEs don't appear. Cause: **different matching rule / different treatment of the interpreter binary as a package.**
- **`CVE-2015-9235` — found by Trivy, missed by Grype.** Package: **`jsonwebtoken@0.1.0`/`0.4.0`**. This is *not* actually missed — Grype flags the very same jsonwebtoken versions, but reports them under **GHSA identifiers** (`GHSA-8cf7-32gw-wr33`, `GHSA-c7hr-j4mj-j2w6`, …) rather than the CVE alias. Cause: **different advisory source / identifier namespace** (GitHub Advisory vs CVE). A naive `comm` over raw ID strings counts it as a divergence, when it is the same finding under a different name — which is exactly why the 104/93 "only in X" numbers overstate the real disagreement.

### Decoupled inventory vs single binary
The **decoupled** approach (Syft SBOM + Grype) is worth the extra moving part when the inventory has a life of its own beyond a single scan: you generate the SBOM **once**, then re-scan that file against fresh advisories every day without pulling or rebuilding the image, share it with auditors as a CISA-style SBOM deliverable, and — critically — **feed it into Lab 8, which signs the CycloneDX SBOM as an in-toto attestation attached to the image**, so downstream consumers can verify *what* they're running. The **single binary** (Trivy) is the better answer when you just need a fast, one-shot pass/fail gate in CI — one tool, no artifact to manage, image-in / findings-out. Rule of thumb: decouple when the SBOM is itself a governed artifact (attestation, audit, longitudinal rescans); reach for the all-in-one when you only need a gate.

## Bonus

### The `jq` command
```bash
DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | sed 's/.*sha256://')
jq -n --arg name "bkimminich/juice-shop:v20.0.0" --arg digest "$DIGEST" \
  --slurpfile bom labs/lab4/juice-shop.cdx.json \
  '{
     _type: "https://in-toto.io/Statement/v0.1",
     predicateType: "https://cyclonedx.org/bom",
     subject: [ { name: $name, digest: { "sha256": $digest } } ],
     predicate: $bom[0]
   }' > labs/lab4/juice-shop-attestation.json
```

First 20 lines of the result:
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:ea46a522-a5c3-414e-bbaa-c16029244dc2",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-21T10:48:32+03:00",
      "tools": {
```
The two type strings are the ones Cosign actually emits: statement type `https://in-toto.io/Statement/v0.1` (v0.1, **not** v1) and the unversioned CycloneDX predicate type `https://cyclonedx.org/bom`.

### The digest, and why digest not tag
Signed over `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`. **The digest is content-addressed and immutable; the tag is a mutable pointer.** `:v20.0.0` can be re-pushed to point at a different image later, so an attestation bound to the tag could be silently attached to something it never described — binding to the digest means the attestation is provably about *these exact bytes*.

### What this file claims, who checks it, what it doesn't prove
The statement **claims: "this CycloneDX SBOM is the bill of materials for the image with this exact digest"** — it binds an inventory to specific content. It is checked by a **downstream consumer / deployment gate** (in Lab 8, via `cosign verify-attestation`, which confirms the signature and that the predicate is bound to the digest they're about to run). It does **not** prove the software is safe, vulnerability-free, or correct, and — until Lab 8 signs it — it does not prove *authenticity* either: unsigned, anyone can rewrite this JSON. It only asserts the composition, not the security, of the image.
