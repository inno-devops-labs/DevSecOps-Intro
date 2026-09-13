# Lab 4 — SBOM Generation and Software Composition Analysis

Tooling: `syft 1.51.1`, `grype 0.118.0`, `trivy 0.74.0`, `jq-1.7.1`.
Target: `bkimminich/juice-shop:v20.0.0`, the image deployed in Lab 1
(`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`).

## Task 1

### Two SBOMs of one image

```bash
$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3068
$ jq '.packages   | length' labs/lab4/juice-shop.spdx.json
909
$ jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
1.7
```

| File | Format | Entries | Size |
|---|---|---:|---:|
| `juice-shop.cdx.json` | CycloneDX 1.7 | 3068 components | 1.7 MB |
| `juice-shop.spdx.json` | SPDX 2.3 | 909 packages | 3.0 MB |

**Why the two disagree.** They are not counting the same kind of thing. Breaking the CycloneDX file down by `type` settles it exactly:

```bash
$ jq -r '[.components[].type] | group_by(.) | map({t:.[0],n:length}) | .[] | "\(.t)\t\(.n)"' \
    labs/lab4/juice-shop.cdx.json
application	1
file	2159
library	907
operating-system	1
```

907 libraries + 1 application + 1 operating-system + **2159 individual files** = 3068. Drop the file entries and 909 is what is left — the same number SPDX reports. Syft emits file-level components into CycloneDX (each with a hash, which is what makes the format usable for integrity checking), while the SPDX output models the image as packages only. Both describe one image; CycloneDX is answering "what bytes are in here", SPDX is answering "what software is installed here". The package-level view agrees perfectly: both files carry 894 `pkg:npm`, 13 `pkg:deb` and 1 `pkg:generic` entries.

Worth noting for Lab 10's dedup work: 70 of the entries are duplicate `name@version` pairs in *both* files — the same library vendored at several paths inside the image.

### Severity table

```bash
$ jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab4/grype-from-sbom.json
[{"severity":"Critical","count":14},{"severity":"High","count":84},{"severity":"Low","count":12},
 {"severity":"Medium","count":61},{"severity":"Negligible","count":7},{"severity":"Unknown","count":4}]
```

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 84 |
| Medium | 61 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 4 |
| **Total matches** | **182** |

182 matches, but only **156 distinct advisories** — the gap is one advisory hitting several copies of the same package.

### Top ten, ranked explicitly

```
Critical	GHSA-c7hr-j4mj-j2w6	jsonwebtoken@0.1.0	fix: 4.2.2
Critical	GHSA-c7hr-j4mj-j2w6	jsonwebtoken@0.4.0	fix: 4.2.2
Critical	GHSA-jf85-cpcp-j695	lodash@2.4.2	fix: 4.17.12
Critical	CVE-2026-63073	libssl3t64@3.5.5-1~deb13u2	fix: 3.5.7-1~deb13u2
Critical	GHSA-mp2f-45pm-3cg9	decompress@4.2.1	fix:
Critical	GHSA-xwcq-pm8m-c4vf	crypto-js@3.3.0	fix: 4.2.0
Critical	CVE-2026-34182	libssl3t64@3.5.5-1~deb13u2	fix: 3.5.6-1~deb13u2
Critical	GHSA-23hp-3jrh-7fpw	tar@4.4.19	fix: 7.5.19
Critical	GHSA-23hp-3jrh-7fpw	tar@6.2.1	fix: 7.5.19
Critical	GHSA-23hp-3jrh-7fpw	tar@7.5.15	fix: 7.5.19
```

### Fix availability and what I would do first

**Nine of the ten have a fix.** The single exception is `GHSA-mp2f-45pm-3cg9` on `decompress@4.2.1`, where the `fix` column is empty — no fixed version has been published.

Given only severity and fix availability, I would act in this order:

1. **`libssl3t64` (two Criticals, both fixed in a patch release of the same Debian package).** One `apt-get upgrade` in the base image closes two Critical findings in a library that terminates TLS for everything in the container. Highest severity, lowest effort, no application code involved — this is the first thing to ship.
2. **`tar` (one Critical across three installed copies, fixed in 7.5.19).** Same advisory, three versions vendored at different depths; one dependency bump per copy, and the duplicate-count problem from the SBOM becomes a concrete work item.
3. **`jsonwebtoken@0.1.0` and `@0.4.0` → 4.2.2.** Critical, fixed, and this is the library that validates the session tokens my Lab 2 auth model flagged as the highest-value asset in the system. A major-version jump, so it carries real regression risk — which is why it is third rather than first despite mattering most.
4. **`decompress@4.2.1`, no fix available**, goes to the bottom of the patch queue and the top of the *decision* queue: nothing to install, so the options are removing the dependency, vendoring a patch, or accepting the risk with a compensating control. Severity alone would have put it first; the fix column is what says "no amount of urgency produces a patch here".

The general rule the two columns give you: **fixed Criticals are work, unfixed Criticals are decisions.** Sorting by severity alone mixes them and guarantees the queue stalls on the one item nobody can close.

## Task 2

### Grype vs Trivy, side by side

```bash
$ jq -c '[.Results[].Vulnerabilities[]? | .Severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab4/trivy.json
[{"severity":"CRITICAL","count":10},{"severity":"HIGH","count":64},
 {"severity":"LOW","count":31},{"severity":"MEDIUM","count":67}]
```

| Severity | Grype (SBOM) | Trivy (image) | Delta |
|---|---:|---:|---:|
| Critical | 14 | 10 | −4 |
| High | 84 | 64 | −20 |
| Medium | 61 | 67 | +6 |
| Low | 12 | 31 | +19 |
| Negligible | 7 | 0 | −7 |
| Unknown | 4 | 0 | −4 |
| **Total matches** | **182** | **172** | **−10** |
| **Distinct advisories** | **156** | **145** | **−11** |

Note the case difference the spec warns about — Grype prints `Critical`, Trivy prints `CRITICAL`; joining the two tables without normalising gives a table of zeros. The `Negligible` and `Unknown` bands exist only in Grype, and Trivy redistributes much of what Grype calls High into Medium and Low, because the two tools pick a severity from different vendor feeds when several disagree (Trivy says so explicitly in its own log: `Using severities from other vendors for some vulnerabilities`).

Where the tools agree completely is the Debian layer: 49 OS-package findings each.

### Two divergent identifiers

```bash
$ comm -23 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l    # grype only
104
$ comm -13 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l    # trivy only
93
```

**Found by Grype, missed by Trivy: `CVE-2026-48617`.**

```bash
$ jq -r '.matches[] | select(.vulnerability.id=="CVE-2026-48617")
         | "\(.artifact.name)@\(.artifact.version) type=\(.artifact.type) ns=\(.vulnerability.namespace)"' \
    labs/lab4/grype-from-sbom.json
node@24.15.0 type=binary ns=nvd:cpe
```

The package is the **Node.js runtime binary itself**, matched by CPE against NVD. Syft catalogues `/usr/local/bin/node` as a `binary` component; Grype then matches that CPE. Trivy's result set for this image contains exactly two vulnerability targets — `debian 13.4` (OS packages) and `Node.js` (`node-pkg`, i.e. the npm tree) — and no entry for the interpreter binary. This is the *ecosystem one tool does not parse* case: 15 of Grype's matches come from `binary`-type artifacts that Trivy never creates a package for.

**Found by Trivy, missed by Grype: `CVE-2019-10744`.**

```bash
$ jq -r '.Results[].Vulnerabilities[]? | select(.VulnerabilityID=="CVE-2019-10744")
         | "\(.PkgName)@\(.InstalledVersion) sev=\(.Severity) src=\(.DataSource.Name)"' labs/lab4/trivy.json
lodash@2.4.2 sev=CRITICAL src=GitHub Security Advisory npm
```

This one is not actually a miss, and that is the more interesting answer. Grype *does* report this vulnerability on the same package — as `GHSA-jf85-cpcp-j695`, the Critical lodash entry sitting third in my top-ten table. Both tools read the same GitHub Security Advisory; Trivy emits the CVE alias as the identifier, Grype emits the GHSA. A naive `comm` on identifier strings therefore reports a disagreement that does not exist. That mechanism explains the shape of both exclusive lists: Grype-only IDs are overwhelmingly `CVE-2026-*` on OS and binary packages, Trivy-only IDs are overwhelmingly old `CVE-2015..2019-*` on npm packages that Grype already reported under a `GHSA-` name. **Deduplicating by identifier alone would double-count these in Lab 10; the alias map is the thing that matters.**

### Decoupled inventory vs single binary

The decoupled split earns its extra moving part whenever the inventory outlives the scan. The SBOM is produced once, at build time, from a filesystem that still exists; from then on every new advisory is answered by re-running Grype against a 1.7 MB JSON file in seconds, with no registry pull, no network access to the image, and no dependence on the image still being available — which matters most for the images you shipped six months ago and no longer build. It also makes the inventory itself an artifact you can hand to somebody: **Lab 8 signs this exact CycloneDX file as a CycloneDX attestation attached to the image digest**, so a consumer can verify both that the SBOM is authentic and that it describes the image they are actually running. A scanner's internal package list cannot be signed, published, or diffed between releases; a file can.

The single binary wins when the question is "is this image safe to promote, right now". Trivy needs one command, no intermediate artifact to store or keep in sync, and it sees things an SBOM-based scan cannot — in this run it also scanned the image for embedded secrets alongside the CVE check. The failure mode of the decoupled approach is a stale SBOM: scan an inventory that no longer matches the image and you get a confident, clean, wrong answer. My practical split is both — Trivy as the CI gate on every build, Syft plus Grype to produce the signed inventory that Lab 8 attests to and Lab 10 triages.

## Bonus

### The command

```bash
DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | cut -d: -f2)

jq -n --arg d "$DIGEST" --slurpfile bom labs/lab4/juice-shop.cdx.json \
  '{_type:"https://in-toto.io/Statement/v0.1",
    predicateType:"https://cyclonedx.org/bom",
    subject:[{name:"bkimminich/juice-shop:v20.0.0", digest:{sha256:$d}}],
    predicate:$bom[0]}' > labs/lab4/juice-shop-attestation.json
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
    "serialNumber": "urn:uuid:37b59ccf-f1dc-4c19-a71c-181938f8f83e",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-13T19:46:35+03:00",
      "tools": {
```

The two type strings are the ones Cosign actually uses, and both are traps if you guess: the statement type is **`https://in-toto.io/Statement/v0.1`**, not `v1`, and the CycloneDX predicate type is **`https://cyclonedx.org/bom`** — unversioned, with no `/v1.7` suffix, even though the document it wraps is spec version 1.7.

### The digest, not the tag

Signed over `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

A tag is a mutable pointer: `v20.0.0` can be re-pushed tomorrow to a completely different image, and every signature naming the tag would still "verify" against content nobody inspected. The digest *is* the content — it is the hash of the manifest — so a statement about a digest can never silently come to describe something else. Lab 8's tag-overwrite demo is exactly this failure, performed deliberately.

### What this file claims, who checks it, and what it does not prove

The claim is narrow and specific: *the CycloneDX inventory in `predicate` is the component list of the image whose manifest hashes to this digest.* Once Cosign signs it and the signature lands in a transparency log, the checker is anyone downstream of the image — an admission controller refusing unattested images, a CI job gating promotion, a customer's compliance process asking for the SBOM of what they actually run, or a responder asking "were we shipping the affected version of `tar`?" six months from now.

What it does not prove is almost everything else. It does not say the image is free of vulnerabilities — the predicate is an inventory, and the same inventory contains 14 Critical findings. It does not say the SBOM is *complete* or *correct*; it says Syft produced this list, and anything Syft failed to catalogue is silently absent. It does not say the image was built from trusted source, by a trusted pipeline, or that its contents are safe to run — those are separate predicates (SLSA provenance, which is Lab 8's other attestation). And it carries no authority on its own: unsigned, this file is a JSON document anyone could have written in the shell one-liner above. The signature is what turns the claim into evidence, and the signature is only worth as much as the key that made it.
