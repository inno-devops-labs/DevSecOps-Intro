# Lab 4 — SBOM Generation and Software Composition Analysis

**Environment:**
- Windows 11 host, Docker Desktop 29.7.2 with the containerd image store, VM memory 2 GiB.
- `syft 1.52.0`, `grype 0.119.0` (vulnerability DB schema v6.1.9, built 2026-09-20T06:27:54Z), `trivy 0.74.0` (vulnerability DB v2, downloaded 2026-09-20), `jq 1.8.2`.
- Image `bkimminich/juice-shop:v20.0.0`, digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

**One deviation from the lab commands.** `syft bkimminich/juice-shop:v20.0.0` does not run on Windows with this version. Every image provider fails the same way:

```text
failed to fetch layer 1: unable to place layer cache
path="C:\\Users\\...\\Temp\\stereoscope-3966662110\\docker-tarball-image-2735322874/1-sha256:621c35e7..."
: The filename, directory name, or volume label syntax is incorrect.
```

Syft's image backend names each cached layer `<index>-sha256:<digest>`, and `:` is not a legal character in an NTFS filename. `docker save` first, `--from oci-archive`, `--from docker-archive`, `--from oci-registry` — all reach the same code path and fail. The fix was to run Syft where the filesystem allows colons, in a Linux container talking to the same Docker daemon:

```bash
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock \
  anchore/syft:latest bkimminich/juice-shop:v20.0.0 -o cyclonedx-json \
  > labs/lab4/juice-shop.cdx.json
```

Everything else — Grype, Trivy, `jq` — ran natively on the host. Grype never touches the image anyway: it reads the SBOM, which is the point of Task 1.

## Task 1

### 4.1 Two SBOMs, one image

```bash
jq '.components | length' labs/lab4/juice-shop.cdx.json
jq '.packages   | length' labs/lab4/juice-shop.spdx.json
jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
```

| File | Count | Format version |
|---|---|---|
| `juice-shop.cdx.json` — `.components` | **3069** | CycloneDX `specVersion` **1.7** |
| `juice-shop.spdx.json` — `.packages` | **909** | `spdxVersion` SPDX-2.3 |

The two numbers describe the same inventory filed two different ways. CycloneDX has one flat `components` array and puts everything in it; breaking it down by `type` gives 907 `library`, 2160 `file`, 1 `operating-system` and 1 `application` — 3069 in total. SPDX splits those across two arrays: `.packages` holds the 907 libraries plus the OS and the image itself (909), while the 2167 file entries live in a separate `.files` array that the lab's `jq` never counts.

```bash
jq -r '[.components[].type] | group_by(.) | map("\(.[0]): \(length)") | .[]' labs/lab4/juice-shop.cdx.json
jq '(.files // []) | length' labs/lab4/juice-shop.spdx.json
```

```text
application: 1
file: 2160
library: 907
operating-system: 1
2167
```

So the gap is not disagreement about what is in the image, it is a schema difference: 909 + 2167 ≈ 3069 + a handful of file entries CycloneDX folds together. The part that actually matters for scanning — packages with a `purl` — is the same on both sides: 894 npm, 13 deb, 1 generic.

### 4.2 Scanning the SBOM, not the image

```bash
grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/grype-from-sbom.json
```

| Severity | Count |
|---|---|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total matches** | **183** |

183 matches across **157 distinct advisories** — the same advisory is counted once per affected package, and 26 of them hit more than one. By ecosystem: 118 npm, 50 deb, 15 against the `node` binary itself.

The run took 6.4 s and never opened the image. That is the argument for the split: the inventory is a 1.8 MB file that can be re-scanned against tomorrow's database without pulling 568 MB again.

### 4.3 Ranked findings

Sorting on the severity string alphabetically puts `Low` above `Medium`, so the ranking uses an explicit order array:

```text
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

**Nine of the ten have a fix version.** The exception is `GHSA-mp2f-45pm-3cg9` against `decompress@4.2.1`, where the `fix` column is empty.

Given only those two columns, the first thing I would do is collapse the list before touching anything: ten rows are seven advisories, because `tar` appears three times at three different versions and `jsonwebtoken` twice. One pin of `tar` to 7.5.19 clears three rows, and the two `libssl3t64` CVEs are both fixed by the same base-image rebuild — so I would rebuild on a current Debian base and bump `tar`, `jsonwebtoken`, `lodash` and `crypto-js`, which is four actions for nine of the ten rows. The fixless `decompress` finding cannot be closed by patching, so it does not belong in the same queue at all: it goes to the track where you check whether the code path is reachable, look for a replacement package, or accept it in writing. Severity tells me what to look at; the fix column tells me which of those I can actually finish today, and doing the finishable ones first is what shrinks the list.

## Task 2

### 4.4 Trivy on the image

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL --format json --output labs/lab4/trivy.json
```

```text
INFO  Detected OS  family="debian" version="13.4"
INFO  [debian] Detecting vulnerabilities...  os_version="13" pkg_num=13
INFO  Number of language-specific files  num=1
INFO  [node-pkg] Detecting vulnerabilities...
```

| Severity | Grype | Trivy | Δ (Grype − Trivy) |
|---|---:|---:|---:|
| Critical | 14 | 10 | **+4** |
| High | 85 | 64 | **+21** |
| Medium | 65 | 68 | **−3** |
| Low | 12 | 31 | **−19** |
| Negligible | 7 | — | **+7** |
| **Total findings** | **183** | **173** | **+10** |
| Distinct advisory IDs | 157 | 146 | +11 |

Trivy has no `Negligible` bucket: Debian's `unimportant` urgency lands in `LOW`, which is most of why its Low column is 31 against Grype's 12. The per-ecosystem split explains the rest — Debian packages: 50 findings in both tools, exactly. npm: 118 (Grype) against 123 (Trivy). Binaries: 15 against 0.

### 4.5 Where they disagree

The lab's `comm` gives a frightening answer — 104 identifiers only in Grype, 93 only in Trivy, out of ~150 each. Almost all of that is bookkeeping, not disagreement: Grype reports npm advisories under their GHSA id (92 of its 157 ids are `GHSA-…`) while Trivy reports the same advisories under the CVE (140 of its 146 are `CVE-…`). Grype's JSON carries the mapping in `relatedVulnerabilities`, so expanding every match into its full identifier cluster before comparing is a fairer test:

```text
naive comm:              only-grype 104   only-trivy 93    shared 53
after alias expansion:   only-grype  15   only-trivy  4    shared 142
```

**Found by Grype, missed by Trivy — `CVE-2026-48617`, High, `node@24.15.0`, fixed in 24.17.0.** This is not a one-off: all 15 remaining Grype-only findings are against that same artifact, the Node.js runtime binary, which Syft catalogues with its binary classifier and records in the SBOM as `node@24.15.0` of type `binary`. Trivy's language analyzer is a package-manifest parser — its `Results` contain exactly two scanners' worth of data, `debian` OS packages and `node-pkg` from `package.json` files — and it never fingerprints the interpreter executing all of that code. This is the "ecosystem one tool does not parse" case, and it is the more serious of the two directions: fifteen runtime CVEs, four of them High, invisible to the all-in-one scanner.

**Found by Trivy, missed by Grype — `NSWG-ECO-154`, Medium, `sanitize-html@1.4.2`, fixed in ≥1.11.4.** Trivy's `DataSource` for it is "Node.js Ecosystem Security Working Group", the pre-GHSA npm advisory database; Grype's npm matches all come from a single namespace, `github:language:javascript`. So an advisory that never received a GHSA or CVE number has no identifier Grype can print. Two of the other three Trivy-only ids are the same story (`NSWG-ECO-17` on `jsonwebtoken`, `NSWG-ECO-428` on `base64url`), and to be fair to Grype: it does report other advisories against those same packages, so the package is not unwatched — the *identifier* is missing, which is precisely why comparing tools by id is so slippery.

The fourth Trivy-only id is the interesting one: **`CVE-2025-57349`, Low, `messageformat@2.3.0`**, sourced from the GitHub Security Advisory database — the same source Grype uses, for a package that is in the SBOM at that exact version. Grype reports nothing at all for `messageformat`. With both databases built the same day, the best explanation left is a matching rule rather than a data gap: the advisory's fixed version is the pre-release `3.0.0-beta.0`, and pre-release boundaries in semver ranges are exactly where two implementations diverge quietly.

### When is the extra moving part worth it

The decoupled route pays off whenever the inventory has to outlive the scan. The SBOM is a small, stable artifact produced once at build time by something that actually saw the build, and everything downstream consumes that file: Grype re-scanned it in 6.4 s with no daemon, no registry pull and no credentials, and **Lab 8 signs this very `juice-shop.cdx.json` as a Cosign attestation bound to the image digest**, so the inventory becomes evidence a deploy-time policy can verify instead of a report someone pasted into a ticket. That also makes the scanner replaceable — a second opinion costs one more scan of the same file, which is the only reason the comparison above was cheap to run. The single binary wins when the answer is needed now and only now: a developer's laptop, a PR gate, a "did this base image get worse overnight" check, where Trivy's one command pulls, unpacks, detects the OS and scans without anyone having to store or version a JSON file. The honest read of this lab is that they are not competitors — Trivy found npm advisories Grype does not carry, Grype found fifteen runtime CVEs Trivy cannot see, and the SBOM is what let me prove that rather than guess it.

## Bonus

### Building the statement

Neither type string is guessable, so both came out of Cosign's source rather than my memory. `pkg/cosign/attestation/attestation.go` builds the CycloneDX statement with `Type: in_toto.StatementInTotoV01` and `PredicateType: in_toto.PredicateCycloneDX`, and those constants are defined in `in-toto-golang/in_toto/attestations.go`:

```go
StatementInTotoV01 = "https://in-toto.io/Statement/v0.1"
PredicateCycloneDX = "https://cyclonedx.org/bom"
```

The statement type is `v0.1`, not `v1`, and the CycloneDX predicate type carries no version at all — the SBOM's own `specVersion` field is where the version lives.

```bash
DIGEST="$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | cut -d@ -f2 | cut -d: -f2)"

jq -n --arg name "bkimminich/juice-shop:v20.0.0" --arg digest "$DIGEST" \
   --slurpfile sbom labs/lab4/juice-shop.cdx.json \
   '{_type: "https://in-toto.io/Statement/v0.1",
     subject: [{name: $name, digest: {sha256: $digest}}],
     predicateType: "https://cyclonedx.org/bom",
     predicate: $sbom[0]}' > labs/lab4/juice-shop-attestation.json
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
    "serialNumber": "urn:uuid:5ee77ca0-3e0f-4e8b-9231-2be739434f30",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-20T16:16:05Z",
      "tools": {
```

The predicate is the whole SBOM — 3069 components, `specVersion` 1.7 — which is why the file is 3.0 MB. (Cosign writes the repository without the tag in `subject[0].name`; I kept the full reference I scanned, as the task asks.)

### The digest

```text
sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

The tag is a mutable pointer — `v20.0.0` can be re-pushed tomorrow at different content, and then a signature over the string "v20.0.0" would vouch for an image nobody has inspected; the digest *is* the content, so a statement about it cannot be transferred to anything else.

### What this file claims

It claims one thing: whoever signs it asserts that this CycloneDX inventory describes the image with that digest. The checker is machinery, not a person — in Lab 8, `cosign verify-attestation` against the signer's identity, and in a real cluster an admission controller that refuses images whose SBOM attestation is missing, unsigned, or signed by the wrong key. What it does not prove is almost everything else: not that the SBOM is complete or correct (Syft can only list what it recognised — and Task 2 showed that two tools looking at the same image do not even agree on what is in it), not that the image is free of vulnerabilities, not that anyone scanned it, and not that the image is safe to run. Unsigned, as it sits in this PR, it proves nothing at all — it is a claim waiting for a signature, which is exactly what Lab 8 adds.

### A note on what is committed

The Submit block in the lab commits both SBOMs; the pitfalls list says not to commit the SPDX one. I followed the Submit block, since the SPDX file is the evidence behind the 4.1 answer, and left the scan outputs (`grype-from-sbom.json`, `grype-from-sbom.txt`, `trivy.json`) out of the PR as instructed — every number above is reproducible from the two SBOMs plus the commands shown.
