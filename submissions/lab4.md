# Lab 4 — SBOM Generation and Software Composition Analysis

Tooling: syft 1.52.0, grype 0.119.0, trivy 0.74.0, jq 1.6, on macOS 15.3.1 (arm64).
Image: `bkimminich/juice-shop:v20.0.0` @ `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

## Task 1

> **Note on what is committed.** `labs/lab4.md` contradicts itself about the SPDX file: the Submit
> block runs `git add labs/lab4/juice-shop.spdx.json` and states "Both SBOMs are committed ... the SPDX
> one is your evidence for the format-comparison answer", while Common pitfalls says "The SPDX file is
> larger than the CycloneDX one and Lab 8 does not use it. Do not commit it", and the Deliverable line
> at the top lists only `juice-shop.cdx.json`. I followed the Submit block and committed both, since it
> is the operative command list and gives an explicit reason, and the evidence for §4.1 is more useful
> in the PR than out of it. The scan outputs (`grype-from-sbom.*`, `trivy.json`) are deliberately left
> out, as the lab instructs — their numbers are pasted below instead.
>
> **These SBOMs collide with Lab 3's own hook.** `.pre-commit-config.yaml` from `feature/lab3` sets
> `check-added-large-files` to `--maxkb=1024`, and the CycloneDX SBOM is 1790 KB. Staging it on a branch
> that carries that config fails with `bigtest-copy.json (1790 KB) exceeds 1024 KB` — I tested it rather
> than assuming, and the first version of this test was wrong: running the hook against the *already
> committed* files passes, because `check-added-large-files` only inspects files being newly added to the
> index. So the conflict is real but only bites once, at the commit that introduces the file. When these
> branches merge, Lab 8 will need `juice-shop.cdx.json` tracked, so the limit has to be raised or
> `labs/lab4/*.json` excluded — a reminder that a size guard tuned for source code is wrong for a repo
> whose deliverables are machine-generated inventories.


### 4.1 Two SBOMs of one image

```console
$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3068
$ jq '.packages   | length' labs/lab4/juice-shop.spdx.json
909
$ jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
1.7
```

**Why the two formats disagree.** They do not actually disagree about the software — they disagree
about what belongs in a list. Syft catalogued the same 907 libraries either way; CycloneDX flattens
*everything* into one `components` array, so that array also carries 2159 `file` entries (individual
files with SHA-1/SHA-256 hashes), one `operating-system` and one `application` root, while SPDX keeps
files in a **separate top-level `files` array** (2166 entries) and reserves `packages` for things that
are actually packages. Break the CycloneDX number down and the gap disappears:

```console
$ jq -r '[.components[].type] | group_by(.) | map("\(.[0]): \(length)") | .[]' labs/lab4/juice-shop.cdx.json
application: 1
file: 2159
library: 907
operating-system: 1
```

907 libraries + 1 OS + 1 root = 909, which is exactly the SPDX package count. So "3068 vs 909" is a
difference in document structure, not in what was found. A second, smaller effect hides inside both
numbers: only **837** of those 907 library components have distinct purls, because the same package
shows up at several paths or layers and each occurrence is its own component. Counting components is
not counting dependencies, in either format.

### 4.2–4.3 Scanning the SBOM

```console
$ grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
$ jq '.matches | length' labs/lab4/grype-from-sbom.json
183
```

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 0 |
| **Total** | **183** |

Top ten, ranked with the explicit order array (sorting the severity string directly would put `Low`
above `Medium`):

| # | Severity | ID | Package@Version | Fix |
|---|---|---|---|---|
| 1 | Critical | `GHSA-c7hr-j4mj-j2w6` | jsonwebtoken@0.1.0 | 4.2.2 |
| 2 | Critical | `GHSA-c7hr-j4mj-j2w6` | jsonwebtoken@0.4.0 | 4.2.2 |
| 3 | Critical | `GHSA-jf85-cpcp-j695` | lodash@2.4.2 | 4.17.12 |
| 4 | Critical | `CVE-2026-63073` | libssl3t64@3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| 5 | Critical | `GHSA-mp2f-45pm-3cg9` | decompress@4.2.1 | **none** |
| 6 | Critical | `GHSA-xwcq-pm8m-c4vf` | crypto-js@3.3.0 | 4.2.0 |
| 7 | Critical | `CVE-2026-34182` | libssl3t64@3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| 8 | Critical | `GHSA-23hp-3jrh-7fpw` | tar@4.4.19 | 7.5.19 |
| 9 | Critical | `GHSA-23hp-3jrh-7fpw` | tar@6.2.1 | 7.5.19 |
| 10 | Critical | `GHSA-23hp-3jrh-7fpw` | tar@7.5.15 | 7.5.19 |

**Nine of the ten have a fix.** The exception is `GHSA-mp2f-45pm-3cg9` on `decompress@4.2.1`, where
Grype reports an empty `fix.versions` array. Across all 183 findings the split is 156 fixable, 27 not.

**What I would do first with only those two columns.** Sort by "Critical **and** fixable" and start
there, because that intersection is the only place where maximum severity meets a one-line remedy —
and read the rows as *advisories*, not as ten separate problems. The ten rows above are really seven
distinct advisories: `GHSA-23hp-3jrh-7fpw` accounts for three of them (three copies of `tar` at
different versions, all fixed by 7.5.19) and `GHSA-c7hr-j4mj-j2w6` for two. So the first action is a
single `tar` bump that clears three rows at once, then `jsonwebtoken` for two more; five of the ten
rows fall to two upgrades. The `libssl3t64` pair is one `apt-get upgrade` to 3.5.7, which supersedes
the 3.5.6 fix for the other CVE. `decompress` is the only one of the ten that needs real thought,
and the fix column is precisely what tells me to spend that thought last rather than first — a
Critical with no fix cannot be closed by triage, only by removing the dependency, pinning a fork, or
accepting it with a compensating control, all of which are decisions rather than commands.

## Task 2

### 4.4 Trivy on the image

```console
$ jq '[.Results[].Vulnerabilities[]?] | length' labs/lab4/trivy.json
173
```

| Severity | Grype (SBOM) | Trivy (image) | Δ (G−T) |
|---|---:|---:|---:|
| Critical | 14 | 10 | **+4** |
| High | 85 | 64 | **+21** |
| Medium | 65 | 68 | −3 |
| Low | 12 | 31 | **−19** |
| Negligible | 7 | 0 | +7 |
| **Total findings** | **183** | **173** | **+10** |
| *Distinct identifiers* | *157* | *146* | *+11* |

Trivy has no `Negligible` band, so Debian's "unimportant" issues land in its `LOW` bucket — which is
most of the +7/−19 swing at the bottom of the table rather than a real disagreement about what is in
the image.

### 4.5 Where they disagree — and mostly do not

The naive comparison the lab suggests makes the two tools look wildly inconsistent:

```console
$ comm -23 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l    # grype-only
104
$ comm -13 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l    # trivy-only
93
$ comm -12 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l    # shared
53
```

53 shared out of ~150 each would be alarming. It is an artifact of identifier namespaces: Grype names
npm advisories by **GHSA** (92 of its 157 IDs) and Trivy names the same advisories by **CVE** (143 of
its 146). Grype carries the CVE alias in `relatedVulnerabilities`; expanding those before comparing
changes the picture completely:

```console
$ jq -r '[.matches[] | (.vulnerability.id, (.relatedVulnerabilities[]?.id))] | unique[]' \
    labs/lab4/grype-from-sbom.json > /tmp/grype-ids-expanded.txt
$ comm -12 /tmp/grype-ids-expanded.txt /tmp/trivy-ids.txt | wc -l
142
$ comm -13 /tmp/grype-ids-expanded.txt /tmp/trivy-ids.txt
CVE-2025-57349
NSWG-ECO-154
NSWG-ECO-17
NSWG-ECO-428
```

**142 of Trivy's 146 identifiers are also found by Grype.** Normalising the other direction (a Grype
match counts as shared if its ID *or any alias* is in Trivy's set) leaves exactly **15** Grype rows
with no Trivy counterpart — and all 15 are on the same artifact. The real divergence is four findings
one way and fifteen the other, not ~100 each way.

**Found by Grype, missed by Trivy: `CVE-2026-48617` on `node@24.15.0`.**
Cause: **an artifact class one tool does not parse.** Syft's binary classifier catalogued the Node.js
*runtime binary* as a component (`"type": "binary"`), so Grype matched Node runtime CVEs against
version 24.15.0. Trivy's scan produced only two vulnerability targets —
`bkimminich/juice-shop:v20.0.0 (debian 13.4)` with `Class: os-pkgs` and `Node.js` with
`Class: lang-pkgs, Type: node-pkg` — and `node-pkg` means *packages declared in `package.json`*, i.e.
the dependencies, not the interpreter executing them. The Node binary is not in a Debian package here
(it is baked into the image), so it falls between Trivy's two analyzers and all 15 of its CVEs are
invisible. This is the whole Grype-only set.

**Found by Trivy, missed by Grype: `NSWG-ECO-17` on `jsonwebtoken@0.1.0` and `0.4.0` (HIGH).**
Cause: **a different advisory source**, and Trivy says so itself —
`.DataSource.Name` on that finding reads *"Node.js Ecosystem Security Working Group"*. Trivy still
ships the legacy nodejs-security-wg advisory database alongside GHSA; Grype's npm matcher uses GitHub
Security Advisories, and an `NSWG-ECO-*` identifier with no CVE or GHSA equivalent has nothing for it
to match on. Two of the other three exclusives (`NSWG-ECO-154` on `sanitize-html`, `NSWG-ECO-428` on
`base64url`) have the same cause; only `CVE-2025-57349` on `messageformat@2.3.0` comes from a source
both tools carry, which makes it a database-freshness difference rather than a structural one.

A worked example of the namespace artifact, so the claim is checkable: `CVE-2019-10744` appears in the
naive "Trivy-only" list, but Grype found the identical issue on the identical package —
`GHSA-jf85-cpcp-j695`, `lodash@2.4.2`, Critical — carrying `CVE-2019-10744` as an alias. It is row 3
of my top ten.

### Decoupled inventory versus single binary

The single binary wins whenever the question is "is this image safe to ship right now" and the answer
is needed inside a pipeline: `trivy image` is one command, needs no intermediate artifact, and scans
the layers directly, which is exactly why it caught the `NSWG-ECO-*` advisories that my SBOM-mediated
path missed. The decoupled path earns its extra moving part when the *inventory itself* is the
deliverable rather than a means to a scan — and that is the case here, because **Lab 8 signs
`juice-shop.cdx.json` as a CycloneDX attestation attached to the image digest**, so the SBOM becomes a
distributable, verifiable claim about what is inside the artifact rather than a scanner's scratch file.
Once that inventory exists and is signed, a CVE published next month is answered by re-running Grype
against the file in seconds, with no registry pull and no rebuild, and the same file feeds Lab 10's
findings import. The honest caveat from 4.5 is that the SBOM is a lossy boundary: everything downstream
inherits what Syft did and did not catalogue, so a scan of the inventory is only ever as good as the
inventory — which is an argument for doing both, not for choosing.

## Bonus

### The command

```bash
DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | cut -d'@' -f2)

jq -n \
  --arg name "bkimminich/juice-shop:v20.0.0" \
  --arg digest "${DIGEST#sha256:}" \
  --slurpfile bom labs/lab4/juice-shop.cdx.json \
  '{_type: "https://in-toto.io/Statement/v0.1",
    subject: [{name: $name, digest: {sha256: $digest}}],
    predicateType: "https://cyclonedx.org/bom",
    predicate: $bom[0]}' > labs/lab4/juice-shop-attestation.json
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
    "serialNumber": "urn:uuid:98ca7e78-5bbb-4ce1-8bc1-7de7ff2f6ad8",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-21T12:13:02+03:00",
      "tools": {
```

**The two type strings are read, not guessed.** Both come from Cosign's source rather than from
memory, since the lab warns that the obvious guesses are wrong:

- `pkg/cosign/attestation/attestation.go` builds the CycloneDX statement with
  `Type: in_toto.StatementInTotoV01, PredicateType: in_toto.PredicateCycloneDX`, and
  `cmd/cosign/cli/options/predicate.go` maps the `--type cyclonedx` flag to that same
  `in_toto.PredicateCycloneDX`.
- `in-toto-golang/in_toto/attestations.go` defines
  `StatementInTotoV01 = "https://in-toto.io/Statement/v0.1"` and
  `PredicateCycloneDX = "https://cyclonedx.org/bom"`.

So the statement type is **v0.1**, not `v1` as the name would suggest, and the CycloneDX predicate type
is **unversioned** — it carries no `/v1` suffix even though the SBOM inside it is specVersion 1.7.
Guessing `https://in-toto.io/Statement/v1` or `https://cyclonedx.org/bom/v1.7` would produce a file
that looks right and that no verifier would accept.

### The digest, and why not the tag

Signed over `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

A tag is a mutable pointer: `v20.0.0` is a label in a registry that whoever controls the repository can
re-point at different bytes at any time, so a statement about "the image tagged v20.0.0" is a statement
about a name, and the name can be made to mean something else after I sign it. The digest *is* the
content — it is the hash of the image manifest — so binding the SBOM to the digest makes the claim
unforgeable in the only way that matters: if a single byte of the image changes, the digest changes,
and this attestation simply no longer refers to it rather than silently vouching for it.

### What this file claims, who checks it, and what it does not prove

The claim is narrowly scoped and worth stating precisely: *at the time this was generated, Syft
catalogued these 3068 components inside the image with this exact digest.* The subject binds it to
specific bytes and the predicate is the inventory; there is no assertion about vulnerabilities,
licences, build provenance or fitness for anything. The consumer is whoever is about to run the image
and needs to answer a supply-chain question without trusting me — a deploy-time admission controller,
a Lab 8 `cosign verify-attestation` in CI, or an incident responder asking "did we ship the affected
version of `tar`" after a CVE drops, which is answerable from this file alone in seconds.

What it does **not** prove is most of what people want it to. Unsigned, as written here, it proves
nothing at all: any field can be edited, and it is only evidence once Lab 8 wraps it in a DSSE envelope
and signs it, at which point it proves *someone holding that key said this* — not that the statement is
true. Even signed and verified, it does not prove the inventory is **complete**: it inherits every
blind spot Syft has, and 4.5 showed those blind spots are real in both directions, since Trivy's
`NSWG-ECO-*` findings came from advisories this pipeline never sees. It does not prove the image is
free of vulnerabilities, that the components are the ones the source tree intended, or that the image
was built from any particular commit — that last one is SLSA provenance, a different predicate type
entirely. It is an inventory with a tamper-evident label, and nothing more.
