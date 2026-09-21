# Lab 4 — Submission

SBOM generation and software composition analysis on `bkimminich/juice-shop:v20.0.0`.

## Setup

```console
$ syft version
Version: 1.52.0
$ grype version
Version: 0.119.0
$ trivy --version
Version: 0.74.0
$ jq --version
jq-1.7.1
```

Grype's vulnerability DB for this run: schema `v6.1.9`, built `2026-09-20T06:27:54Z`. Worth recording, because
the same SBOM scanned next week gives different numbers and the DB version is the only thing that explains why.

## Task 1

### 4.1 Two SBOMs from one image

```console
$ syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
$ syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json

$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3069
$ jq '.packages   | length' labs/lab4/juice-shop.spdx.json
909
$ jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
1.7
```

| | CycloneDX | SPDX |
|---|---:|---:|
| count queried | `.components` → **3069** | `.packages` → **909** |
| spec version | **1.7** | SPDX-2.3 |
| file size | 1.8 MB | 3.0 MB |

### Why the two numbers differ

They are counting different things. Splitting the CycloneDX array by type shows it:

```console
$ jq -r '[.components[].type] | group_by(.) | map("\(.[0]): \(length)") | .[]' labs/lab4/juice-shop.cdx.json
application: 1
file: 2160
library: 907
operating-system: 1
```

**907 library + 1 operating-system + 1 application = 909, exactly the SPDX package count.** CycloneDX puts
packages *and* individual files in one `components` array; SPDX keeps them in two arrays, `packages` (909) and
`files` (2167). So `.components | length` compares a mixed list against half of the other format. Both files
describe the same ~909 packages — the 3069-vs-909 gap was my question being wrong, not the tools disagreeing.

The file arrays differ slightly too: 2160 in CycloneDX, 2167 in SPDX. All seven extras are SPDX-only:

```
juice-shop/node_modules/iltorb/build/Release/iltorb.node
juice-shop/node_modules/iltorb/build/Release/obj.target/iltorb.node
juice-shop/node_modules/iltorb/build/bindings/iltorb.node
juice-shop/node_modules/libxmljs2/build/Release/xmljs.node
juice-shop/node_modules/portscanner/package.json
juice-shop/node_modules/sqlite3/build/Release/node_sqlite3.node
juice-shop/node_modules/toposort-class/package.json
```

Each of the seven has only a `SHA1` checksum, where files in both formats have `SHA1` and `SHA256`. SPDX needs
a SHA1 on every file it lists, so it keeps them; syft's CycloneDX output drops them. Five are compiled `.node`
native addons — exactly what a licence audit cares about, and exactly what you lose by trusting one count.

### 4.2 Scanning the SBOM instead of the image

```console
$ grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
$ grype sbom:labs/lab4/juice-shop.cdx.json -o table | tee labs/lab4/grype-from-sbom.txt
NAME          INSTALLED  FIXED IN   TYPE  VULNERABILITY        SEVERITY  EPSS          RISK
lodash        2.4.2      4.17.21    npm   GHSA-35jh-r3h4-6jhm  High      21.3% (97th)  15.7
moment        2.0.0      2.29.2     npm   GHSA-8hfj-j24r-96c4  High      13.9% (96th)  10.4
jsonwebtoken  0.1.0      4.2.2      npm   GHSA-c7hr-j4mj-j2w6  Critical  8.7% (94th)   7.8
...
```

| Severity | Count |
|---|---:|
| Critical | 14 |
| High | 85 |
| Medium | 65 |
| Low | 12 |
| Negligible | 7 |
| **Total matches** | **183** |
| *distinct advisory ids* | *157* |

183 matches but only 157 distinct ids, because one advisory can hit several packages at once — the three `tar`
rows below are one advisory counted three times.

### 4.3 Top ten, ranked properly

Sorting the severity string alphabetically would put `Low` above `Medium`, so the order comes from an explicit
list:

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

All ten are Critical and **nine have a fix**. The one that does not is `GHSA-mp2f-45pm-3cg9` on
`decompress@4.2.1`.

### What I would do first

Those two columns split the work into "a bump fixes this" and "a bump cannot". I would take the nine fixable
Criticals first, ordered by how many findings one bump clears. `tar` is the best deal: three rows are one
advisory against three copies (4.4.19, 6.2.1, 7.5.15, all transitive) and `7.5.19` closes all three.
`jsonwebtoken` is two rows for one bump to 4.2.2, and both `libssl3t64` CVEs are one base-image update.
Six of ten findings gone in three changes.

`decompress@4.2.1` goes last despite being Critical, because urgency does not create a patch that does not
exist. Its empty fix column turns the question into "drop this dependency or work around it" — a design call
that should not block nine bumps that are ready today. Severity says what matters, the fix column says what is
actionable, and sorting on severity alone would have put the one unfixable finding first.

## Task 2

### 4.4 Trivy against the image

```console
$ trivy image bkimminich/juice-shop:v20.0.0 \
    --severity LOW,MEDIUM,HIGH,CRITICAL \
    --format json --output labs/lab4/trivy.json
INFO  Detected OS  family="debian" version="13.4"
INFO  [debian] Detecting vulnerabilities...  os_version="13" pkg_num=13
INFO  Number of language-specific files  num=1
INFO  [node-pkg] Detecting vulnerabilities...
```

### Side by side

Trivy prints severities in upper case and Grype in title case, so I normalised them first — joining them raw
gives a table full of zeros.

| Severity | Grype | Trivy | Delta |
|---|---:|---:|---:|
| Critical | 14 | 10 | **+4** |
| High | 85 | 64 | **+21** |
| Medium | 65 | 68 | **-3** |
| Low | 12 | 31 | **-19** |
| Negligible | 7 | — | **+7** |
| **Total findings** | **183** | **173** | **+10** |
| *distinct ids* | *157* | *146* | *+11* |

Trivy has no `Negligible` bucket, and I passed `--severity LOW,MEDIUM,HIGH,CRITICAL`, so anything Trivy rated
`UNKNOWN` was filtered out before it reached the file — part of that column is my flag, not a disagreement. The
other severity gaps are partly a rating difference: each tool takes CVSS from whichever feed it trusts, so the
same CVE can land in a different row.

Where the totals come from is more interesting than the totals:

| Source | Grype | Trivy |
|---|---:|---:|
| Debian OS packages | 50 | 50 |
| npm packages | 118 | 123 |
| binary (Node.js runtime) | 15 | 0 |

The Debian side matches exactly. The whole net gap is `+15` from a component Trivy never catalogued, minus `5`
npm findings Trivy has and Grype does not.

### 4.5 Where they disagree

The raw id diff makes the gap look far worse than it is:

```console
$ comm -23 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l   # grype only
104
$ comm -13 /tmp/grype-ids.txt /tmp/trivy-ids.txt | wc -l   # trivy only
93
```

Grype reports 92 `GHSA-` and 65 `CVE-` ids; Trivy reports 3 `GHSA-` and 140 `CVE-`. They are mostly naming the
same advisories from different namespaces. Expanding each Grype match with its `relatedVulnerabilities` aliases
and comparing again:

```
grype distinct ids                 : 157
grype ids + aliases                : 246
trivy-only, raw                    : 93
trivy-only, after alias expansion  : 4
-> 89 of Trivy's 93 "unique" findings are CVE names for GHSAs Grype already reported
```

**Grype found, Trivy missed: `CVE-2026-48617` on `node@24.15.0`** — the Node.js runtime itself, not an npm
package. This is the ecosystem case. Syft's `binary-classifier-cataloger` spotted `/nodejs/bin/node` and
catalogued it as `pkg:generic/node@24.15.0`, giving Grype something to match — 15 findings in total. Trivy
reported only two targets, `debian` OS packages and `node-pkg` language packages, and zero findings with
`PkgName` `node`: it read `node_modules` and the Debian package database but never treated the interpreter
shipped in the image as an inventory item. Fourteen more CVEs against that runtime are invisible for the same
reason.

**Trivy found, Grype missed: `NSWG-ECO-17` on `jsonwebtoken@0.1.0` and `@0.4.0`** — the advisory-source case.
`NSWG-ECO-*` ids come from the Node Security Working Group set, a feed Trivy carries and Grype's database does
not, so Grype has no id it could even emit. The other three are the same shape: `NSWG-ECO-154` on
`sanitize-html@1.4.2`, `NSWG-ECO-428` on `base64url@0.0.6`, and `CVE-2025-57349` on `messageformat@2.3.0`.
Three of four are one feed Grype does not subscribe to — a much smaller gap than the raw 93.

### Decoupled inventory versus one binary

The split is worth it when the inventory has to outlive the scan. Once `juice-shop.cdx.json` exists, other
things can use it: re-running Grype against the file answers "are we affected" in about a second with no
registry pull, which is what you want at 2am when an advisory lands. It also answers licence and provenance
questions a vulnerability scanner never touches. **Lab 8 takes this exact file and attaches it to the image as a
signed Cosign attestation** — the bonus below builds that envelope by hand — and that only works because the
inventory is a separate file instead of console output. An SBOM you can sign is one a downstream team can check
against the digest they actually pulled.

One binary wins when the output is a pass/fail gate nobody reads twice. A PR check that blocks on new Criticals
wants one tool, one DB and one exit code, not two pipeline stages, and Trivy covers the Debian layer,
`node_modules` and secrets in a single pass. But the numbers say this is not really either/or: 50 identical
Debian findings, `node` runtime CVEs only Grype saw, `NSWG-ECO` advisories only Trivy saw. Running one tool
means accepting a known blind spot; the question is which one you can live with.

## Bonus

### The command

```console
$ DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' \
           | cut -d@ -f2 | sed 's/^sha256://')

$ jq -n --arg name "bkimminich/juice-shop:v20.0.0" \
        --arg digest "$DIGEST" \
        --slurpfile bom labs/lab4/juice-shop.cdx.json \
   '{_type: "https://in-toto.io/Statement/v0.1",
     subject: [{name: $name, digest: {sha256: $digest}}],
     predicateType: "https://cyclonedx.org/bom",
     predicate: $bom[0]}' > labs/lab4/juice-shop-attestation.json
```

`--slurpfile` reads the whole SBOM into `$bom` as a one-element array, so `$bom[0]` drops the document in
unchanged. `--arg` keeps the digest a string instead of letting jq interpret it.

### First 20 lines

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
    "serialNumber": "urn:uuid:77142b11-7931-42d5-8571-f2c3e19fe854",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-21T09:38:49+03:00",
      "tools": {
```

I did not guess the two type strings. Cosign's `generateCycloneDXStatement` uses `in_toto.StatementInTotoV01`
and `in_toto.PredicateCycloneDX`, and its own tests pin the literal values:

```json
{"_type":"https://in-toto.io/Statement/v0.1", ... ,"predicateType":"https://cyclonedx.org/bom", ...}
```

So the statement type is `v0.1`, not the spec's current `v1`, and the CycloneDX predicate type has no version
at all — which means the predicate's own `specVersion: 1.7` is the only record of which schema was used.

### The digest, and why not the tag

```console
$ docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

A tag is just a pointer that can move: `v20.0.0` could be repushed tomorrow with different bytes, leaving this
attestation making a true-looking claim about an image that no longer exists. The digest *is* the content, so
binding to `sha256:fd58bdc…` means the claim either matches the bytes someone pulled or clearly does not.

### What it claims, who checks it, what it does not prove

It claims the CycloneDX inventory in `predicate` is the inventory of the image whose manifest digests to
`sha256:fd58bdc…` — a claim about those exact bytes, which stays checkable after the tag moves. Whoever is about
to run the image and did not build it is the one who checks: a deploy-time admission controller, a downstream
team, an auditor asking what is inside what you shipped. In Lab 8 that is `cosign verify-attestation`.

What it does not prove is most things. As written it is an unsigned JSON file anyone could write or edit, so it
says nothing about who made it — the signature Lab 8 adds is what turns "this document says so" into "a key you
trust says so". Even signed, it would not prove the inventory is *correct*: it inherits whatever syft missed,
and this lab already found seven files and a whole Node runtime that one tool or the other failed to catalogue.
It also says nothing about whether those components are vulnerable or properly licensed. It is an inventory
tied to a digest, not a verdict on safety.
