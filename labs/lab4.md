# Lab 4 — SBOM Generation and Software Composition Analysis

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-SBOM%20%2B%20SCA-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Syft%20%2B%20Grype%20%2B%20Trivy-informational)

> **Goal:** Build an inventory of everything inside the Juice Shop image, scan that inventory for known vulnerabilities, and compare the decoupled approach with an all-in-one scanner.
> **Deliverable:** A PR from `feature/lab4` with `submissions/lab4.md` and `labs/lab4/juice-shop.cdx.json`. Submit the PR link via Moodle.
> **Builds on:** the image from Lab 1. **Used by:** Lab 8 signs this SBOM as an attestation, Lab 10 imports these findings.

## Setup

- Docker, with the Juice Shop image from Lab 1 (`docker pull bkimminich/juice-shop:v20.0.0`).
- `syft` 1.x, `grype` 0.x, `trivy` 0.74.x: `brew install syft grype trivy`, or the release pages for [syft](https://github.com/anchore/syft/releases), [grype](https://github.com/anchore/grype/releases), [trivy](https://github.com/aquasecurity/trivy/releases).
- `jq`.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab4
```

```bash
syft version && grype version && trivy --version && jq --version
mkdir -p labs/lab4
```

## Task 1 — SBOM and CVE scan (6 pts)

### 4.1 Generate two SBOMs

<!-- produces: labs/lab4/juice-shop.cdx.json for lab 8 and lab 10 -->
<!-- produces: labs/lab4/grype-from-sbom.json for lab 10 -->
```bash
syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json

jq '.components | length' labs/lab4/juice-shop.cdx.json
jq '.packages   | length' labs/lab4/juice-shop.spdx.json
jq -r '.specVersion' labs/lab4/juice-shop.cdx.json
```

Expect roughly 3000 CycloneDX components and about 900 SPDX packages from the same image, and `specVersion` 1.7. The two numbers differ because the formats count different things; explaining that gap is part of the task.

### 4.2 Scan the SBOM, not the image

```bash
grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
grype sbom:labs/lab4/juice-shop.cdx.json -o table | tee labs/lab4/grype-from-sbom.txt

jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/grype-from-sbom.json
```

Scanning the SBOM rather than the image is the point of the split: one inventory, many scans. When a vulnerability is published next month you re-run Grype against this file and know within seconds whether you shipped the affected package, without pulling anything.

### 4.3 Rank the findings

Severity is a string, so sorting on it directly gives you alphabetical order, where `Low` outranks `Medium`. Rank it:

```bash
jq -r '["Critical","High","Medium","Low","Negligible","Unknown"] as $order
  | [.matches[] | {sev: .vulnerability.severity, id: .vulnerability.id,
                   pkg: .artifact.name, ver: .artifact.version,
                   fix: (.vulnerability.fix.versions // [] | join(","))}]
  | sort_by(.sev as $s | $order | index($s))
  | .[:10][] | "\(.sev)\t\(.id)\t\(.pkg)@\(.ver)\tfix: \(.fix)"' \
  labs/lab4/grype-from-sbom.json
```

**Submit** in `submissions/lab4.md`, section `## Task 1`:

- Component counts for both files, the `specVersion`, and two sentences on why CycloneDX and SPDX disagree about how many things are in one image.
- The severity table with your counts and the total.
- The top ten rows from 4.3.
- How many of those ten have a fix available, and what you would do first given only that column and the severity column.

## Task 2 — Compare with an all-in-one scanner (4 pts)

Optional. Skipping it does not affect later labs.

### 4.4 Scan the image with Trivy

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output labs/lab4/trivy.json

jq '[.Results[].Vulnerabilities[]? | .Severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/trivy.json
```

Trivy prints severities in upper case and Grype in title case, so a naive join of the two tables silently produces zeros.

### 4.5 Find where they disagree

```bash
jq -r '[.matches[].vulnerability.id] | unique[]' labs/lab4/grype-from-sbom.json > /tmp/grype-ids.txt
jq -r '[.Results[].Vulnerabilities[]?.VulnerabilityID] | unique[]' labs/lab4/trivy.json > /tmp/trivy-ids.txt
comm -23 /tmp/grype-ids.txt /tmp/trivy-ids.txt | head
comm -13 /tmp/grype-ids.txt /tmp/trivy-ids.txt | head
```

**Submit**, section `## Task 2`:

- A side-by-side severity table, Grype against Trivy, with the deltas and both totals.
- Two identifiers found by one tool and missed by the other, one in each direction. For each, name the package and give your best explanation: different advisory source, different matching rule, or a package ecosystem one tool does not parse.
- Three or four sentences: when is the decoupled inventory worth the extra moving part, and when is the single binary the better answer? Your answer should mention what Lab 8 does with the SBOM.

## Bonus — A sign-ready attestation (2 pts)

Lab 8 will attach this SBOM to the image as a signed attestation. Cosign wraps a predicate in an in-toto statement itself, but writing the envelope by hand once is how you learn what is actually being signed.

```bash
# YOUR TASK: write labs/lab4/juice-shop-attestation.json
# Shape (in-toto Statement v1):
#   _type          the in-toto Statement type Cosign emits
#   subject[0].name   the image reference you scanned
#   subject[0].digest {"sha256": "<the digest, without the sha256: prefix>"}
#   predicateType  the CycloneDX predicate type Cosign uses for --type cyclonedx
#   predicate      the entire contents of juice-shop.cdx.json
#
# Hints:
#   - do not guess the two type strings. Cosign's CycloneDX predicate type is
#     unversioned and its statement type is not v1; Lab 8 shows you how to read
#     both out of a real attestation with
#       cosign verify-attestation ... | jq -r '.payload | @base64d | fromjson'
#   - the digest: docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
#   - jq can build the whole file in one line; you do not need a script
```

**Submit**, section `## Bonus`:

- The `jq` command you used and the first 20 lines of the result.
- The digest you signed over, and one sentence on why the digest and not the tag.
- Two or three sentences: what claim does this file make, who would check it, and what does it not prove?

## Submit

<!-- verify:skip student fork files -->
```bash
git add labs/lab4/juice-shop.cdx.json labs/lab4/juice-shop.spdx.json submissions/lab4.md
git add labs/lab4/juice-shop-attestation.json   # bonus only
git commit -m "feat(lab4): juice shop SBOM + grype and trivy comparison"
git push -u origin feature/lab4
```

Both SBOMs are committed: Lab 8 signs the CycloneDX one, and the SPDX one is your evidence for the format-comparison answer. The scan outputs are not: leave `grype-from-sbom.*` and `trivy.json` out of the PR and paste the numbers instead.

## Acceptance criteria

- Task 1 (6): both SBOMs generated, counts and `specVersion` reported from the actual files; the format-difference answer names a concrete reason; severity table matches the JSON; ten findings listed with package, version and fix column; the triage answer uses both fix availability and severity.
- Task 2 (4): Trivy scan present; side-by-side table with deltas; one divergent identifier in each direction with a plausible cause; the decoupled-versus-all-in-one answer refers to what Lab 8 does with the SBOM.
- Bonus (2): `juice-shop-attestation.json` has the four required fields, a real digest, and the two type strings Cosign actually uses rather than invented ones; the answer says what the attestation does not prove.

## Common pitfalls

- Grype reports GitHub advisory identifiers (`GHSA-...`) as well as `CVE-...`. Both are real; paste what the tool printed.
- Grype's severities are `Critical`, Trivy's are `CRITICAL`. Normalise the case before comparing, or your table will be full of zeros.
- The same advisory appears more than once when several packages in the image are affected. Use `unique` before counting distinct advisories.
- `syft` needs to pull the image if it is not local; the first run is slow, later ones use the cache.
- The SPDX file is larger than the CycloneDX one and Lab 8 does not use it. Do not commit it.
- `docker inspect --format '{{index .RepoDigests 0}}'` returns the digest of the registry the image came from. If you later push the image somewhere else, that list grows and the order stops being obvious; Lab 8 deals with this.

## Resources

- [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype), [Trivy](https://trivy.dev/)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/) and [SPDX](https://spdx.dev/use/specifications/)
- [CISA, Minimum Elements for an SBOM](https://www.cisa.gov/sbom) — what a regulator expects an SBOM to contain
- [in-toto attestation spec](https://github.com/in-toto/attestation/blob/main/spec/README.md)
