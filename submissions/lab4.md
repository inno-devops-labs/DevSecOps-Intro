# Lab 4 — SBOM Generation and Software Composition Analysis

## Task 1

### 1. SBOM generation

Two SBOM files were generated from the Docker image `bkimminich/juice-shop:v20.0.0` using Syft:

* `labs/lab4/juice-shop.cdx.json` — CycloneDX JSON
* `labs/lab4/juice-shop.spdx.json` — SPDX JSON

Results:

| File                   | Format    |           Count |
| ---------------------- | --------- | --------------: |
| `juice-shop.cdx.json`  | CycloneDX | 3069 components |
| `juice-shop.spdx.json` | SPDX      |    909 packages |

CycloneDX and SPDX use different data models and represent software components and related metadata differently, so the same image can produce different counts. The numbers therefore should not be interpreted as a direct comparison of the number of installed packages.

CycloneDX specification version:

```text
1.7
```

The values were obtained directly from the generated SBOM files using `jq`.

### 2. Vulnerability severity

Grype scanned the generated CycloneDX SBOM rather than the Docker image directly.

The scan produced **182 vulnerability matches**:

| Severity   |   Count |
| ---------- | ------: |
| Critical   |      14 |
| High       |      85 |
| Medium     |      64 |
| Low        |      12 |
| Negligible |       7 |
| Unknown    |       0 |
| **Total**  | **182** |

Grype also reported:

* Fixed: **156**
* Not fixed: **26**
* Ignored: **0**

### 3. Top 10 findings

The following are the first ten findings produced by the ranking command from section 4.3:

|  # | Severity | Vulnerability       | Package      | Installed       | Fix             |
| -: | -------- | ------------------- | ------------ | --------------- | --------------- |
|  1 | Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0           | 4.2.2           |
|  2 | Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.4.0           | 4.2.2           |
|  3 | Critical | GHSA-jf85-cpcp-j695 | lodash       | 2.4.2           | 4.17.12         |
|  4 | Critical | CVE-2026-63073      | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
|  5 | Critical | GHSA-mp2f-45pm-3cg9 | decompress   | 4.2.1           | No fix          |
|  6 | Critical | GHSA-xwcq-pm8m-c4vf | crypto-js    | 3.3.0           | 4.2.0           |
|  7 | Critical | CVE-2026-34182      | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
|  8 | Critical | GHSA-23hp-3jrh-7fpw | tar          | 4.4.19          | 7.5.19          |
|  9 | Critical | GHSA-23hp-3jrh-7fpw | tar          | 6.2.1           | 7.5.19          |
| 10 | Critical | GHSA-23hp-3jrh-7fpw | tar          | 7.5.15          | 7.5.19          |

### 4. Triage

Of the ten highest-ranked findings, **9 have a fix available** and **1 does not**.

Based only on severity and fix availability, I would first investigate the Critical vulnerabilities that have a known fixed version, because they combine the highest severity with an available remediation path. In particular, `jsonwebtoken`, `lodash`, `libssl3t64`, `crypto-js`, and `tar` should be reviewed for safe version upgrades and compatibility with the application.

The `decompress` vulnerability (`GHSA-mp2f-45pm-3cg9`) is also Critical, but Grype does not report an available fix, so it would require a different mitigation approach, such as checking whether the dependency can be removed, replaced, or isolated.

The scan demonstrates the value of separating SBOM generation from vulnerability scanning: the CycloneDX SBOM provides an inventory that can be scanned independently by Grype.

## Task 2

### 1. Trivy scan

Trivy scanned the Docker image `bkimminich/juice-shop:v20.0.0` directly (not the SBOM):

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output labs/lab4/trivy.json
```

### 2. Grype vs. Trivy — severity comparison

Trivy prints severities in upper case and Grype in title case; the table below normalizes both to one case before comparing.

| Severity   | Grype |  Trivy | Delta (Grype − Trivy) |
| ---------- | ----: | -----: | ---------------------: |
| Critical   |    14 |     10 |                     +4 |
| High       |    85 |     64 |                    +21 |
| Medium     |    64 |     68 |                     −4 |
| Low        |    12 |     30 |                    −18 |
| Negligible |     7 |    N/A |                     +7 |
| **Total**  | **182** | **172** |                **+10** |

Trivy's `--severity` filter was set to `LOW,MEDIUM,HIGH,CRITICAL`, so it has no `Negligible` bucket at all (those 7 Grype matches simply have no equivalent row). Even excluding Negligible, the two tools disagree on where individual findings land (Critical/High vs. Medium/Low), because each tool's own database assigns the severity, not a shared source.

### 3. Where they disagree

Comparing the unique vulnerability IDs (`comm -23` / `comm -13` after each list was deduplicated with `unique`) gives 156 distinct IDs from Grype and 145 from Trivy, with real differences in both directions:

* **Grype only — `CVE-2026-48617` (package `node`, version `24.15.0`, type `binary`, High).** Syft's binary classifier fingerprints the embedded Node.js runtime binary itself and Grype matches it against Node's own advisory feed. Trivy's report has a target literally named `Node.js`, but every entry under it is an npm dependency resolved from `node_modules/*/package.json` (e.g. `@ai-sdk/provider-utils`) — Trivy never lists a package named `node` at version `24.15.0` anywhere in its output. This is a package-ecosystem gap: Trivy's default scanners do not treat the Node.js runtime binary as a scannable artifact, so a runtime CVE like this one is invisible to it regardless of database freshness.
* **Trivy only — `CVE-2015-9235` (package `jsonwebtoken`, versions `0.1.0`/`0.4.0`, Critical in Trivy's output).** This looks like a miss on Grype's side, but Grype flagged the exact same flaw under a different identifier: `GHSA-c7hr-j4mj-j2w6` (the #1 and #2 rows in the Task 1 top-ten table), whose own reference list links straight to `https://nvd.nist.gov/vuln/detail/CVE-2015-9235`. Grype's npm advisory data is keyed on GHSA IDs while Trivy's is keyed on the CVE ID for the same advisory, so a naive ID-only diff counts one real vulnerability as "found by only one tool" in each direction. This is a different-matching-rule / identifier-normalization problem, not a coverage gap.

### 4. Decoupled inventory vs. all-in-one scanner

The decoupled Syft+Grype approach earns its extra moving part when the SBOM itself has downstream value beyond this one scan: Lab 8 takes `juice-shop.cdx.json` and attaches it to the image as a signed in-toto attestation, so the inventory becomes a durable, verifiable artifact that can be re-scanned the moment a new CVE is published, without re-pulling or re-building the image. Trivy's single binary is the better answer when you just need a fast, one-shot answer to "is this image vulnerable right now," for example in a CI gate that doesn't need to persist or sign anything. In practice the two are complementary rather than substitutes: this comparison shows Trivy catching npm dependency CVEs Grype's SBOM-based scan also caught (just under different IDs) plus its own OS-package view, while only the Syft-generated SBOM gives Grype visibility into the Node.js runtime binary and, more importantly, gives Lab 8 something it can actually sign.

## Bonus

### 1. Building the attestation

The digest was read directly from the local image, and the entire CycloneDX SBOM was slurped in as the predicate, in one `jq` invocation:

```bash
DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | sed 's/.*@sha256://')

jq -n \
  --arg image "bkimminich/juice-shop:v20.0.0" \
  --arg digest "$DIGEST" \
  --slurpfile predicate labs/lab4/juice-shop.cdx.json \
  '{
    _type: "https://in-toto.io/Statement/v0.1",
    subject: [{name: $image, digest: {sha256: $digest}}],
    predicateType: "https://cyclonedx.org/bom",
    predicate: $predicate[0]
  }' > labs/lab4/juice-shop-attestation.json
```

The two type strings were not guessed: `predicateType` is Cosign's unversioned CycloneDX predicate identifier (`in_toto.PredicateCycloneDX` in Cosign's source, `https://cyclonedx.org/bom`), and `_type` is the in-toto Statement type Cosign actually emits, which — despite the in-toto spec having moved on to v1 — is still `https://in-toto.io/Statement/v0.1`.

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
    "serialNumber": "urn:uuid:a7acd9a9-8f21-459e-82f0-d031efb50fd4",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-17T19:20:36+03:00",
      "tools": {
```

### 2. The digest

The digest signed over is `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`, obtained with `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'`. The digest is signed rather than the tag because a tag (`v20.0.0`) is a mutable pointer that can be repushed to reference different bytes at any time, while the digest is a cryptographic hash of the immutable image content — signing it is the only way to guarantee that the SBOM actually describes the exact bytes someone later pulls and runs.

### 3. What the attestation claims

The attestation claims that the CycloneDX document in `predicate` is the software bill of materials for the image identified by `subject[0].digest`, and — once wrapped by Cosign and signed — that whoever holds the corresponding private key (or identity, under keyless signing) vouches for that pairing. A verifier such as `cosign verify-attestation` (and, in Lab 8, a policy engine gating a deployment) checks the signature and the subject digest to confirm the SBOM belongs to that exact image before trusting its contents. It does **not** prove that the SBOM is complete or accurate (a scanner can still miss vendored or dynamically fetched code), that the image is free of vulnerabilities, or that the image was built from the source it claims to be built from — it only proves the SBOM and the image digest have not been separated or swapped since signing.

