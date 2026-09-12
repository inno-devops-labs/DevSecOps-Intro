# Lab 4 — Submission

*SBOM Generation & Software Composition Analysis on Juice Shop (`bkimminich/juice-shop:v20.0.0`).*

Tooling: Syft 1.42.4 · Grype 0.111.0 (DB v6.1.7, built 2026-06-19) · Trivy 0.69.3 · jq 1.7.1.

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

* `juice-shop.cdx.json` component count (`jq '.components | length'`): **3068**

* `juice-shop.cdx.json` size: **1,834,870 bytes (~1.8 MB)**

* `juice-shop.spdx.json` package count (`jq '.packages | length'`): **909**

> Grype scanned the **SBOM** rather than the image (`grype sbom:labs/lab4/juice-shop.cdx.json`). This follows the decoupled approach: one SBOM can be reused for multiple scans as new CVEs are published, without pulling the image again.
>
> Grype DB for reproducibility: schema `v6.1.7`, built `2026-09-11T22:08:25Z`,
>
> checksum `sha256:0319d622a5515072a8f6df44b36efb29947224523dea8b2f8c460b6f11d388d5`.

### Grype severity breakdown

| Severity   |   Count |
| ---------- | ------: |
| Critical   |       7 |
| High       |      51 |
| Medium     |      35 |
| Low        |       4 |
| Negligible |       7 |
| **Total**  | **104** |

### Top 10 CVEs (by true severity rank)

| CVE / GHSA          | Severity | Package      | Installed       | Fix             |
| ------------------- | -------- | ------------ | --------------- | --------------- |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb       | 0.6.11          | —               |
| CVE-2026-34182      | Critical | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-5450       | Critical | libc6        | 2.41-12+deb13u2 | —               |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js    | 3.3.0           | 4.2.0           |
| GHSA-jf85-cpcp-j695 | Critical | lodash       | 2.4.2           | 4.17.12         |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0           | 4.2.2           |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0           | 4.2.2           |
| GHSA-gjcw-v447-2w7q | High     | jws          | 0.2.6           | 3.0.0           |
| GHSA-r6q2-hw4h-h46w | High     | tar          | 6.2.1           | 7.5.4           |
| GHSA-r6q2-hw4h-h46w | High     | tar          | 4.4.19          | 7.5.4           |

### Fix-available rate

**8 of the top 10** have an available fix (only `marsdb` and `libc6`/`CVE-2026-5450` do not). Across the complete scan, **89 of 104** findings can be fixed. Therefore, most of the triage effort is a *patching* task rather than a *mitigation* task:

following Lecture 4's shortcut — **sort by fix-available AND severity ≥ HIGH first** — the immediate action list consists of the 5 fixable Criticals (`lodash`, `crypto-js`, `jsonwebtoken`, `libssl3t64`) together with the High `tar`/`jws` upgrades. All of these can be addressed by updating the affected dependencies.

The two Critical findings without fixes (`marsdb` is abandoned, while `libc6 CVE-2026-5450` does not yet have a patched Debian build) should instead be moved lower in the patch queue and handled through a risk decision: replace `marsdb` or accept and monitor the `libc6` issue.

---

## Task 2: Trivy Comparison

Trivy was executed **directly against the image** (`trivy image …`), using its all-in-one mode where image cataloging and vulnerability scanning happen in a single step.

### Side-by-side counts

| Severity   |   Grype |   Trivy | Δ (Trivy−Grype) |
| ---------- | ------: | ------: | --------------: |
| Critical   |       7 |       5 |              −2 |
| High       |      51 |      43 |              −8 |
| Medium     |      35 |      39 |              +4 |
| Low        |       4 |      22 |             +18 |
| Negligible |       7 |       0 |              −7 |
| **Total**  | **104** | **109** |          **+5** |

### Why the difference?

A simple comparison of vulnerability IDs produced around 60 apparently "divergent" findings, but **most of this difference comes from identifier naming rather than actual disagreement**. Grype uses **GHSA** identifiers for npm advisories, whereas Trivy often reports the corresponding **CVE** aliases.

Two concrete cases:

1. **`CVE-2019-10744` (lodash 2.4.2)** — *appears* to be Trivy-only. **Trivy found** it as `CVE-2019-10744` (Critical), while **Grype only appears to have "missed" it because of the identifier**. Grype reports the **same vulnerability, package, and severity** under the alias `GHSA-jf85-cpcp-j695`. **Why:** the tools use different identifier namespaces: Grype prefers GHSA identifiers for language packages, while Trivy prefers CVE identifiers. This is the main reason the raw ID sets differ; at the *vulnerability* level, both tools report the same issue.

2. **`CVE-2025-57349` (messageformat 2.3.0, Low)** — this is a **genuine** difference. **Trivy found** the vulnerability, while **Grype genuinely missed it** because Grype reports **zero** findings for `messageformat`; the package does not appear in its result set at all. **Why:** differences in database sources and package-matching update cycles. Trivy's DB contained the recent 2025 advisory mapped to `messageformat`, while Grype's DB build did not associate that advisory with the package. `messageformat` is the *only* package flagged by Trivy that Grype misses completely (Trivy: 30 vulnerable packages, Grype: 29).

There is also a **severity-rating** difference that accounts for the Critical count gap (Grype 7 vs Trivy 5):

`CVE-2026-34182` (libssl3t64) and `CVE-2026-5450` (libc6) are classified as **Critical by Grype** but **Medium by Trivy**. Trivy used a non-vendor fallback severity for the Debian package, whereas Grype retained the upstream CVSS rating. Thus, the same two CVEs receive different severity scores, producing a difference of ±2 Critical findings. Trivy's much larger Low category, 22 versus 4, is the corresponding effect: it includes findings that Grype classifies as Negligible along with a number of older npm Low findings.

### When would you pick each?

* **Syft + Grype (decoupled) wins** when the **SBOM itself is a deliverable or attestation**: the inventory can be generated once, signed (Lab 8 `cosign attest --type cyclonedx`), published, and then rescanned from that *same frozen SBOM* whenever a new CVE appears. This answers "are we affected?" without requiring image access. It also allows inventory generation and vulnerability scanning/policy enforcement to be placed in separate pipeline stages managed by different teams.

* **Trivy (all-in-one) wins** when you need **a single, straightforward CI step with broader coverage**: one `trivy image` (or `trivy fs`) command handles OS and language CVEs **as well as** IaC misconfigurations, secrets, and licenses, with database management built in. For a quick PR gate or a repository without an SBOM-signing requirement, this means fewer separate components and steps.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

* `specVersion`: **1.6** (≥ 1.5, what Cosign/Lab 8 expect)

* `bomFormat`: **CycloneDX**

* `metadata.timestamp`: `2026-09-11T20:34:57+03:00` ✓

* `metadata.tools`: `syft 1.42.4` (anchore) ✓

### Image digest captured

```text
docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'

bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Attestation predicate (first 30 lines of `juice-shop-attestation.json`)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:87e626e2-092a-4147-be18-6bfd9834bedd",
    "version": 1,
    "metadata": {
      "timestamp": "2026-09-11T19:34:57+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.42.4"
          }
        ]
      },
      "component": {
```

(Built with `jq -n --slurpfile bom juice-shop.cdx.json …` — the `predicate` contains the complete 3068-component SBOM.)

### What this enables in Lab 8

When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json <image>@sha256:fd58…`, Cosign places this in-toto **Statement** inside a DSSE envelope and signs it using the project key. The signature covers the **binding between a specific artifact and its bill of materials**: `subject.digest.sha256` identifies the exact image bytes (`fd58bdc9…`), while the `predicate` contains the SBOM describing *those same* bytes.

As a result, the signature provides a verifiable claim: *"this signed identity attests that image `sha256:fd58…` contains exactly these 3068 components"*. A downstream verifier, such as an admission controller, `cosign verify-attestation`, or the DefectDojo import in Lab 10, can therefore trust that the SBOM was produced by us and corresponds to the deployed image rather than being a forged or mismatched inventory. (Lecture 8 slide 9: the digest in `subject` prevents the attestation from being transferred to a different image.)
