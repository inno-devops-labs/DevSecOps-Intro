# Lab 4 — Submission

_SBOM Generation & Software Composition Analysis on Juice Shop (`bkimminich/juice-shop:v20.0.0`)._

Tooling: Syft 1.42.4 · Grype 0.111.0 (DB v6.1.7, built 2026-06-19) · Trivy 0.69.3 · jq 1.7.1.

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count (`jq '.components | length'`): **3068**
- `juice-shop.cdx.json` size: **1,834,870 bytes (~1.8 MB)**
- `juice-shop.spdx.json` package count (`jq '.packages | length'`): **909**

> Grype was run against the **SBOM**, not the image (`grype sbom:labs/lab4/juice-shop.cdx.json`) — the
> decoupled pattern: one SBOM, many re-scans as new CVEs drop, no image re-pull.
> Grype DB for reproducibility: schema `v6.1.7`, built `2026-06-19T08:08:25Z`,
> checksum `sha256:0319d622a5515072a8f6df44b36efb29947224523dea8b2f8c460b6f11d388d5`.

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

### Top 10 CVEs (by true severity rank)
| CVE / GHSA | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | — |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | — |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-gjcw-v447-2w7q | High | jws | 0.2.6 | 3.0.0 |
| GHSA-r6q2-hw4h-h46w | High | tar | 6.2.1 | 7.5.4 |
| GHSA-r6q2-hw4h-h46w | High | tar | 4.4.19 | 7.5.4 |

### Fix-available rate
**8 of the top 10** have a fix (only `marsdb` and `libc6`/`CVE-2026-5450` don't); across the whole scan,
**89 of 104** findings are fixable. That means triage is mostly a *patching* problem, not a *mitigation* one:
applying Lecture 4's shortcut — **sort by fix-available AND severity ≥ HIGH first** — the actionable queue is the
5 fixable Criticals (`lodash`, `crypto-js`, `jsonwebtoken`, `libssl3t64`) plus the High `tar`/`jws` upgrades,
all one dependency bump away. The two unfixable Criticals (`marsdb` is abandoned; `libc6 CVE-2026-5450` has no
patched Debian build yet) drop to the bottom of the patch queue and instead need a risk decision —
replace `marsdb`, accept-and-watch `libc6` — rather than a version bump.

---

## Task 2: Trivy Comparison

Trivy was run **directly against the image** (`trivy image …`) — the all-in-one mode (catalog + scan in one step).

### Side-by-side counts
| Severity | Grype | Trivy | Δ (Trivy−Grype) |
|----------|------:|------:|--:|
| Critical | 7 | 5 | −2 |
| High | 51 | 43 | −8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | −7 |
| **Total** | **104** | **109** | **+5** |

### Why the difference?
A naïve ID diff suggested ~60 "divergent" findings, but **most of that is identifier scheme, not real
disagreement** — Grype emits **GHSA** IDs for npm advisories while Trivy normalizes the same advisories to their
**CVE** aliases. Two concrete cases:

1. **`CVE-2019-10744` (lodash 2.4.2)** — *appears* Trivy-only. **Found by Trivy** as `CVE-2019-10744` (Critical);
   **"missed" by Grype** only in name — Grype reports the **identical** vuln/package/severity under the alias
   `GHSA-jf85-cpcp-j695`. **Why:** different identifier namespace (Grype prefers GHSA for language packages, Trivy
   prefers CVE). This is the #1 reason the raw ID sets diverge; at the *vulnerability* level it's the same finding.

2. **`CVE-2025-57349` (messageformat 2.3.0, Low)** — a **genuine** divergence. **Found by Trivy**;
   **truly missed by Grype** (Grype reports **zero** findings for `messageformat` — the package isn't in its result
   set at all). **Why:** DB source + package-matching cadence — Trivy's DB had this recent (2025) advisory mapped
   to `messageformat`; Grype's DB build did not associate it. `messageformat` is the *only* package Trivy flags
   that Grype misses entirely (Trivy: 30 vulnerable packages, Grype: 29).

There's also a **severity-rating** divergence that explains the Critical gap (Grype 7 vs Trivy 5):
`CVE-2026-34182` (libssl3t64) and `CVE-2026-5450` (libc6) are rated **Critical by Grype** but **Medium by Trivy** —
Trivy fell back to a non-vendor severity for the Debian package while Grype kept the upstream CVSS. Same two CVEs,
different score → ±2 Criticals. (Trivy's much larger Low bucket, 22 vs 4, is the mirror image: it lumps in items
Grype labels Negligible plus a tail of old npm Lows.)

### When would you pick each?
- **Syft + Grype (decoupled) wins** when the **SBOM is itself a deliverable/attestation**: you generate the
  inventory once, sign it (Lab 8 `cosign attest --type cyclonedx`), publish it, and then re-scan that *same frozen
  SBOM* every time a new CVE drops — answering "are we affected?" in seconds with no image access. It also lets the
  inventory step and the policy/scan step live in different pipeline stages owned by different teams.
- **Trivy (all-in-one) wins** when you want **one simple CI step with the broadest scope**: a single `trivy image`
  (or `trivy fs`) call covers OS + language CVEs **plus** IaC misconfig, secrets, and licenses, with its own DB
  management built in. For a quick PR gate or a repo with no SBOM-signing requirement, it's less moving parts.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **1.6** (≥ 1.5, what Cosign/Lab 8 expect)
- `bomFormat`: **CycloneDX**
- `metadata.timestamp`: `2026-06-19T20:24:57+03:00` ✓
- `metadata.tools`: `syft 1.42.4` (anchore) ✓

### Image digest captured
```
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
      "timestamp": "2026-06-19T20:24:57+03:00",
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
(Built with `jq -n --slurpfile bom juice-shop.cdx.json …` — the `predicate` holds the full 3068-component SBOM.)

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json <image>@sha256:fd58…`,
Cosign wraps this in-toto **Statement** in a DSSE envelope and signs it with the project key. What gets signed is
the **binding between a specific artifact and its bill of materials**: the `subject.digest.sha256` pins the exact
image bytes (`fd58bdc9…`), and the `predicate` is the SBOM of *those* bytes. The signature therefore proves a
verifiable claim — *"this signed identity attests that image `sha256:fd58…` contains exactly these 3068
components"* — so a downstream verifier (admission controller, `cosign verify-attestation`, or DefectDojo import in
Lab 10) can trust the SBOM came from us and matches the image it's deployed from, rather than a forged or
mismatched inventory. (Lecture 8 slide 9: the digest in `subject` is what makes the attestation non-transferable
to any other image.)
