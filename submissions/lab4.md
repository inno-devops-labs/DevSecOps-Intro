# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: **3068**
- `juice-shop.cdx.json` size: **1.7 MB**
- `juice-shop.spdx.json` package count: **909**
- `juice-shop.spdx.json` size: **3.0 MB**

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| Unknown | 0 |
| **Total** | **104** |

### Top 10 CVEs / advisories

| CVE / Advisory | Source advisory | Severity | Package | Installed | Fix |
|----------------|-----------------|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | GHSA-c7hr-j4mj-j2w6 | Critical | `jsonwebtoken` | `0.1.0` | `4.2.2` |
| GHSA-c7hr-j4mj-j2w6 | GHSA-c7hr-j4mj-j2w6 | Critical | `jsonwebtoken` | `0.4.0` | `4.2.2` |
| GHSA-jf85-cpcp-j695 | GHSA-jf85-cpcp-j695 | Critical | `lodash` | `2.4.2` | `4.17.12` |
| GHSA-xwcq-pm8m-c4vf | GHSA-xwcq-pm8m-c4vf | Critical | `crypto-js` | `3.3.0` | `4.2.0` |
| CVE-2026-5450 | CVE-2026-5450 | Critical | `libc6` | `2.41-12+deb13u2` | `No listed fix` |
| CVE-2026-34182 | CVE-2026-34182 | Critical | `libssl3t64` | `3.5.5-1~deb13u2` | `3.5.6-1~deb13u2` |
| GHSA-5mrr-rgp6-x4gr | GHSA-5mrr-rgp6-x4gr | Critical | `marsdb` | `0.6.11` | `No listed fix` |
| GHSA-35jh-r3h4-6jhm | GHSA-35jh-r3h4-6jhm | High | `lodash` | `2.4.2` | `4.17.21` |
| GHSA-8hfj-j24r-96c4 | GHSA-8hfj-j24r-96c4 | High | `moment` | `2.0.0` | `2.29.2` |
| GHSA-p6mc-m468-83gw | GHSA-p6mc-m468-83gw | High | `lodash.set` | `4.3.2` | `No listed fix` |

### Fix-available rate

Out of the top 10 findings, **7 of 10** have a listed fix version. My patch cadence priority would be to sort first by fix availability and then by severity, especially for findings with severity `High` or `Critical`. This follows the Lecture 4 triage shortcut: fix what is both severe and practically patchable first, then track the remaining unfixed items as risk accepted or blocked by upstream dependencies.

---

## Task 2: Trivy Comparison

### Trivy scan output

The following table summarizes the HIGH/CRITICAL vulnerabilities from Trivy JSON output:

| Vulnerability | Severity | Package | Installed | Fixed | Target |
|---------------|----------|---------|-----------|-------|--------|
| CVE-2023-46233 | CRITICAL | `crypto-js` | `3.3.0` | `4.2.0` | `Node.js` |
| CVE-2015-9235 | CRITICAL | `jsonwebtoken` | `0.1.0` | `4.2.2` | `Node.js` |
| CVE-2015-9235 | CRITICAL | `jsonwebtoken` | `0.4.0` | `4.2.2` | `Node.js` |
| CVE-2019-10744 | CRITICAL | `lodash` | `2.4.2` | `4.17.12` | `Node.js` |
| GHSA-5mrr-rgp6-x4gr | CRITICAL | `marsdb` | `0.6.11` | `No listed fix` | `Node.js` |
| CVE-2026-45447 | HIGH | `libssl3t64` | `3.5.5-1~deb13u2` | `3.5.6-1~deb13u2` | `bkimminich/juice-shop:v20.0.0 (debian 13.4)` |
| NSWG-ECO-428 | HIGH | `base64url` | `0.0.6` | `>=3.0.0` | `Node.js` |
| CVE-2020-15084 | HIGH | `express-jwt` | `0.1.3` | `6.0.0` | `Node.js` |
| CVE-2022-25881 | HIGH | `http-cache-semantics` | `3.8.1` | `4.1.1` | `Node.js` |
| CVE-2022-23539 | HIGH | `jsonwebtoken` | `0.1.0` | `9.0.0` | `Node.js` |
| NSWG-ECO-17 | HIGH | `jsonwebtoken` | `0.1.0` | `>=4.2.2` | `Node.js` |
| CVE-2022-23539 | HIGH | `jsonwebtoken` | `0.4.0` | `9.0.0` | `Node.js` |
| NSWG-ECO-17 | HIGH | `jsonwebtoken` | `0.4.0` | `>=4.2.2` | `Node.js` |
| CVE-2016-1000223 | HIGH | `jws` | `0.2.6` | `>=3.0.0` | `Node.js` |
| CVE-2025-65945 | HIGH | `jws` | `0.2.6` | `3.2.3, 4.0.1` | `Node.js` |
| CVE-2018-16487 | HIGH | `lodash` | `2.4.2` | `>=4.17.11` | `Node.js` |
| CVE-2021-23337 | HIGH | `lodash` | `2.4.2` | `4.17.21` | `Node.js` |
| CVE-2020-8203 | HIGH | `lodash.set` | `4.3.2` | `No listed fix` | `Node.js` |
| CVE-2026-26996 | HIGH | `minimatch` | `3.0.5` | `10.2.1, 9.0.6, 8.0.5, 7.4.7, 6.2.1, 5.1.7, 4.2.4, 3.1.3` | `Node.js` |
| CVE-2026-27903 | HIGH | `minimatch` | `3.0.5` | `10.2.3, 9.0.7, 8.0.6, 7.4.8, 6.2.2, 5.1.8, 4.2.5, 3.1.3` | `Node.js` |

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | 4 |
| Low | 4 | 22 | 18 |
| **Total** | **104** | **109** | **5** |

### Why the difference?

1. **CVE-2015-9235** was found by **Trivy** and not by **Grype** after normalizing Grype's related CVE aliases. A likely reason is that Grype and Trivy use different vulnerability databases, package matching logic, and metadata refresh cadence. This can make one tool report a vulnerability that the other does not match to the same package/version.

2. **CVE-2016-1000223** was found by **Trivy** and not by **Grype** after normalizing Grype's related CVE aliases. This difference is likely caused by tool-specific package identification and fix-version awareness. It shows why scan results should be treated as evidence to triage, not as a single absolute truth.

### When would you pick each?

Syft + Grype is better when I want a decoupled workflow: generate the SBOM once, store it as an artifact, and rescan the same inventory later when new CVEs appear. This model is also better for attestations because the SBOM can become the signed predicate in Lab 8.

Trivy is better when I want a simpler all-in-one CI step. It is easy to run directly against an image and can also cover other checks such as IaC, secrets, and misconfiguration scanning, so it is convenient for fast pipeline feedback.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: **1.5**
- `bomFormat`: **CycloneDX**

### Image digest captured

- Image: `bkimminich/juice-shop:v20.0.0`
- Captured digest: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Predicate type: `https://cyclonedx.org/bom/v1.5`

### Attestation predicate

First 30 lines of `labs/lab4/juice-shop-attestation.json`:

~~~json
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
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:934e810b-d481-4527-9bc2-c7237f80ee71",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T18:49:14+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.45.1"
          }
        ]
      },
      "component": {
~~~

### What this enables in Lab 8

In Lab 8, `cosign attest --type cyclonedx --predicate juice-shop-attestation.json` will sign the claim that the specific Juice Shop image digest is associated with this CycloneDX SBOM. The signature does not claim that the image is vulnerability-free; it proves that this SBOM inventory was produced for that exact image digest and can be verified later as supply-chain evidence.
