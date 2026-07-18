# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### Environment

* Image: `bkimminich/juice-shop:v20.0.0`
* Syft: `1.45.1`
* Grype: `0.114.0`
* Trivy: `0.69.3`
* CycloneDX specification: `1.6`

### SBOM stats

* `juice-shop.cdx.json` component count: **1846**
* `juice-shop.cdx.json` size: **1.5 MB**
* `juice-shop.cdx.json` format: **CycloneDX 1.6**
* `juice-shop.spdx.json` package count: **911**
* `juice-shop.spdx.json` size: **2.3 MB**

Syft cataloged 910 packages from the image. The CycloneDX document contains more components because the format can represent additional component and dependency records beyond the package count shown in the Syft scan summary.

### Grype severity breakdown

| Severity   |   Count |
| ---------- | ------: |
| Critical   |       7 |
| High       |      52 |
| Medium     |      35 |
| Low        |       4 |
| Negligible |       7 |
| **Total**  | **105** |

Grype reported 89 fixed and 16 not-fixed vulnerability matches. It also warned that vulnerability information for packages associated with end-of-life distributions may be incomplete or outdated.

### Top 10 CVEs

| CVE              | Severity | Package      | Installed       | Fix              |
| ---------------- | -------- | ------------ | --------------- | ---------------- |
| CVE-2015-9235    | Critical | jsonwebtoken | 0.1.0           | 4.2.2            |
| CVE-2019-10744   | Critical | lodash       | 2.4.2           | 4.17.12          |
| CVE-2023-46233   | Critical | crypto-js    | 3.3.0           | 4.2.0            |
| CVE-2026-34182   | Critical | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2  |
| CVE-2026-5450    | Critical | libc6        | 2.41-12+deb13u2 | No fix available |
| CVE-2016-1000223 | High     | jws          | 0.2.6           | 3.0.0            |
| CVE-2017-18214   | High     | moment       | 2.0.0           | 2.19.3           |
| CVE-2018-16487   | High     | lodash       | 2.4.2           | 4.17.11          |
| CVE-2020-15084   | High     | express-jwt  | 0.1.3           | 6.0.0            |
| CVE-2020-8203    | High     | lodash.set   | 4.3.2           | No fix available |

### Fix-available rate

A fix is available for **8 of the 10 findings**, giving a fix-available rate of **80%**. Following the Lecture 4 triage shortcut, the Critical and High findings with an available fixed version should be handled first because they combine high severity with an immediately actionable remediation.

The two findings without a fixed version require a different response. They should be monitored for advisory updates while compensating controls, package replacement, feature isolation, or removal of the affected dependency are considered.

## Task 2: Trivy Comparison

### Trivy severity breakdown

| Severity  |   Count |
| --------- | ------: |
| Critical  |       5 |
| High      |      43 |
| Medium    |      39 |
| Low       |      22 |
| **Total** | **109** |

Trivy detected the container operating system as Debian 13.4 and analyzed both operating-system packages and Node.js packages.

### Side-by-side counts

| Severity  |  Grype |   Trivy |       Δ |
| --------- | -----: | ------: | ------: |
| Critical  |      7 |       5 |      -2 |
| High      |     52 |      43 |      -9 |
| Medium    |     35 |      39 |      +4 |
| Low       |      4 |      22 |     +18 |
| **Total** | **98** | **109** | **+11** |

The Grype total in this comparison is 98 because the table includes only Critical, High, Medium, and Low findings. Grype additionally reported 7 Negligible findings, making its full result 105.

Although the severity totals differ, comparison of the primary CVE identifiers produced:

* Unique CVEs reported by Grype: **90**
* Unique CVEs reported by Trivy: **90**
* CVEs reported by both tools: **89**
* CVEs reported only by Grype: **1**
* CVEs reported only by Trivy: **1**

### Why the results differ

#### CVE-2022-4899

* Found by: **Grype**
* Missed by: **Trivy**
* Package: `libzstd`
* Installed version: `1.5.7+dfsg-1`
* Grype severity: **High**
* Fixed version: no fix reported

Grype associated the installed Debian package with `CVE-2022-4899`, while Trivy did not produce this primary vulnerability identifier. The likely reason is a difference in Linux distribution advisory mapping, package-version matching, or vendor-specific vulnerability interpretation between the Grype and Trivy databases.

The scanner output does not expose the exact internal matching decision, so the cause cannot be proven from the reports alone. This demonstrates why findings from different SCA tools should be validated against the relevant distribution advisory before remediation decisions are made.

#### CVE-2025-57349

* Found by: **Trivy**
* Missed by: **Grype**
* Package: `messageformat`
* Installed version: `2.3.0`
* Trivy severity: **Low**
* Fixed version: `3.0.0-beta.0`
* Status: fixed
* Finding: prototype pollution vulnerability

Trivy associated `messageformat` version 2.3.0 with `CVE-2025-57349`, while Grype did not report the CVE when scanning the CycloneDX SBOM. The likely explanation is a difference in advisory-source coverage, database refresh content, or Node.js package matching rules.

This result also shows that two current vulnerability databases may contain nearly identical CVE sets while still disagreeing on individual package-to-advisory relationships.

### When would I pick each?

#### Syft + Grype

The decoupled Syft and Grype model is preferable when the SBOM must be stored as an independent supply-chain artifact. The same CycloneDX document can be rescanned later as vulnerability databases change, passed to other security platforms, and signed as an attestation without rebuilding or downloading the original image again.

This model is especially useful for long-term evidence, incident response, regulated environments, and the Cosign attestation workflow used in Lab 8.

#### Trivy

Trivy is preferable when a team needs a simple all-in-one CI security step with minimal integration overhead. One tool can scan container images and can also cover areas such as infrastructure-as-code, secrets, and configuration problems.

Its unified workflow is convenient for fast feedback in CI pipelines, although the resulting vulnerability report is less separated from the scanner implementation than a reusable standalone SBOM.
