# Lab 4 — SBOM Generation and Software Composition Analysis

## Task 1

### SBOM generation

The CycloneDX SBOM contains **3069 components**.

The SPDX SBOM contains **909 packages**.

The CycloneDX SBOM has `specVersion` **1.7**.

The two formats report different numbers because CycloneDX and SPDX use different structures and counting models for representing software components and their relationships. CycloneDX represents a broader component inventory, while SPDX groups information into packages and related metadata, so the same image can produce different counts.

### Grype severity summary

| Severity   |   Count |
| ---------- | ------: |
| Critical   |      14 |
| High       |      85 |
| Medium     |      65 |
| Low        |      12 |
| Negligible |       7 |
| **Total**  | **183** |

Grype reported **183 vulnerability matches** in total: **156 fixed** and **27 not fixed**.

### Top 10 findings

| Severity | Vulnerability       | Package      | Installed version | Fix             |
| -------- | ------------------- | ------------ | ----------------- | --------------- |
| High     | GHSA-35jh-r3h4-6jhm | lodash       | 2.4.2             | 4.17.21         |
| High     | GHSA-8hfj-j24r-96c4 | moment       | 2.0.0             | 2.29.2          |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0             | 4.2.2           |
| Critical | GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.4.0             | 4.2.2           |
| Medium   | GHSA-87vv-r9j6-g5qv | moment       | 2.0.0             | 2.11.2          |
| Critical | GHSA-jf85-cpcp-j695 | lodash       | 2.4.2             | 4.17.12         |
| High     | GHSA-p6mc-m468-83gw | lodash.set   | 4.3.2             | No fix listed   |
| High     | CVE-2026-45447      | libssl3t64   | 3.5.5-1~deb13u2   | 3.5.6-1~deb13u2 |
| High     | GHSA-446m-mv8f-q348 | moment       | 2.0.0             | 2.19.3          |
| Medium   | GHSA-fvqr-27wr-82fm | lodash       | 2.4.2             | 4.17.5          |

**9 of the top 10 findings have a fix available.** The only one without a listed fix is `GHSA-p6mc-m468-83gw` affecting `lodash.set`.

Given only the severity and fix information, I would first address the **Critical** findings that have an available fix, especially the `jsonwebtoken` and `lodash` vulnerabilities. After that I would address the remaining High-severity findings with available fixes, followed by Medium and Low findings. The `lodash.set` finding would require separate investigation because Grype does not list a fixed version.

The results above come directly from the Grype scan: 14 Critical, 85 High, 65 Medium, 12 Low and 7 Negligible findings. The first rows of the scan show the package versions and available fixes used in the table.

## Task 2

### Grype vs Trivy

| Severity  |   Grype |   Trivy | Delta (Trivy − Grype) |
| --------- | ------: | ------: | --------------------: |
| Critical  |      14 |      10 |                    -4 |
| High      |      85 |      64 |                   -21 |
| Medium    |      65 |      68 |                    +3 |
| Low       |      12 |      31 |                   +19 |
| **Total** | **183** | **173** |               **-10** |

Trivy reported **173 vulnerabilities** in total: 10 Critical, 64 High, 68 Medium and 31 Low. Grype reported **183** findings. Therefore, Grype reported 10 more matches overall, although Trivy reported more Medium and Low findings.

### Divergent identifiers

One identifier found by Grype but missed by Trivy is **GHSA-35jh-r3h4-6jhm**, affecting the **lodash 2.4.2** package. This is a GitHub Security Advisory identifier, and the difference can plausibly be caused by differences in advisory databases or vulnerability matching rules between Grype and Trivy.

One identifier found by Trivy but missed by Grype is **CVE-2015-9235**, affecting the **jsonwebtoken** package. This difference can similarly be explained by different advisory sources or matching rules used by the two scanners.

The comparison shows that the two tools should not necessarily be expected to produce identical vulnerability sets. Grype scans the previously generated SBOM, which separates inventory generation from vulnerability analysis and makes the same inventory reusable by different tools. This extra step is useful when the SBOM needs to be stored, transferred, audited or reused later. In contrast, an all-in-one scanner such as Trivy is convenient when a quick scan of an image is needed without maintaining a separate inventory workflow. In Lab 8, the CycloneDX SBOM generated here is used as a signed attestation for the image.

## Evidence

The generated SBOM files are:

* `labs/lab4/juice-shop.cdx.json`
* `labs/lab4/juice-shop.spdx.json`

The CycloneDX file contains **3069 components**, the SPDX file contains **909 packages**, and the CycloneDX `specVersion` is **1.7**.

The scan output files were used to obtain the reported numbers, while the lab instructions specify that the scan outputs themselves should not be committed to the PR; instead, the numerical results should be included in the report.
