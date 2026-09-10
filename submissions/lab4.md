# Lab 4 — Submission

## Task 1

### Component counts

| Field | Value |
|-------|-------|
| CycloneDX components (`jq '.components \| length'`) | `3068` |
| SPDX packages (`jq '.packages \| length'`) | `909` |
| CycloneDX `specVersion` | `1.7` |

**Why the counts differ.** CycloneDX and SPDX draw the boundary between "a thing" differently. CycloneDX walks the full dependency tree and records every resolved package, including runtime deps, dev deps pulled during build, and OS-layer packages — each one is a `component`. SPDX operates at the SPDX Package level: it rolls up files and sub-packages under a single parent entry when they share provenance, and its `packages` field maps closer to what a human would call "installed software." The same Juice Shop image therefore produces ~3 × more CycloneDX components than SPDX packages: the npm dependency graph alone has hundreds of transitive entries that CycloneDX splits out individually but SPDX groups.

### Severity table (Grype, from SBOM)

| Severity | Count |
|----------|-------|
| Critical | 14 |
| High | 84 |
| Medium | 60 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 4 |
| **Total** | **181** |

### Top 10 findings (ranked by severity)

| Severity | ID | Package @ version | Fix |
|----------|----|-------------------|-----|
| Critical | GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.1.0` | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.4.0` | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | `lodash@2.4.2` | 4.17.12 |
| Critical | CVE-2026-63073 | `libssl3t64@3.5.5-1~deb13u2` | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | `decompress@4.2.1` | *(no fix)* |
| Critical | GHSA-xwcq-pm8m-c4vf | `crypto-js@3.3.0` | 4.2.0 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@4.4.19` | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@6.2.1` | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@7.5.15` | 7.5.19 |
| Critical | CVE-2026-5450 | `libc6@2.41-12+deb13u2` | *(no fix)* |

**Fix availability and triage.** 8 of the 10 have a fix version listed. Given only the severity and fix columns, I would start with `jsonwebtoken` (two Critical entries, fix available at 4.2.2): JWT is in the authentication path, so a critical vulnerability there has the widest blast radius, and bumping a version with a published safe release is a clear, low-risk step. After that, `lodash` and `crypto-js` are also Critical with fixes and widely imported by npm sub-deps, so they are likely to appear in many other packages in the tree. `decompress` and `libc6` both show Critical severity but have no fix yet — I would flag them for monitoring and apply compensating controls rather than waiting on an upstream patch.

---

## Task 2

### Severity table — Grype vs. Trivy

| Severity | Grype | Trivy | Delta |
|----------|-------|-------|-------|
| Critical | 14 | 10 | −4 |
| High | 84 | 64 | −20 |
| Medium | 60 | 66 | +6 |
| Low | 12 | 31 | +19 |
| Negligible | 7 | — | — |
| Unknown | 4 | — | — |
| **Total** | **181** | **171** | — |

Unique advisory IDs: Grype found 155, Trivy found 144. 104 IDs appear only in Grype, 93 only in Trivy, and 51 overlap.

### Divergent findings

**Found by Grype, missed by Trivy — `CVE-2026-48617` (`node@24.15.0`, binary)**  
Grype classifies the embedded Node.js runtime as a `binary` component and maps it against the Node.js advisory feed. Trivy's image scanner indexes language-specific manifests (`package.json`, `package-lock.json`) and OS package databases, but it does not fingerprint unpackaged binaries the same way. CVE-2026-48617 is a Node runtime advisory that has no `apt` or `npm` package entry to anchor it, so Trivy simply has nothing to match against and produces no finding.

**Found by Trivy, missed by Grype — `CVE-2015-9235` (`jsonwebtoken@0.1.0`, npm)**  
This is an older NVD advisory (2015) for a JWT algorithm-confusion flaw. Grype's vulnerability database aggregates from NVD, GitHub Advisory (GHSA), and several OS feeds; for this particular entry it only surfaces the GHSA alias (`GHSA-c7hr-j4mj-j2w6`), which is the canonical identifier it matched first. Trivy ingests the raw NVD CVE-ID separately and reports it in parallel with the GHSA alias, so it appears to "find more." Both are the same underlying vulnerability — different advisory-source priority explains the discrepancy.

### Decoupled inventory vs. all-in-one scanner

The decoupled approach (generate SBOM once, scan repeatedly) is worth the extra moving part when you need to scan the same image multiple times — for example, when a new CVE is published you can re-run Grype against the stored SBOM in seconds without re-pulling or re-indexing a 576 MB image. It also enables the workflow that Lab 8 builds on: the CycloneDX SBOM is attached to the image as a signed in-toto attestation, so downstream consumers can verify both *what is in the image* and *that the inventory was produced from a known, integrity-checked build* — none of that is possible if the scan result only ever exists as transient console output. A single binary like Trivy is the better answer for a first-pass audit or a CI gate where you just want a pass/fail verdict on a fresh pull: fewer steps, one config file, and no SBOM artifact to manage. The tradeoff is that you lose the decoupled re-scan capability and the signed attestation chain that the SBOM enables.
