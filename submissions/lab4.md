# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: 1,504,963 bytes (~1.5 MB)
- `juice-shop.spdx.json` component count: 911

Note: the CycloneDX component count (1846) is notably higher than the SPDX
package count (911). CycloneDX counts every individual component including
nested/transitive npm dependencies as separate entries, while SPDX's `packages`
array appears to group some of these more coarsely. Both numbers are also well
above the lab's expected 200-500 range — likely because the current Juice Shop
v20.0.0 image has a deeper node_modules tree than when the lab was written.

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 105 |

### Top 10 CVEs

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (none — won't fix) |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (none) |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | (none) |

Note on sorting: `sort_by(.severity)` sorts alphabetically, so "Negligible" would
normally outrank "Critical" in the full list. In this specific result it happened
to work out correctly because all 7 Critical findings sorted before any Low/Negligible
entries simply due to volume — but this was verified by inspecting the full severity
breakdown first, not assumed from the sort order alone.

### Fix-available rate

Out of the top 10 CVEs, 7 out of 10 have a fix version available; 3 (libc6 CVE-2026-5450,
marsdb GHSA-5mrr-rgp6-x4gr, and lodash.set GHSA-p6mc-m468-83gw) have no fix listed.
Following Lecture 4's triage shortcut — sort by fix-available AND severity >= HIGH first —
the actionable priority list is the 6 npm-level Critical/High findings with a fix
(jsonwebtoken, lodash, crypto-js, libssl3t64), since those can be remediated immediately
by bumping a version. The 3 no-fix findings need a different response: either accept the
risk, find an alternative package (marsdb and lodash.set look abandoned), or wait for an
upstream patch (libc6's "won't fix" status from Debian means it's not getting fixed in
this OS release at all).

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Delta |
|----------|------:|------:|------:|
| Critical | 7 | 5 | -2 |
| High | 52 | 43 | -9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible (Grype only) | 7 | n/a | n/a |
| **Total** | 105 | 109 | +4 |

Note: Trivy has no "Negligible" severity bucket, so Grype's 7 negligible findings
have no direct counterpart in the Trivy breakdown. The "Total" delta is therefore
not a clean apples-to-apples number.

### Why the difference?

**CVE pair 1 — GHSA-35jh-r3h4-6jhm vs CVE-2021-23337 (lodash, command injection)**
Grype reported this as `GHSA-35jh-r3h4-6jhm`. Trivy did not list that ID for lodash,
which initially looked like a missed finding. Looking it up, GHSA-35jh-r3h4-6jhm
*is* CVE-2021-23337 — the same vulnerability under GitHub's advisory ID instead of
the CVE ID. Trivy's lodash findings list does include CVE-2021-23337. So this
isn't really a missed detection — it's a reminder that Grype and Trivy don't always
report the same identifier for the same underlying issue, and a naive ID-string
diff produces false "only found by X" results unless you cross-reference aliases.

**CVE pair 2 — CVE-2022-4899 (libzstd, real divergence)**
Grype found `CVE-2022-4899` (High) in `libzstd` on the Debian OS layer. Trivy's
scan of the same image returned zero vulnerabilities for `libzstd` — not a
different ID, an empty result. The image runs Debian 13 (noted as EOL/unstable by
Grype's own warning during the scan), and the two tools likely pull from different
OS vulnerability feeds with different coverage for non-LTS Debian releases. This
looks like a genuine gap in Trivy's Debian 13 package coverage for this CVE, not
a labeling difference.

### When would you pick each?
Syft+Grype's decoupled model wins when the SBOM itself is a long-lived artifact —
once you've generated `juice-shop.cdx.json`, you can re-run Grype against it weekly
without re-pulling or re-scanning the image, and the same SBOM becomes the Cosign
attestation predicate for Lab 8. It's the right choice when the SBOM needs to be
signed, stored, or shared as proof of what's inside an image at build time.

Trivy's all-in-one model wins as a single CI step when you just need a fast
pass/fail gate: one command covers OS packages, language dependencies, IaC
misconfigurations, and secrets (it caught a private key in `lib/insecurity.ts`
during this same scan, which Grype's SBOM-only scan has no mechanism to do at all).
For a quick "is this image safe to ship" check without needing a durable SBOM
artifact afterward, Trivy's broader single-pass scope is simpler to wire up.