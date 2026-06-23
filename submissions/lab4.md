# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

Image: `bkimminich/juice-shop:v20.0.0` (digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`).
Tools: Syft 1.45.1, Grype 0.114.0 (DB schema v6.1.7, built 2026-06-18).

### SBOM stats
- `juice-shop.cdx.json` component count: **1846**
- `juice-shop.cdx.json` size: **1,504,963 bytes** (~1.5 MB)
- `juice-shop.spdx.json` package count: **911**
- `juice-shop.spdx.json` size: **2,369,824 bytes** (~2.4 MB)

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **105** |

By fix status: **89 fixed, 16 not-fixed**.

### Top 10 CVEs (by Grype risk score)
| Advisory / CVE | Severity | Package | Installed | Fix |
|----------------|----------|---------|-----------|-----|
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-87vv-r9j6-g5qv | Medium | moment | 2.0.0 | 2.11.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | _(no fix)_ |
| GHSA-446m-mv8f-q348 | High | moment | 2.0.0 | 2.19.3 |
| GHSA-4xc9-xhrj-v574 | High | lodash | 2.4.2 | 4.17.11 |
| GHSA-fvqr-27wr-82fm | Medium | lodash | 2.4.2 | 4.17.5 |

### Fix-available rate
9 of the top 10 have a fix available (only `lodash.set` GHSA-p6mc-m468-83gw has none), and across the whole scan 89/105 (~85%) are fixable. Following Lecture 4's triage shortcut — *sort by fix-available AND severity ≥ HIGH first* — the priority is the cluster of outdated npm libraries (`lodash`, `jsonwebtoken`, `moment`), where a single version bump clears several High/Critical findings at once. The handful of no-fix items (e.g. `lodash.set`) drop down the queue: they can't be patched, so they're handled by compensating controls or dependency replacement rather than blocking the patch cadence.

---

## Task 2: Trivy Comparison

Trivy v0.71.1, direct image scan (`trivy image`). Detected OS: Debian 13.4, 13 OS packages + 1 language manifest (npm).

### Side-by-side counts
| Severity | Grype | Trivy | Δ (Trivy − Grype) |
|----------|------:|------:|--:|
| Critical | 7 | 5 | −2 |
| High | 52 | 43 | −9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | −7 |
| **Total** | **105** | **109** | **+4** |

Trivy has no "Negligible" bucket (it folds those into Low/Unknown), which alone explains the Low column swing (+18) and the missing Negligible row.

### Why the difference? (two tool-divergent findings)
1. **CVE-2019-10744 (lodash) — found by Trivy, "missing" in Grype.** Grype *does* flag the same defect, but under its GitHub Security Advisory ID **GHSA-jf85-cpcp-j695**, not the CVE ID. So this is not a true miss — it's an **identifier-namespace difference**: for npm packages Grype prefers GHSA IDs while Trivy prefers CVE IDs. Most of the "Trivy-only" list (`CVE-2020-8203`, `CVE-2021-23337`, `CVE-2018-3721` …) are lodash/npm CVEs that map 1:1 to Grype's GHSA findings once aliases are normalized.
2. **CVE-2022-4899 (libzstd, Debian) — found by Grype, missing in Trivy.** This is a genuine divergence on an OS package. Trivy leans on the Debian security tracker's status (this zstd CVE is treated as no-DSA / not-fixed for the stable release), so it suppresses it, whereas Grype's matcher still surfaces it as High. Same idea drives Grype's 7 Negligible glibc CVEs (e.g. `CVE-2018-20796`) that Trivy doesn't report at all — different DB curation and "won't fix" handling.

In short: the headline count gap is mostly **identifier aliasing (GHSA vs CVE) for npm** plus **different OS-CVE curation policies**, not the tools genuinely seeing different software.

### When would you pick each?
- **Syft + Grype (decoupled)** wins when the SBOM itself is a first-class artifact: you generate one CycloneDX SBOM, sign it as an attestation (Lab 8), and re-scan that same inventory every time a new CVE drops — no image re-pull needed. It's the right model for supply-chain provenance and "are we affected by the next Log4Shell?" incident response.
- **Trivy (all-in-one)** wins when you want one simple CI step with the broadest scope: a single `trivy image` covers OS + language CVEs *plus* secrets and misconfiguration in one pass. Fewer moving parts, faster to wire into a pipeline, and good as a default gate when you don't need a standalone signed SBOM.
