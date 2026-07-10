# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1832321 bytes (~1.8 MB)
- `juice-shop.spdx.json` component count: 908 packages

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 8 |
| High | 51 |
| Medium | 36 |
| Low | 6 |
| Negligible | 7 |
| **Total** | 108 |

### Top 10 CVEs (by severity)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (no fix) |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-mp2f-45pm-3cg9 | Critical | decompress | 4.2.1 | (no fix) |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (no fix) |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |

### Fix-available rate
Seven of the top 10 findings have a fix available (only `libc6` CVE-2026-5450, `decompress`
GHSA-mp2f-45pm-3cg9, and `marsdb` GHSA-5mrr-rgp6-x4gr have no upstream patch). Applying Lecture 4's
triage shortcut — sort by *fix-available AND severity ≥ High* first — the immediate patch batch is
the four fixable Criticals (jsonwebtoken → 4.2.2, lodash → 4.17.12, crypto-js → 4.2.0, libssl3t64 →
3.5.6), since each is both high-impact and one dependency bump away from resolution. The three
no-fix Criticals drop to a separate track: they can't be patched, so they need compensating
controls or risk-acceptance with expiry rather than blocking the patch cadence — which is exactly
the kind of split DefectDojo will formalize in Lab 10.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ (Trivy−Grype) |
|----------|------:|------:|----:|
| Critical | 8 | 12 | +4 |
| High | 51 | 103 | +52 |
| Medium | 36 | 79 | +43 |
| Low | 6 | 57 | +51 |
| **Total** | 101 | 251 | +150 |

### Why the difference?
**CVE-2023-46233 / GHSA-xwcq-pm8m-c4vf (crypto-js) — found by BOTH, but under different IDs.**
Trivy reports it as `CVE-2023-46233`; Grype reports the same flaw as `GHSA-xwcq-pm8m-c4vf`. These
are the same advisory cross-referenced in the GitHub Advisory Database — the divergence is purely
identifier namespace (CVE number vs GHSA ID), not a real detection gap. This shows why raw ID
matching across tools is unreliable without normalization.

**NSWG-ECO-17 / NSWG-ECO-428 (jsonwebtoken, base64url) — found only by Trivy.**
Trivy carries Node Security Working Group ecosystem advisories (`NSWG-ECO-*`), a source Grype's
GHSA/CVE-centric database does not track at all. For the same `jsonwebtoken` package Grype returns
only GHSA IDs and never the NSWG-ECO entries, so these advisories appear exclusively in Trivy —
a case of different database *sources*, not just different refresh cadence. Combined with Trivy's
more aggressive matching on Debian OS packages (`libc6`, `libssl3t64`, `perl-base`), this is what
drives Trivy's +150 total.

### When would you pick each?
**Syft+Grype (decoupled) wins** when the SBOM itself is a durable artifact you want to reuse. You
generate the inventory once with Syft, then re-scan that same SBOM with Grype every time a new CVE
drops — no re-pulling the image. The SBOM also becomes a signable attestation (Lab 8 signs exactly
this `juice-shop.cdx.json` with Cosign), so the inventory doubles as supply-chain evidence, and
tooling can evolve independently of scanning.

**Trivy (all-in-one) wins** when you want one simple CI step with the broadest scope. A single
`trivy image` call covers OS + language CVEs, and the same binary also scans IaC misconfigurations
(Checkov-style), secrets, and licenses — no SBOM plumbing to maintain. For a fast pipeline gate or
a team that wants one tool instead of a Syft→Grype chain, Trivy's convenience and wider default
coverage (visible here as +150 findings) is the pragmatic choice.
