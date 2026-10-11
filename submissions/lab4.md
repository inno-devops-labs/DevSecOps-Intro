# Lab 4 — SBOM Generation & Software Composition Analysis on Juice Shop

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1.8 MB (1,832,332 bytes)
- `juice-shop.spdx.json` component count: 909
- Syft cataloged: 908 packages, 286 executables, 2,159 file locations

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

### Top 10 CVEs (Critical and High only)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-446m-mv8f-q348 | High | moment | 2.0.0 | 2.19.3 |
| GHSA-4xc9-xhrj-v574 | High | lodash | 2.4.2 | 4.17.11 |
| GHSA-rc47-6667-2j5j | High | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2026-45447 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | — |

### Fix-available rate
Of the top 10 Critical/High CVEs, 9 out of 10 have a fix available — only `lodash.set` (GHSA-p6mc-m468-83gw) has no published fix version. Following Lecture 4's triage shortcut of sorting by fix-available AND severity ≥ HIGH first, the immediate priorities are the two Critical `jsonwebtoken` findings and the Critical `lodash` prototype pollution (GHSA-jf85-cpcp-j695), all of which have fixes available and represent real exploit paths (JWT forgery and prototype pollution are actively exploited vulnerability classes). The high fix-available rate (89 out of 104 total matches) means this image's vulnerability backlog is largely addressable by dependency upgrades rather than requiring architectural changes.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **104** | **109** | **+5** |

### Why the difference?

**1. GHSA-p6mc-m468-83gw (lodash.set prototype pollution) — Grype found it, Trivy did not.**
Grype matched this via the GitHub Advisory database which indexes npm advisories directly against package names. Trivy's node-pkg detector matched fewer lodash sub-packages in this image, likely because it uses a different package resolution strategy — it detected 13 OS-level packages vs Syft's 908 total, suggesting Trivy's node_modules walk was shallower. Different package matching rules, not a DB gap, explains this miss.

**2. CVE-2026-45447 (libssl3t64) — Grype found it as High, Trivy reported it differently.**
Grype pulled this from its daily-refreshed NVD+GitHub Advisory combined DB while Trivy sourced it from the Debian security tracker. The two databases can differ in severity assignment and fix-version awareness for OS-level packages, which is why the counts diverge at the OS layer even when both tools see the same Debian 13.4 base image.

### When would you pick each?

**Syft+Grype decoupled model wins when:**
The SBOM is a first-class artifact that needs to travel with the software — for attestations, compliance handoffs, or incident response. Because the SBOM is generated once and stored (as in this lab, where `juice-shop.cdx.json` goes into the repo and Lab 8 will sign it), re-scanning when new CVEs drop requires only re-running Grype against the existing file with no image access needed. This decoupled pattern also fits SBOM-as-attestation workflows (Cosign + in-toto) and multi-tool pipelines where the same inventory feeds both Grype and a compliance checker simultaneously.

**Trivy all-in-one wins when:**
Speed and simplicity matter more than artifact reuse — for example, a single CI step that needs vuln scanning, secret detection, and IaC misconfiguration checks in one command. Trivy's broader scope (image + filesystem + IaC + secrets + misconfig) makes it the better choice for a developer's local pre-push check or a pipeline stage where installing and coordinating two tools adds unnecessary complexity.
