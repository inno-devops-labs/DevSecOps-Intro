# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: ~1.5 MB (1,504,963 bytes)
- `juice-shop.spdx.json` package count: 911
- Syft cataloged 910 packages in the image

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 6 |
| High | 41 |
| Medium | 27 |
| Low | 2 |
| Negligible | 7 |
| **Total** | 83 |

By fix status: 67 fixed, 16 not-fixed.

### Top 10 CVEs (by risk, Critical/High first)
| CVE / GHSA | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (no fix) |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (won't fix) |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | (no fix) |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-3h5v-q93c-6h6q | High | ws | 7.4.6 | 7.5.10 |
| GHSA-6g6m-m6h5-w9gf | High | express-jwt | 0.1.3 | 6.0.0 |

### Fix-available rate
Out of these top 10, 7 have a fix available (the three exceptions are marsdb, lodash.set, and the libc6 OS-level CVE marked "won't fix"). Applying Lecture 4's triage shortcut — *sort by fix-available AND severity ≥ HIGH first* — the immediate priorities are the fixable Critical/High npm packages (jsonwebtoken → 4.2.2, lodash → 4.17.21, crypto-js → 4.2.0, ws → 7.5.10, express-jwt → 6.0.0), because they give the biggest risk reduction for the least effort. The no-fix items (marsdb, lodash.set) need a different strategy — replacing or removing the dependency rather than bumping a version.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 6 | 5 | -1 |
| High | 41 | 39 | -2 |
| Medium | 27 | 31 | +4 |
| Low | 2 | 12 | +10 |
| Negligible | 7 | 0 | -7 |
| **Total** | 83 | 87 | +4 |

### Why the difference?
1. **CVE-2025-65945** (jws, HIGH) — found by **Trivy**, not in Grype's output. Likely Trivy's CVE DB had this newer advisory mapped to the installed jws version while Grype's matching didn't surface it on this run (different DB refresh cadence and advisory sources).
2. **GHSA-vpq2-c234-7xj6** (@tootallnate/once, Low) — found by **Grype**, not reported by Trivy. Grype leans heavily on the GitHub Security Advisory database for fine-grained npm transitive packages, whereas Trivy's npm matching surfaced a different set at the low end.

A structural reason for the totals: Grype reports a "Negligible" bucket (7) that Trivy folds into LOW, and Trivy surfaced far more LOW findings (12 vs 2). So the two tools don't just disagree per-CVE — they bucket severities differently, which inflates Trivy's Medium/Low counts relative to Grype.

### When would you pick each?
- **Syft + Grype (decoupled)** wins when the SBOM itself is a first-class artifact: you generate it once, sign it (Lab 8 / Cosign attestation), store it, and re-scan that same SBOM whenever a new CVE drops — no need to re-pull or rebuild the image. It fits an SBOM-as-attestation supply-chain workflow and gives reproducible, auditable inventory.
- **Trivy (all-in-one)** wins when you want one simple CI step with the broadest scope: in a single command it scans not just OS+language CVEs but also secrets, IaC misconfigurations, and licenses (we even saw it flag the embedded RSA private key). For a quick, comprehensive gate in a pipeline with minimal wiring, Trivy is the lower-friction choice.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.6
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (head of juice-shop-attestation.json)
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
      "predicate": { ... full CycloneDX SBOM ... }
    }

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json`, Cosign cryptographically signs the binding between the **image** (identified by its sha256 digest in `subject`) and the **SBOM** (carried in `predicate`). The signed claim being made is: "this exact image, by this exact digest, has this exact software bill of materials, and I — the holder of the signing key — vouch for it." Anyone can later run `cosign verify-attestation` to confirm the SBOM was not tampered with and genuinely corresponds to that image, which is what turns an SBOM from a loose file into a trustworthy supply-chain attestation (Lecture 8 slide 9).