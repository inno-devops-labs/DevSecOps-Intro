# Lab 4 — Submission

> Environment note: Docker daemon was not running, so the image was read **directly from
> the registry** (`syft registry:...`, `trivy image ...`) instead of the local Docker
> daemon. Results are identical — these tools pull the manifest + layers anonymously from
> Docker Hub. Tool versions: Syft 1.45.1, Grype 0.114.0, Trivy 0.71.1, jq 1.8.1.

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **1846**
- `juice-shop.cdx.json` size: **1 504 963 bytes (~1.5 MB)**
- `juice-shop.spdx.json` component count (packages): **911**

> The CycloneDX count (1846) is higher than SPDX (911) because Syft's CycloneDX output
> also emits OS/file-level and relationship components, while the SPDX `packages` array
> counts resolved packages only.

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **105** |

### Top 10 CVEs (by severity, Critical → High)
| CVE / Advisory | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | _(no fix)_ |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | _(no fix)_ |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-446m-mv8f-q348 | High | moment | 2.0.0 | 2.19.3 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | _(no fix)_ |

### Fix-available rate
Across **all 105** findings, **89 have a fix available (85%)**. Among the **top 10** above,
**7 of 10** have a fixed version. Following Lecture 4's triage shortcut — *sort by
fix-available AND severity ≥ HIGH first* — the immediate work queue is the fixable Criticals
(`jsonwebtoken`, `lodash`, `crypto-js`, `libssl3t64`): these are cheap, high-impact dependency
bumps. The three no-fix Criticals (`libc6`, `marsdb`, and `lodash.set` at High) drop to a
second queue requiring compensating controls or dependency replacement rather than a version
bump. The high fix-available rate (85%) means our patch cadence is the limiting factor, not
upstream — most of this debt is closable today by updating `package.json`.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ (Trivy−Grype) |
|----------|------:|------:|--:|
| Critical | 7 | 5 | −2 |
| High | 52 | 43 | −9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | −7 |
| **Total** | **105** | **109** | **+4** |

> Trivy has **no "Negligible" tier** — Grype's 7 Negligibles map into Trivy's LOW/UNKNOWN
> buckets, which partly explains Trivy's much larger LOW count (22 vs 4). Totals are close
> (105 vs 109) but the *distribution* differs because the tools grade severity from different
> sources.

### Why the difference? — two tool-divergent findings

**1. CVE-2019-10744 — `lodash` prototype pollution (Critical)**
- **Trivy found it** as `CVE-2019-10744`; **Grype "missed" the CVE id** — but actually reported
  the *exact same finding* (lodash 2.4.2 → fix 4.17.12) under the GitHub advisory id
  **`GHSA-jf85-cpcp-j695`**, whose `relatedVulnerabilities` field lists `CVE-2019-10744`.
- **Why:** this is an **identifier-namespace difference**, not a coverage gap. Grype prefers
  **GHSA** IDs for the npm ecosystem (GitHub Advisory DB); Trivy normalizes the same advisory
  to its **CVE** alias. Comparing tools by raw ID overstates how much they actually diverge.

**2. CVE-2022-4899 — `libzstd` / zstd buffer overflow (High)**
- **Grype found it** (OS package `libzstd 1.5.7+dfsg-1`, fix state `wont-fix`); **Trivy reported
  nothing for zstd at all**.
- **Why:** an **OS-package DB / fix-status difference**. Trivy follows the **Debian Security
  Tracker**, which marks this won't-fix / not-affected for the distro package and therefore
  suppresses it. Grype matched against broader **NVD** data — and it even warned the image's
  distro looked **EOL / "unknown"**, causing it to fall back to looser NVD matching that keeps
  the finding visible.

### When would you pick each?
- **Syft + Grype (decoupled) wins** when the SBOM is itself an artifact you want to keep, sign,
  and re-scan over time. Generate the SBOM once; when a new CVE drops next month, re-run Grype
  against the *same* stored SBOM (no image re-pull) to instantly answer "are we affected?". The
  SBOM also becomes a **signed attestation** (Lab 8) and audit/compliance evidence — the
  inventory and the scan are separate, reusable steps.
- **Trivy (all-in-one) wins** when you want **one simple CI step with the broadest scope**:
  besides image CVEs it also scans IaC misconfig, secrets, and licenses in a single command,
  with no SBOM to manage. Ideal for a fast PR gate where simplicity beats artifact reuse.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **"1.6"**
- `bomFormat`: **"CycloneDX"**
- `metadata.timestamp`: present (`2026-06-19T21:49:09+05:00`)
- `metadata.tools`: present (`syft 1.45.1`)

(Already ≥ 1.5, so no Syft re-run with `@1.5` was needed. 1.6 is accepted by Cosign in 2026.)

### Image digest captured
Docker daemon was down, so the digest was read from the registry manifest (the same value
`docker inspect ... RepoDigests` returns):
```
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Attestation predicate (`juice-shop-attestation.json`, first lines)
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
  "predicate": { "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [ ... 1846 ... ] }
}
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`,
Cosign wraps this in-toto Statement in a **DSSE envelope** and signs it. What is being signed
is the **binding between a specific image** (identified by its immutable digest
`sha256:fd58…418b0`, not the mutable `v20.0.0` tag) **and its exact bill of materials** — all
1846 components. The signature proves a verifiable claim: *"this SBOM is the authentic
inventory of this exact image, attested by the holder of this key."* A consumer can later
`cosign verify-attestation` and trust the SBOM's provenance before using it for incident
response (e.g. the next Log4Shell "do we depend on this library?" question), because the
digest-pinned subject makes tag-swapping or SBOM-tampering detectable.
