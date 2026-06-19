# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **3068**
- `juice-shop.cdx.json` size: **1832332 bytes (~1.8 MB)**
- `juice-shop.spdx.json` package count: **909**

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

(by status: 89 fixed, 15 not-fixed)

### Top 10 CVEs (by severity rank, with fix availability)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | _(won't fix)_ |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | _(none)_ |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | _(none)_ |

### Fix-available rate
7 of the top 10 ship a fix that is just a version bump, so the triage shortcut — sort by fix-available AND severity ≥ HIGH first — clears most of the critical risk in a single patch wave (jsonwebtoken→4.2.2, lodash→4.17.12/4.17.21, crypto-js→4.2.0, moment→2.29.2, libssl3t64→3.5.6). The 3 without a fix — libc6 CVE-2026-5450 (marked won't-fix), marsdb GHSA-5mrr-rgp6-x4gr, and lodash.set GHSA-p6mc-m468-83gw — drop to a second tier that needs compensating controls or dependency replacement rather than a patch, so they should not block the fast patch cadence on the fixable criticals.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ (Trivy−Grype) |
|----------|------:|------:|----------------:|
| Critical | 7 | 5 | −2 |
| High | 51 | 43 | −8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | **97** | **109** | **+12** |

(Totals exclude Grype's 7 Negligible findings; Trivy does not emit a Negligible class. Trivy debian target reported only 1 OS vulnerability; node-pkg target reported 47.)

### Why the difference?
The divergence is concentrated on the OS (Debian) layer. Trivy's `debian` target found exactly **1** vulnerability, while Grype matched ~25+ CVEs across the same `libssl3t64` / `libc6` / `zlib1g` packages.

1. **CVE-2026-5450** — `libc6`, Critical. **Found by Grype, missed by Trivy.** Trivy reported zero libc6 CVEs for this image.
2. **CVE-2026-34182** — `libssl3t64`, Critical. **Found by Grype, missed by Trivy.** Trivy's libssl3t64 detection surfaced only CVE-2026-45447.

Likely cause: Trivy's Debian scanner is driven by the Debian Security Tracker and suppresses glibc/openssl issues that Debian triages as minor / no-DSA / not-affected, whereas Grype matches installed versions against GHSA/NVD ranges through the Anchore feed and surfaces every version-range hit regardless of distro triage. The inverse shows up at Low severity (Trivy 22 vs Grype 4): Trivy pulls in more low-severity npm advisories, so the totals end up close (97 vs 109) but the composition is very different — Grype skews toward OS packages and High/Critical, Trivy toward more numerous Low/Medium application findings.

### When would you pick each?
- **Syft + Grype (decoupled):** when the SBOM itself is the deliverable. Generate the inventory once, then rescan the same SBOM each time a new CVE lands — no image re-pull, works air-gapped, and the SBOM becomes a durable, signable artifact (the Lab 8 Cosign attestation) that travels with the image as provenance. Wins for supply-chain evidence and repeatable, inventory-driven scanning over time.
- **Trivy (all-in-one):** when you want one binary and one CI step with the broadest scope — image CVEs plus IaC misconfig, secrets, and licenses in a single pass, with distro-aware filtering that trims OS-layer noise. Wins for the simplest pipeline integration and wide coverage when you don't need a standalone SBOM step.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.6"
- `bomFormat`: "CycloneDX"
- `metadata.timestamp`: "2026-06-19T20:41:21+03:00"
- `metadata.tools`: syft 1.45.1 (author: anchore)

### Image digest captured
- `docker inspect ... RepoDigests`: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (first 30 lines of juice-shop-attestation.json)
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
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3502ba7d-b767-4253-a278-39e569548f5a",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T20:41:21+03:00",
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
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, Cosign wraps this in-toto Statement in a DSSE envelope and signs it, cryptographically binding the CycloneDX SBOM (the `predicate`) to the exact image identified by its sha256 digest (the `subject`). The signed claim proves that this specific image — the digest, not just the mutable `v20.0.0` tag — has this exact component inventory, attested by the holder of the signing key. Downstream consumers, and Lab 10's DefectDojo, can verify the signature before trusting the SBOM, turning the inventory into tamper-evident provenance rather than an unsigned text file.
