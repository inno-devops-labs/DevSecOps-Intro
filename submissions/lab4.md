# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1832332 bytes (1.8 MB)
- `juice-shop.spdx.json` component count: 3068

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 48 |
| Medium | 31 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **97** |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-gjcw-v447-2w7q | High | jws | 0.2.6 | 3.0.0 |

### Fix-available rate
Out of the top 10 most critical vulnerabilities, 7 have a fix available, while 3 (including the critical `marsdb` and `libc6` vulnerabilities) do not. Following the triage shortcut (sorting by fix-available AND severity ≥ HIGH), my immediate patching priority would be to upgrade `jsonwebtoken`, `lodash`, `crypto-js`, `libssl3t64` and `jws` to their respective fixed versions, as this provides maximum risk reduction with minimal engineering effort.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 48 | 40 | -8 |
| Medium | 31 | 35 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 90 | 102 | +12 |
*(Note: Grype also found 7 "Negligible" vulnerabilities, which are excluded from the total above for a direct comparison, as Trivy does not use this severity level).*

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:
1. `CVE-2025-57349` (in `messageformat`): Found by Trivy, missed by Grype.
   - **Why:** The most likely reason is a difference in CVE database refresh cadence. Trivy's vulnerability database might be more up-to-date and have ingested this recent 2025 CVE sooner than Grype's default Anchore database snapshot.
2. `CVE-2015-9235` (in `jsonwebtoken`): Found by Trivy as a primary ID, "missed" by Grype.
   - **Why:** Grype actually found this underlying vulnerability but reported it using its ecosystem-specific ID (`GHSA-c7hr-j4mj-j2w6`) as the primary identifier instead of the CVE. Trivy, on the other hand, outputs the CVE ID directly. This reflects different package matching rules and identifier preferences (Grype favoring GHSA for npm packages).

### When would you pick each?
- When does Syft+Grype's **decoupled** model win? 
  Syft+Grype wins when you need SBOM-as-an-attestation to continuously monitor for new vulnerabilities without re-scanning or re-pulling the container image. This decoupled model allows you to generate the SBOM once during the build phase and run Grype against it daily.
- When does Trivy's **all-in-one** win? 
  Trivy wins when you need a simpler, comprehensive CI step that checks for multiple security issues at once. Its broader scope easily covers OS packages, IaC misconfigurations, and hardcoded secrets within a single execution step.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.6
- `bomFormat`: CycloneDX

### Image digest captured
- `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate:
```
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:631714b7-4fa2-45df-a4f7-52773c3731ca",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-15T14:33:32+03:00",
      "tools": {
```