# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1 835 742 bytes
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown (paste table or JSON)
| Severity   |   Count |
| ---------- | ------: |
| Critical   |       7 |
| High       |      51 |
| Medium     |      35 |
| Low        |       4 |
| Negligible |       7 |
| **Total**  | **104** |


### Top 10 CVEs (paste from jq output)
| CVE                 | Severity | Package      | Installed       | Fix             |
| ------------------- | -------- | ------------ | --------------- | --------------- |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0           | 4.2.2           |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0           | 4.2.2           |
| GHSA-jf85-cpcp-j695 | Critical | lodash       | 2.4.2           | 4.17.12         |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js    | 3.3.0           | 4.2.0           |
| CVE-2026-5450       | Critical | libc6        | 2.41-12+deb13u2 | —               |
| CVE-2026-34182      | Critical | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb       | 0.6.11          | —               |
| GHSA-35jh-r3h4-6jhm | High     | lodash       | 2.4.2           | 4.17.21         |
| GHSA-8hfj-j24r-96c4 | High     | moment       | 2.0.0           | 2.29.2          |
| GHSA-p6mc-m468-83gw | High     | lodash.set   | 4.3.2           | —               |


### Fix-available rate
Out of the top 10 CVEs, 7 have a published fix version (jsonwebtoken, lodash, crypto-js, libssl3t64, moment), while 3 show no fixed version — CVE-2026-5450 (libc6), GHSA-5mrr-rgp6-x4gr (marsdb), and GHSA-p6mc-m468-83gw (lodash.set). Per Lecture 4's triage shortcut, the immediate patch cadence should prioritize fixable Critical and High vulnerabilities first, since they are actionable today and reduce the attack surface fastest. The unfixable items require vendor escalation or compensating controls (e.g., WAF rules, network segmentation) rather than waiting indefinitely for upstream patches.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity   | Grype | Trivy |   Δ |
| ---------- | ----: | ----: | --: |
| Critical   |     7 |     5 |  -2 |
| High       |    51 |    43 |  -8 |
| Medium     |    35 |    39 |  +4 |
| Low        |     4 |    22 | +18 |
| Negligible |     7 |     0 |  -7 |
| **Total**  |   104 |   109 |  +5 |


### Why the difference?
CVE-2026-5450 (libc6, Critical) — found by Grype, missed by Trivy.
Trivy reported only one Debian OS vulnerability (libssl3t64), while Grype surfaced multiple libc6 CVEs including this Critical one. Likely reason: Grype's Debian Security Tracker integration pulls in more unstable/testing branch CVEs for Debian 13, whereas Trivy's OS-detection narrowed the scope to a smaller package set or used a fresher-but-different data slice.
CVE-2026-26996 (minimatch, High) — found by Trivy, missed by Grype.
Trivy detected several 2026-era npm CVEs (e.g., minimatch, tar, multer) that Grype did not list. Likely reason: Trivy consumes GitHub Advisory Database and NVD with a faster refresh cadence for language-specific (npm) packages, while Grype's DB may lag behind for very recent Node.js disclosures.

### When would you pick each?
Syft + Grype (decoupled): This model wins when the SBOM itself must become a long-lived attestation artifact — for example, in Lab 8 where cosign attest will sign the CycloneDX predicate. Decoupling inventory generation from vulnerability scanning means the same SBOM can be re-scanned weeks later without rebuilding the image, and the SBOM travels with the image as a compliance document (Lecture 4: "the SBOM is the answer to the next Log4Shell question").
Trivy (all-in-one): Trivy wins in CI pipelines that need a single binary and a single step to cover containers, secrets, misconfigurations, and IaC. In this scan Trivy also caught hardcoded RSA private keys (AsymmetricPrivateKey) in insecurity.js — a secret finding Grype does not perform — making it the better choice when breadth (vuln + secret + config) matters more than SBOM reusability.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.6"
- `bomFormat`: "CycloneDX"

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 30 lines)
```json
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
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:baaf1acb-018e-4221-aec8-9e620d216fd3",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-18T16:45:38-04:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.42.0"
          }
        ]
      },
      "component": {
        ...
```
When Lab 8 runs cosign attest --type cyclonedx --predicate juice-shop-attestation.json ..., it signs the in-toto Statement v1 envelope (Lecture 8 slide 9). Specifically, the signature covers the binding between the image identity (bkimminich/juice-shop@sha256:fd58...) and the CycloneDX SBOM predicate. This creates a non-repudiable claim: "this SBOM accurately describes the contents of this exact image at this exact digest." Anyone with the public key can verify that the SBOM was not swapped or tampered with after the fact, which is the foundation for supply-chain attestation and Lab 10 DefectDojo ingestion.
