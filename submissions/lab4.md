
# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

* `juice-shop.cdx.json` component count: 3069
* `juice-shop.cdx.json` size: 1.8M
* `juice-shop.spdx.json` component count: 909

### Grype severity breakdown

| Severity   |   Count |
| ---------- | ------: |
| Critical   |       7 |
| High       |      51 |
| Medium     |      35 |
| Low        |       4 |
| Negligible |       7 |
| **Total**  | **104** |

### Top 10 CVEs

| CVE                 | Severity | Package      | Installed       | Fix             |
| ------------------- | -------- | ------------ | --------------- | --------------- |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0           | 4.2.2           |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0           | 4.2.2           |
| GHSA-jf85-cpcp-j695 | Critical | lodash       | 2.4.2           | 4.17.12         |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js    | 3.3.0           | 4.2.0           |
| CVE-2026-5450       | Critical | libc6        | 2.41-12+deb13u2 | not available   |
| CVE-2026-34182      | Critical | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb       | 0.6.11          | not available   |
| GHSA-35jh-r3h4-6jhm | High     | lodash       | 2.4.2           | 4.17.21         |
| GHSA-8hfj-j24r-96c4 | High     | moment       | 2.0.0           | 2.29.2          |
| GHSA-p6mc-m468-83gw | High     | lodash.set   | 4.3.2           | not available   |

### Fix-available rate

Out of the top 10 CVEs, 7 have a fix available and 3 do not have a fix listed. This means the first patching priority should be vulnerabilities that are both fixable and at least High severity, especially the Critical findings in `jsonwebtoken`, `lodash`, `crypto-js`, and `libssl3t64`. For the unfixed issues, the correct next step is to track upstream fixes, check whether the vulnerable code path is reachable, and consider dependency replacement or compensating controls if the risk is relevant.

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity  |  Grype |   Trivy |       Δ |
| --------- | -----: | ------: | ------: |
| Critical  |      7 |       5 |      -2 |
| High      |     51 |      43 |      -8 |
| Medium    |     35 |      39 |      +4 |
| Low       |      4 |      22 |     +18 |
| **Total** | **97** | **109** | **+12** |

Note: Grype also reported 7 Negligible findings. They are not included in this comparison table because the Trivy scan was filtered to LOW, MEDIUM, HIGH, and CRITICAL severities.

### Why the difference?

1. `GHSA-35jh-r3h4-6jhm` was found by Grype but did not appear under the same ID in the Trivy-only list. This is likely because Grype reports this lodash issue using the GitHub Advisory ID, while Trivy maps the same or related lodash vulnerability to CVE IDs such as `CVE-2021-23337`. This shows that the two scanners may use different advisory identifiers even when they detect issues in the same dependency family.

2. `CVE-2015-9235` was found by Trivy but did not appear under that exact ID in the Grype-only list. Grype reported the related `jsonwebtoken` issue as `GHSA-c7hr-j4mj-j2w6`, while Trivy reported it as a CVE. This difference is most likely caused by different vulnerability databases, identifier normalization rules, and package matching logic.

### When would you pick each?

Syft + Grype is better when the SBOM itself is a first-class artifact. The decoupled model lets me generate the inventory once with Syft, store it, scan it repeatedly with Grype later, and reuse the same CycloneDX SBOM for attestation/signing in Lab 8. This is useful for auditability, incident response, and supply-chain evidence.

Trivy is better when I need a simpler all-in-one CI step. It scans the image directly and can also cover vulnerabilities, secrets, misconfigurations, and other checks in one tool. For a fast CI gate or a lightweight project, Trivy is easier to wire into the pipeline.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

* `specVersion`: `1.6`
* `bomFormat`: `CycloneDX`

### Image digest captured

* `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate

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
    "serialNumber": "urn:uuid:4b9f4f58-c6bf-4e51-a313-2c21cbb6821c",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T16:03:11+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.44.0"
          }
        ]
      }
    }
  }
}
```

The actual `labs/lab4/juice-shop-attestation.json` file contains the full CycloneDX SBOM under the `predicate` field. The snippet above shows the first part of the in-toto statement shape: statement type, image subject, immutable image digest, CycloneDX predicate type, and SBOM metadata.

### What this enables in Lab 8

In Lab 8, `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...` will sign the CycloneDX SBOM as an attestation predicate for the immutable `bkimminich/juice-shop:v20.0.0` image digest. This proves that the specific image digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` is associated with the generated CycloneDX SBOM, instead of relying only on a mutable image tag. This gives Lab 8 a verifiable supply-chain artifact: the image identity, SBOM contents, and attestation claim can be checked together.


