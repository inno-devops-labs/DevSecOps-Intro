# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1.7M
- `juice-shop.spdx.json` package count: 909
- Image scanned: `bkimminich/juice-shop:v20.0.0`

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 CVEs

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 |  |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 |  |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 |  |

### Fix-available rate

Out of the top 10 CVEs, 7 have a fix version available. This means the first patching priority should be vulnerabilities that are both fixable and severity `HIGH` or `CRITICAL`, because those issues can be reduced immediately by upgrading affected packages. This follows the Lecture 4 triage shortcut: sort by fix-available first and then prioritize severity greater than or equal to `HIGH`.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Delta |
|----------|------:|------:|------:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible / Unknown | 7 | 0 | -7 |
| **Total** | 104 | 109 | +5 |

### Why the difference?

#### CVE 1

- CVE: `GHSA-35jh-r3h4-6jhm`
- Found by: Grype
- Missed by: Trivy
- Package: `lodash`
- Installed version: `2.4.2`
- Fix version: `4.17.21`

This difference is likely caused by different advisory database sources and package matching rules. Grype reported this GitHub Security Advisory directly for `lodash`, while Trivy may normalize the same issue differently, report it under another CVE/advisory identifier, or not match this exact package/advisory pair in the same way.

#### CVE 2

- CVE: `CVE-2015-9235`
- Found by: Trivy
- Missed by: Grype
- Package: `jsonwebtoken`
- Installed versions: `0.1.0`, `0.4.0`
- Fix version: `4.2.2`

This difference is likely caused by different vulnerability database metadata and identifier mapping. Trivy reported this as `CVE-2015-9235`, while Grype reported the related `jsonwebtoken` issue as `GHSA-c7hr-j4mj-j2w6` in the top findings. This shows that the tools may detect the same vulnerable package but represent the vulnerability using different advisory IDs.

### When would you pick each?

Syft+Grype is better when I want a decoupled workflow: first generate an SBOM as a reusable inventory, then scan that same SBOM multiple times over time. This is useful for incident response and future attestations, because the SBOM can become evidence that a specific image contained a specific set of components at a specific time.

Trivy is better when I want a simple all-in-one CI step. It can scan the image directly and is also useful because it supports more security checks beyond dependency CVEs, including misconfigurations, secrets, IaC, Kubernetes, and filesystem scans.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: `1.5`
- `bomFormat`: `CycloneDX`

### Image digest captured

- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate preview

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
      "predicate": {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:b129f6a5-441c-484e-ab6b-d7f56a6c7793",
        "version": 1,
        "metadata": {
          "timestamp": "2026-06-19T21:11:38+03:00",
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

### What this enables in Lab 8

The attestation file wraps the CycloneDX SBOM inside an in-toto Statement v1 envelope. In Lab 8, when `cosign attest --type cyclonedx --predicate juice-shop-attestation.json` is used, the signed object will be the claim that the specific Juice Shop image digest is associated with this exact CycloneDX SBOM. This proves that the SBOM belongs to the referenced image digest and allows later verification that the dependency inventory was not changed after signing.
