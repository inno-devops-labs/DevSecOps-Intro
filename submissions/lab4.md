# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: **3069**
- `juice-shop.cdx.json` size: **1.7 MB**
- `juice-shop.spdx.json` component count (packages): **909**
- `juice-shop.spdx.json` size: **3.0 MB**

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
| CVE-2026-5450       | Critical | libc6        | 2.41-12+deb13u2 | —               |
| CVE-2026-34182      | Critical | libssl3t64   | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb       | 0.6.11          | —               |
| GHSA-35jh-r3h4-6jhm | High     | lodash       | 2.4.2           | 4.17.21         |
| GHSA-8hfj-j24r-96c4 | High     | moment       | 2.0.0           | 2.29.2          |
| GHSA-p6mc-m468-83gw | High     | lodash.set   | 4.3.2           | —               |

### Fix-available rate

Among the top 10 Critical and High CVEs, 7 have an available fix. Per Lecture 4's triage shortcut — attack fixable High+ first — the priority upgrades are `jsonwebtoken` (4.2.2), `lodash` (4.17.21), `crypto-js` (4.2.0), and `libssl3t64` (3.5.6). The three unfixable CVEs (`libc6`, `marsdb`) need compensating controls or risk acceptance, since a simple dependency bump won't close them.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity   |   Grype |   Trivy |      Δ |
| ---------- | ------: | ------: | -----: |
| Critical   |       7 |       5 |     -2 |
| High       |      51 |      43 |     -8 |
| Medium     |      35 |      39 |     +4 |
| Low        |       4 |      22 |    +18 |
| Negligible |       7 |       0 |     -7 |
| **Total**  | **104** | **109** | **+5** |

### Why the difference?

1. **GHSA-23c5-xmqv-rm74** (High, `minimatch@3.0.5`) — caught by **Grype**, invisible to **Trivy**. Grype natively ingests GitHub Security Advisories, while Trivy's scanner maps everything to CVE IDs from NVD and vendor sources. Since this advisory hasn't been assigned a CVE yet, Trivy's database has no matching entry and the vulnerability goes unreported.

2. **CVE-2015-9235** (Critical, `jsonwebtoken@0.1.0`) — caught by **Trivy**, invisible to **Grype**. Grype knows about it but files it under GHSA-c7hr-j4mj-j2w6. Grype's deduplication logic prefers the GHSA alias and drops the older CVE reference. No disagreement on the risk — just different choices about which identifier to display.

### When would you pick each?

**Syft + Grype (decoupled model):** This approach shines when the SBOM is the artifact that matters most — think signing it as an attestation in Lab 8 or re-scanning the same frozen inventory whenever new CVEs surface, no image pull needed. It also maps neatly onto compliance pipelines where the SBOM gets handed off to a separate security team or archived in a registry next to the image signature.

**Trivy (all-in-one):** The all-in-one model shines in CI pipelines where operational simplicity matters more than scan customisation. One tool, one command, one output format — and it covers not just CVEs but also Terraform misconfigurations, leaked secrets, Dockerfile mistakes, and Kubernetes policy violations. When the goal is wide coverage with minimal setup, running one `trivy image` command is far simpler than the two-stage Syft-then-Grype workflow.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: **"1.5"**
- `bomFormat`: **"CycloneDX"**

### Image digest captured

- `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'`:
  `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 30 lines of `juice-shop-attestation.json`)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:284ad5d4-cae7-4b7c-b81c-04d2b020382b",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T21:40:03+10:00",
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

Lab 8's `cosign attest` command signs the full in-toto envelope and pushes it to the registry as an OCI artifact alongside the image. The signature proves a concrete claim: this specific image digest had exactly this SBOM — 3068 components in CycloneDX 1.6 — at the moment of signing. Later, `cosign verify-attestation` lets anyone confirm the SBOM is authentic, untampered, and came from a trusted signer — the supply-chain transparency promise from Lecture 8 slide 9, implemented.
