# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: `3069`
- `juice-shop.cdx.json` size: `1.8M`
- `juice-shop.spdx.json` component count: `909`

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-87vv-r9j6-g5qv | Medium | moment | 2.0.0 | 2.11.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | |
| GHSA-446m-mv8f-q348 | High | moment | 2.0.0 | 2.19.3 |
| GHSA-4xc9-xhrj-v574 | High | lodash | 2.4.2 | 4.17.11 |
| GHSA-fvqr-27wr-82fm | Medium | lodash | 2.4.2 | 4.17.5 |

### Fix-available rate
Out of the top 10 CVEs, 9 have a fix available. This indicates that patching existing dependencies should be prioritized before spending effort on deeper investigations. Following the Lecture 4 triage shortcut, vulnerabilities that are both HIGH/CRITICAL severity and have an available fix should be remediated first, as they provide the fastest risk reduction.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity   | Grype | Trivy |   Δ |
| ---------- | ----: | ----: | --: |
| Critical   |     7 |     5 |  -2 |
| High       |    51 |    35 | -16 |
| Medium     |    35 |    39 |  +4 |
| Low        |     4 |    22 | +18 |
| Negligible |     7 |     0 |  -7 |
| **Total**  |   104 |   101 |  -3 |

### Why the difference?

#### Example 1
- CVE ID: GHSA-35jh-r3h4-6jhm
- Found by: Grype
- Missed by: Trivy

Likely reason: Grype matched this vulnerability through GitHub Security Advisory (GHSA) metadata present in the SBOM, while Trivy relied on a different vulnerability database and matching strategy. Differences in advisory sources and package matching rules can lead to one tool reporting a finding that the other omits.

#### Example 2
- CVE ID: CVE-2021-23337
- Found by: Trivy
- Missed by: Grype

Likely reason: Trivy's vulnerability database contained a mapping for this package/version combination that was not present in the Grype database at scan time. Different database refresh cadence and vulnerability enrichment processes commonly produce small discrepancies between scanners.

### When would you pick each?

#### Syft + Grype (decoupled model)

I would choose Syft and Grype when I need a reusable SBOM that can be scanned multiple times without re-accessing the original image. This approach is useful for supply-chain workflows, artifact attestations, and later verification steps because the SBOM becomes a portable security artifact that can be signed and distributed independently.

#### Trivy (all-in-one model)

I would choose Trivy when I want a simple CI/CD security step with minimal setup. Trivy can scan containers, IaC, secrets, and misconfigurations using a single tool, making it convenient for automated pipelines and quick security checks.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: `1.6`
- `bomFormat`: `CycloneDX`

### Image digest captured
- `docker inspect bkimminich/juice-shop:v20.0.0 \
| jq -r '.[0].RepoDigests[]'`:\
output:\
`bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)

```
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
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:fafd7525-1236-4b4f-9c6e-d69e4bec0ced",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T17:51:02+03:00",
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