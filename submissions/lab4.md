# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

* `juice-shop.cdx.json` component count: **1846**
* `juice-shop.cdx.json` size: **1504963 bytes**
* `juice-shop.spdx.json` component count: **911**

### Grype severity breakdown

| Severity   |   Count |
| ---------- | ------: |
| Critical   |       7 |
| High       |      52 |
| Medium     |      35 |
| Low        |       4 |
| Negligible |       7 |
| **Total**  | **105** |

### Top 10 CVEs

| CVE                 | Severity | Package      | Installed | Fix     |
| ------------------- | -------- | ------------ | --------- | ------- |
| GHSA-35jh-r3h4-6jhm | High     | lodash       | 2.4.2     | 4.17.21 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0     | 4.2.2   |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0     | 4.2.2   |
| GHSA-87vv-r9j6-g5qv | Medium   | moment       | 2.0.0     | 2.11.2  |
| GHSA-jf85-cpcp-j695 | Critical | lodash       | 2.4.2     | 4.17.12 |
| GHSA-8hfj-j24r-96c4 | High     | moment       | 2.0.0     | 2.29.2  |
| GHSA-p6mc-m468-83gw | High     | lodash.set   | 4.3.2     | none    |
| GHSA-446m-mv8f-q348 | High     | moment       | 2.0.0     | 2.19.3  |
| GHSA-4xc9-xhrj-v574 | High     | lodash       | 2.4.2     | 4.17.11 |
| GHSA-fvqr-27wr-82fm | Medium   | lodash       | 2.4.2     | 4.17.5  |

### Fix-available rate

Out of the top 10 findings, **9 have a fix available** and **1 does not**. I would prioritize fixes that are both fix-available and severity High or Critical first, because they are actionable and reduce the most immediate risk. This matches the Lecture 4 triage shortcut: sort by fix availability and severity ≥ HIGH first.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity   |   Grype |   Trivy |      Δ |
| ---------- | ------: | ------: | -----: |
| Critical   |       7 |       5 |     -2 |
| High       |      52 |      43 |     -9 |
| Medium     |      35 |      39 |     +4 |
| Low        |       4 |      22 |    +18 |
| Negligible |       7 |       0 |     -7 |
| **Total**  | **105** | **109** | **+4** |

### Why the difference?

Grype and Trivy reported different counts because they use different vulnerability databases, package matching logic, severity normalization, and deduplication behavior. In this run, Grype reported more Critical and High findings, while Trivy reported more Medium and Low findings.

Two examples from the Grype top findings are `GHSA-c7hr-j4mj-j2w6` for `jsonwebtoken` and `GHSA-jf85-cpcp-j695` for `lodash`. These differences are likely caused by different advisory sources and matching rules for npm packages, especially when GitHub Security Advisories and CVE-style records are mapped differently by each scanner.

### When would you pick each?

Syft + Grype's decoupled model wins when the SBOM itself is an artifact that needs to be stored, reused, signed, or attached to an image. It is useful for supply chain workflows because one SBOM can be scanned again later when vulnerability databases change.

Trivy's all-in-one model wins when a team wants a simpler CI step with fewer moving parts. It is also useful because Trivy supports broader scanning use cases, including container images, filesystems, IaC, secrets, and misconfigurations.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

* `specVersion`: **1.6**
* `bomFormat`: **CycloneDX**

### Image digest captured

* `docker inspect ... RepoDigests`:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Attestation predicate

First lines of `labs/lab4/juice-shop-attestation.json`:

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
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6"
  }
}
```

### What this enables in Lab 8

In Lab 8, `cosign attest --type cyclonedx --predicate juice-shop-attestation.json` will sign the SBOM predicate for the Juice Shop image digest. This proves that the specific image digest is associated with the CycloneDX SBOM generated in this lab. The signed attestation can later be verified by CI/CD or security tooling to confirm the image's software inventory.
