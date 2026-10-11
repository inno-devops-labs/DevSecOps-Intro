# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1.7M
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown

| Severity   | Count |
|------------|------:|
| Critical   | 7     |
| High       | 51    |
| Medium     | 35    |
| Low        | 4     |
| Negligible | 7     |
| **Total**  | **104** |

### Top 10 CVEs

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | — |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | — |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | — |

### Fix-available rate
Of the top 10 CVEs, 7 have a fix available. Following Lecture 4's triage shortcut — fix-available AND severity ≥ HIGH first — the immediate priority is `jsonwebtoken`, `lodash`, `crypto-js`, and `libssl3t64`, all Critical with known fixes. The three without fixes (`libc6`, `marsdb`, `lodash.set`) require compensating controls (network isolation, WAF rules) until upstream patches arrive.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity   | Grype | Trivy | Δ |
|------------|------:|------:|--:|
| Critical   | 7     | 5     | -2 |
| High       | 51    | 43    | -8 |
| Medium     | 35    | 39    | +4 |
| Low        | 4     | 22    | +18 |
| Negligible | 7     | 0     | -7 |
| **Total**  | **104** | **109** | **+5** |

### Why the difference?

**1. GHSA-23c5-xmqv-rm74** — found by Grype, missed by Trivy.
Grype uses GitHub Advisory Database (GHSA) as a primary source and matches GitHub Security Advisories directly against npm packages. Trivy's node-pkg detector primarily maps against NVD CVE IDs; GHSA-only advisories (without a CVE alias) are often absent from Trivy's DB or matched with a different severity.

**2. CVE-2015-9235** — found by Trivy, missed by Grype.
Trivy found this older JWT vulnerability via its NVD/OSV database mapping for the `jsonwebtoken` package range. Grype deduplicated or superseded it with the newer GHSA entry for the same library, so only the GHSA ID appeared in Grype output. Different deduplication logic between the two DBs causes the same underlying issue to surface under different identifiers.

### When would you pick each?

**Syft + Grype (decoupled):** Use when the SBOM itself is a deliverable — e.g., for compliance, vendor attestation, or Lab 8's Cosign signing workflow. One SBOM can be re-scanned by Grype next month when a new CVE drops, without re-pulling or re-inspecting the image. This model also lets you share the SBOM with a customer or auditor who runs their own scanner.

**Trivy (all-in-one):** Use in CI pipelines where simplicity matters — one command scans the image, IaC files, secrets, and misconfigs in a single step. No intermediate SBOM file to manage. Better suited for fast shift-left gates where breadth (multiple target types) matters more than SBOM portability.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.6"
- `bomFormat`: "CycloneDX"

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

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
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "...",
    "version": 1,
    "metadata": { "...": "..." },
    "components": [ "... 3068 components ..." ]
  }
}
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json`, Cosign wraps the attestation in a DSSE envelope and signs it with the Lab 8 signing key, then pushes the signature to the OCI registry alongside the image. The signed statement proves two things: (1) the exact image identified by its sha256 digest was scanned, and (2) the resulting component inventory (3068 packages) is the claimed bill of materials — cryptographically binding the SBOM to the image at a specific point in time. Any downstream consumer can verify the signature with `cosign verify-attestation` to confirm the SBOM was not tampered with after generation.
