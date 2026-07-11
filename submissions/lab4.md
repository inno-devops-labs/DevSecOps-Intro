# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **3068**
- `juice-shop.cdx.json` size: **1.7 MB**
- `juice-shop.spdx.json` component count (packages): **909**

```bash
syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json
jq '.components | length' labs/lab4/juice-shop.cdx.json  # 3068
jq '.packages | length' labs/lab4/juice-shop.spdx.json   # 909
```

### Grype severity breakdown

```bash
grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/grype-from-sbom.json
```

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

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

Of the top 10 Critical/High CVEs, **7 out of 10** have a fix version available. Following Lecture 4's triage shortcut (sort by fix-available AND severity ≥ HIGH first), the immediate priority list is: `jsonwebtoken` (both instances — upgrade to 4.2.2), `lodash` (upgrade to 4.17.21), `crypto-js` (upgrade to 4.2.0), and `libssl3t64` (upgrade to 3.5.6). The three without fixes (`libc6`, `marsdb`) require either accepting the risk temporarily, applying compensating controls (WAF, network isolation), or tracking upstream advisories — they cannot be resolved by a simple dependency bump.

---

## Task 2: Trivy Comparison

```bash
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output labs/lab4/trivy.json
jq '[.Results[].Vulnerabilities[]? | .Severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/trivy.json
```

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **104** | **109** | **+5** |

### Why the difference?

1. **GHSA-23c5-xmqv-rm74** (High, `minimatch@3.0.5`) — found by **Grype**, missed by **Trivy**. Grype indexes GitHub Security Advisories (GHSA) natively as first-class identifiers; Trivy's primary database maps findings to CVE IDs from NVD and OS vendor advisories. This GHSA has no corresponding CVE ID assigned yet, so Trivy's scanner simply has no record of it.

2. **CVE-2015-9235** (Critical, `jsonwebtoken@0.1.0`) — found by **Trivy**, missed by **Grype**. This CVE predates Grype's GHSA-sourced record (`GHSA-c7hr-j4mj-j2w6`) that covers the same vulnerability. Grype deduplicates by GHSA alias and surfaces the advisory under the GHSA identifier; Trivy reports the original CVE ID instead. Neither tool is wrong — they surface the same underlying flaw under different identifiers.

### When would you pick each?

**Syft + Grype (decoupled model):** This wins when the SBOM itself is the primary artifact — for example, when you need to attest the inventory (Lab 8: `cosign attest --predicate juice-shop.cdx.json`) and re-scan the same frozen SBOM after new CVEs drop without re-pulling the image. The decoupled model also fits compliance workflows where the SBOM must be handed off to a separate security team or stored in a registry alongside the image signature.

**Trivy (all-in-one):** Trivy wins when you want a single CI step that covers more than just packages — it also scans IaC files (Terraform, Helm charts), Dockerfiles for misconfigurations, embedded secrets, and Kubernetes manifests. For a pipeline that needs breadth over depth with minimal configuration, a single `trivy image` command is operationally simpler than the Syft-generate + Grype-scan two-step.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

```bash
jq '.specVersion, .bomFormat' labs/lab4/juice-shop.cdx.json
```

- `specVersion`: **"1.6"**
- `bomFormat`: **"CycloneDX"**

Syft 1.45.1 generates CycloneDX 1.6 by default — compatible with Cosign's attestation predicate requirements (Lab 8 expects 1.5+).

### Image digest captured

```bash
docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
# bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Attestation predicate (first 30 lines of `juice-shop-attestation.json`)

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
    "serialNumber": "urn:uuid:...",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-18T10:12:...",
      "tools": { ... },
      "component": { "name": "bkimminich/juice-shop", "version": "v20.0.0", ... }
    },
    "components": [ ... 3068 components ... ],
    ...
  }
}
```

### What this enables in Lab 8

When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json`, Cosign signs the entire in-toto Statement v1 envelope with the Lab 8 signing key and pushes the resulting OCI artifact to the registry alongside the image. The signature proves a specific claim: that at the time of signing, this exact image digest (`sha256:fd58bdc9...`) had a known, enumerated software composition — the 3068 components listed in the CycloneDX 1.6 SBOM. Anyone pulling the image later can run `cosign verify-attestation` to confirm that the SBOM was produced and signed by a trusted party and has not been tampered with since, which is exactly the supply-chain transparency guarantee described in Lecture 8 slide 9.
