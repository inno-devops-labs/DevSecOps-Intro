# Lab 4 — Submission

- **Name:** [YOUR NAME HERE]
- **Student ID / Username:** [YOUR ID HERE]
- **Date:** [DATE HERE]

## Task 1: Syft SBOM Generation + Grype SCA

### SBOM generation
- `syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json`
- `syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json`

### SBOM stats
- `labs/lab4/juice-shop.cdx.json` component count: **3069**
- `labs/lab4/juice-shop.cdx.json` format: **CycloneDX**
- `labs/lab4/juice-shop.cdx.json` specVersion: **1.6**
- `labs/lab4/juice-shop.spdx.json` package count: **909**

### Grype scan results
- Scan command: `grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json`

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 Grype findings
| CVE / GHSA | Severity | Package | Installed | Fix available |
|------------|----------|---------|-----------|--------------|
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | (none) |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | (none) |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-34180 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-34181 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-34183 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

### Fix available rate
- Among the top 10 findings, **8 of 10** have a fix available.
- This means priority should focus on the remaining critical/unfixed findings first, while also patching widely used library versions like `libssl3t64` and `jsonwebtoken`.

---

## Task 2: Trivy All-in-One Comparison

### Trivy image scan
- Scan command: `trivy image bkimminich/juice-shop:v20.0.0 --severity LOW,MEDIUM,HIGH,CRITICAL --format json --output labs/lab4/trivy.json`
- High/critical table generated to `labs/lab4/trivy.txt`.

### Comparison counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|---:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 104 | 109 | +5 |

### Tool-divergent CVEs
- `GHSA-23c5-xmqv-rm74` was found by Grype only on `minimatch 3.0.5` (High, fix 3.1.4). This suggests Grype's SBOM-based matching map picked up a vulnerable package entry that Trivy's direct image scan did not report.
- `CVE-2015-9235` was found by Trivy only in `jsonwebtoken 0.1.0` (Critical, fixed in 4.2.2). This is likely due to Trivy's direct filesystem/image scan and different vulnerability database mapping compared to Grype's SBOM-based model.

### When to pick each
- Syft+Grype wins when you need a reusable, attestable inventory and want to scan the same SBOM over time without re-pulling the image. It is the better choice for formal SBOM workflows and supply-chain auditing.
- Trivy all-in-one wins when you want a fast, simple pipeline step and broad image-based coverage. It is useful for quick CI checks where you want direct OS/package scanning in one command.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema
- `bomFormat`: **CycloneDX**
- `specVersion`: **1.6**

### Image digest
- `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'`
- `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate
- File produced: `labs/lab4/juice-shop-attestation.json`
- `predicateType`: **https://cyclonedx.org/bom/v1.6**

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
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6"
  }
}
```

### What this enables
- This predicate binds the attestation to the exact image digest and the CycloneDX SBOM contents.
- In Lab 8, `cosign attest --predicate labs/lab4/juice-shop-attestation.json ...` will sign the claim that this SBOM describes `bkimminich/juice-shop:v20.0.0` and that the inventory is authentic.

---

## Submission notes
- Committed artifact: `labs/lab4/juice-shop.cdx.json`
- Supporting artifact: `labs/lab4/juice-shop.spdx.json`
- Bonus artifact: `labs/lab4/juice-shop-attestation.json`
- Scan/output files to keep local only: `labs/lab4/grype-from-sbom.*`, `labs/lab4/trivy.*`

## Commands used
```bash
git switch main && git pull
git switch -c feature/lab4
mkdir -p labs/lab4
# generate SBOMs
syft bkimminich/juice-shop:v20.0.0 -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
syft bkimminich/juice-shop:v20.0.0 -o spdx-json=labs/lab4/juice-shop.spdx.json
# scan SBOM
grype sbom:labs/lab4/juice-shop.cdx.json -o json --file labs/lab4/grype-from-sbom.json
# image scan
trivy image bkimminich/juice-shop:v20.0.0 --severity LOW,MEDIUM,HIGH,CRITICAL --format json --output labs/lab4/trivy.json
# generate attestation predicate
# (contents already produced locally in labs/lab4/juice-shop-attestation.json)
```

## PR checklist
- [ ] Task 1 — `labs/lab4/juice-shop.cdx.json` + `labs/lab4/juice-shop.spdx.json` + Grype counts
- [ ] Task 2 — Trivy comparison + divergent CVEs
- [ ] Bonus — sign-ready attestation predicate
