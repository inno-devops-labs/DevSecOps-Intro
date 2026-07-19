# Lab 4 — Submission

---

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: **3069** (`jq '.components | length' labs/lab4/juice-shop.cdx.json`)
- `juice-shop.cdx.json` size: **1.8M** (`ls -lh labs/lab4/juice-shop.cdx.json`)
- `juice-shop.spdx.json` component count: **909** (`jq '.packages | length' labs/lab4/juice-shop.spdx.json`)
- Syft cataloged **908 packages** in the image (`bkimminich/juice-shop:v20.0.0`, digest `sha256:99779f57113bd47312e8fe7b264ff402eeb46046ad3cd33fb34b8479fd68800c311c7c08a`)

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 48 |
| Medium | 31 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **97** |

Grype status summary: **82 fixed**, **15 not-fixed**, **0 ignored**.

```json
[
  {"severity": "Critical", "count": 7},
  {"severity": "High", "count": 48},
  {"severity": "Low", "count": 4},
  {"severity": "Medium", "count": 31},
  {"severity": "Negligible", "count": 7}
]
```

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
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | — |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-gjcw-v447-2w7q | High | jws | 0.2.6 | 3.0.0 |

### Fix-available rate

Out of the top 10 CVEs, **7 have a fix version listed** (jsonwebtoken, lodash, crypto-js, libssl3t64, jws); **3 do not** (CVE-2026-5450 in libc6 marked won't fix, marsdb GHSA-5mrr-rgp6-x4gr, lodash.set GHSA-p6mc-m468-83gw). Per Lecture 4 triage: sort by **fix-available first**, then **severity ≥ HIGH** — the npm Critical/High items with clear upgrade paths (jsonwebtoken → 4.2.2+, lodash → 4.17.x, crypto-js → 4.2.0) are the fastest patch wins. The three unfixable entries need compensating controls (WAF, input validation) or explicit risk acceptance; distro CVEs in libc6/openssl may require a base-image rebuild when Debian publishes fixes.

---

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | −2 |
| High | 48 | 40 | −8 |
| Medium | 31 | 35 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | −7 |
| **Total** | **97** | **102** | **+5** |

Trivy JSON breakdown:

```json
[
  {"severity": "CRITICAL", "count": 5},
  {"severity": "HIGH", "count": 40},
  {"severity": "LOW", "count": 22},
  {"severity": "MEDIUM", "count": 35}
]
```

### Why the difference?

**CVE 1:** `GHSA-5mrr-rgp6-x4gr` (marsdb 0.6.11, Critical) — found by **Grype**, absent from Trivy’s Critical set (Grype 7 vs Trivy 5 Critical). Marsdb is a niche npm dependency; Grype’s GitHub Advisory DB maps it directly, while Trivy’s matcher may not associate the advisory with the installed component or deduplicates nested `node_modules` differently.

**CVE 2:** `CVE-2019-9192` (libc6, Negligible) — found by **Grype** in the Negligible bucket (7 items total); **Trivy has no Negligible severity** and typically suppresses ancient glibc issues below its reporting threshold. Conversely, Trivy reports **18 more LOW** findings (22 vs 4) — extra Debian/OS CVEs in `libssl3t64`, `zlib1g`, and related distro packages that Grype either rates Negligible, deduplicates across duplicate SBOM components, or does not match to the same package record.

Verify with:

```bash
jq -r '.matches[].vulnerability.id' labs/lab4/grype-from-sbom.json | sort -u > /tmp/grype-cves.txt
jq -r '.Results[].Vulnerabilities[]?.VulnerabilityID' labs/lab4/trivy.json | sort -u > /tmp/trivy-cves.txt
comm -23 /tmp/grype-cves.txt /tmp/trivy-cves.txt | head -5   # Grype-only
comm -13 /tmp/grype-cves.txt /tmp/trivy-cves.txt | head -5   # Trivy-only
```

### When would you pick each?

**Syft + Grype (decoupled):** One SBOM is an immutable inventory artifact — re-scan the same SBOM when new CVEs drop without re-pulling the image; the SBOM becomes a Cosign attestation in Lab 8 (supply-chain proof of what was in the image at build time).

**Trivy (all-in-one):** Single CI step for image + misconfig + secrets; simpler pipeline when you do not need a portable SBOM file for auditors or downstream tools.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: **1.6**
- `bomFormat`: **CycloneDX**

### Image digest captured

```
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Attestation predicate (first ~30 lines)

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
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:…",
    "version": 1,
    "metadata": {
      "timestamp": "…",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            …
```

*(Full file: `labs/lab4/juice-shop-attestation.json` — predicate embeds the complete `juice-shop.cdx.json` BOM.)*

### What this enables in Lab 8

`cosign attest --type cyclonedx --predicate juice-shop-attestation.json` signs an in-toto Statement binding the image digest (subject) to the CycloneDX BOM (predicate). The claim: *this exact image, at this digest, contained these components at scan time* — verifiable supply-chain metadata for consumers and incident response (Log4Shell-style dependency questions).
