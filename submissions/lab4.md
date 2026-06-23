# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **3069**
- `juice-shop.cdx.json` size: **1.8M**
- `juice-shop.spdx.json` package count: **909**
- CycloneDX `specVersion`: **1.6**, `bomFormat`: **CycloneDX**

### Grype severity breakdown
| Severity   | Count |
|------------|------:|
| Critical   |     7 |
| High       |    51 |
| Medium     |    35 |
| Low        |     4 |
| Negligible |     7 |
| **Total**  |  **104** |

### Top 10 CVEs (sorted by severity)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | *(no fix)* |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | *(no fix)* |
| GHSA-6g6m-m6h5-w9gf | High | express-jwt | 0.1.3 | 6.0.0 |
| GHSA-rc47-6667-2j5j | High | http-cache-semantics | 3.8.1 | 4.1.1 |
| GHSA-8cf7-32gw-wr33 | High | jsonwebtoken | 0.1.0 | 9.0.0 |

### Fix-available rate
Out of the top 10 Critical/High CVEs, **8 of 10** have a fix available — only `libc6` (CVE-2026-5450) and `marsdb` (GHSA-5mrr-rgp6-x4gr) lack a published fix version. This maps directly onto Lecture 4's triage shortcut: prioritise findings where `severity ≥ HIGH AND fix != ""` first, since those are both exploitable and actionable today. `crypto-js`, `jsonwebtoken`, and `lodash` are all ancient pinned versions with well-known exploits and upstream patches years old — they should be the first patch sprint items.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity  | Grype | Trivy | Δ |
|-----------|------:|------:|--:|
| Critical  |     7 |     5 | -2 |
| High      |    51 |    43 | -8 |
| Medium    |    35 |    39 | +4 |
| Low       |     4 |    22 | +18 |
| Negligible|     7 |     0 | -7 |
| **Total** |**104**|**109**| **+5** |

### Why the difference?

**1. CVE-2015-9235 — found by Trivy, missed by Grype**
Trivy reported `CVE-2015-9235` for `jsonwebtoken`, while Grype filed the same issue under `GHSA-c7hr-j4mj-j2w6`. Both tools found the vulnerability in the same package, but they use different primary identifiers: Trivy anchors on NVD CVE IDs, Grype anchors on GitHub Security Advisory (GHSA) IDs. When doing a simple set-diff on identifiers they appear as unique findings — but they describe the same flaw. This is one of the most common sources of apparent discrepancy between the two tools.

**2. GHSA-23c5-xmqv-rm74 — found by Grype, missed by Trivy**
Grype surfaced `GHSA-23c5-xmqv-rm74` (a GitHub-native advisory with no CVE alias at time of scan), while Trivy did not report it. Trivy's primary source is the OSV/NVD feed which lags GitHub Advisory Database by days-to-weeks for advisories that haven't been assigned a CVE yet. Grype's direct integration with the GitHub Advisory Database means it picks up GHSA-only advisories faster, at the cost of noise when those advisories are later de-duped with existing CVEs.

### When would you pick each?

**Syft + Grype (decoupled model):**
The decoupled pattern wins when the SBOM is itself a deliverable — e.g., when you're producing a CycloneDX attestation for a customer, storing it in an artifact registry, or feeding it into DefectDojo (Lab 10). Generate the SBOM once, re-scan it on demand with Grype whenever the CVE DB refreshes, without re-pulling or re-analysing the image. The SBOM also serves as the predicate for Cosign signing (Lab 8), giving you a tamper-evident inventory that can be verified independently of the scanner.

**Trivy (all-in-one):**
Trivy wins for a fast, single-step CI gate where you don't need the SBOM as a persistent artefact. It bundles image scanning, IaC misconfiguration detection, secret scanning, and k8s manifest auditing in one binary and one command — far less glue code in the pipeline. The trade-off is that if you want historical re-scans against the same image snapshot you have to re-pull and re-scan from scratch each time.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **"1.6"**
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
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:30ed21ce-8e69-4afc-bccd-815f8901a029",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-18T17:17:55+03:00",
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
    ...
  }
}
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, Cosign wraps this JSON in a DSSE envelope and signs it with your Sigstore/SSH key, then pushes the signature to the OCI registry alongside the image. What is being signed is the *claim* that **this specific image digest** (`sha256:fd58...`) has the **exact set of components listed in the CycloneDX SBOM**. Anyone who later pulls the image can run `cosign verify-attestation` to confirm that the SBOM was produced by a trusted party and has not been tampered with — closing the gap between "we have an SBOM" and "we can prove this SBOM corresponds to this image and was not altered after the fact" (Lecture 8 slide 9: non-repudiation at the supply-chain level).
