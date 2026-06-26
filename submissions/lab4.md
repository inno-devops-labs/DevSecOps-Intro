# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1832332
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown (paste table or JSON)
```
[
  {
    "severity": "Critical",
    "count": 7
  },
  {
    "severity": "High",
    "count": 51
  },
  {
    "severity": "Low",
    "count": 4
  },
  {
    "severity": "Medium",
    "count": 35
  },
  {
    "severity": "Negligible",
    "count": 7
  }
]
```

### Top 10 CVEs (paste from jq output)
```
[
  {
    "cve": "GHSA-c7hr-j4mj-j2w6",
    "severity": "Critical",
    "package": "jsonwebtoken",
    "version": "0.1.0",
    "fix": "4.2.2"
  },
  {
    "cve": "GHSA-c7hr-j4mj-j2w6",
    "severity": "Critical",
    "package": "jsonwebtoken",
    "version": "0.4.0",
    "fix": "4.2.2"
  },
  {
    "cve": "GHSA-jf85-cpcp-j695",
    "severity": "Critical",
    "package": "lodash",
    "version": "2.4.2",
    "fix": "4.17.12"
  },
  {
    "cve": "GHSA-xwcq-pm8m-c4vf",
    "severity": "Critical",
    "package": "crypto-js",
    "version": "3.3.0",
    "fix": "4.2.0"
  },
  {
    "cve": "CVE-2026-5450",
    "severity": "Critical",
    "package": "libc6",
    "version": "2.41-12+deb13u2",
    "fix": ""
  },
  {
    "cve": "CVE-2026-34182",
    "severity": "Critical",
    "package": "libssl3t64",
    "version": "3.5.5-1~deb13u2",
    "fix": "3.5.6-1~deb13u2"
  },
  {
    "cve": "GHSA-5mrr-rgp6-x4gr",
    "severity": "Critical",
    "package": "marsdb",
    "version": "0.6.11",
    "fix": ""
  },
  {
    "cve": "GHSA-35jh-r3h4-6jhm",
    "severity": "High",
    "package": "lodash",
    "version": "2.4.2",
    "fix": "4.17.21"
  },
  {
    "cve": "GHSA-8hfj-j24r-96c4",
    "severity": "High",
    "package": "moment",
    "version": "2.0.0",
    "fix": "2.29.2"
  },
  {
    "cve": "GHSA-p6mc-m468-83gw",
    "severity": "High",
    "package": "lodash.set",
    "version": "4.3.2",
    "fix": ""
  }
]

```

### Fix-available rate
Out of the top 10 CVEs, **7 have a fix available**. This means we can immediately remediate the majority of critical/high vulnerabilities, aligning with Lecture 4's triage shortcut: prioritize issues where **severity ≥ HIGH and fix-available = true**. The remaining 3 (two critical, one high) lack fixes, so we must rely on mitigations or monitoring while awaiting patches.

## Task 2: Trivy Comparison

### Comparison of findings

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 3 | 43 | +40 |
| Medium | 0 | 39 | +39 |
| Low | 0 | 22 | +22 |
| **Total** | 10 | 109 | +99 |

### Reasons for discrepancy

1. **CVE-2026-45447 (libssl3t64)** – Trivy detected it, Grype did not.  
   - Trivy refreshes its vulnerability database daily, while Grype uses a different update schedule. This CVE is recent (2026), so Trivy had it already indexed, but Grype’s feed had not yet included it.

2. **Private keys** – Trivy flagged 2 occurrences (in `insecurity.js` and `insecurity.ts`); Grype reported none.  
   - Grype is strictly a vulnerability scanner; Trivy is a multi‑purpose tool that also performs **secret detection** and configuration checks, so it catches things like embedded keys that Grype ignores.

Overall, Trivy reported 99 additional issues plus the two secrets. This is because Trivy scans **every Node module** (over 109 packages) in detail, whereas Grype typically focuses on direct dependencies and does not traverse deeper transitive trees as exhaustively. Additionally, Trivy’s built‑in secret and misconfiguration scanning adds extra coverage.

### When to choose each approach

**Syft + Grype (decoupled)** – best when you need a **verifiable SBOM** as an artifact. Generate an SBOM once at build time, sign it, and later re‑scan it against updated vulnerability feeds without re‑analysing the image. This aligns well with compliance frameworks (e.g., SLSA) and supply chain auditing.

**Trivy (all‑in‑one)** – ideal for a **single CI step** that covers vulnerabilities, secrets, and misconfigurations. It offers quicker onboarding and broader detection out‑of‑the‑box – as demonstrated by its ability to find private keys that Grype completely missed.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.6"
- `bomFormat`: "CycloneDX"

### Image digest captured
- `docker inspect ... RepoDigests`: `sha256:e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9`

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:1ce6cba0-7534-42e7-8656-a518ceab66c7",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-18T20:46:09+03:00",
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
        "bom-ref": "pkg:oci/bkimminich/juice-shop@sha256:e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9?repository_url=index.docker.io%2Fbkimminich%2Fjuice-shop",
        "type": "container",
        "name": "juice-shop",
        "version": "v20.0.0"
      }
    },
    "components": [
      {
        "bom-ref": "pkg:github/andyet/spacejam@1.6.0?package_id=bWFpbg%3D%3D",
        "type": "library",
        "name": "spacejam",
        "version": "1.6.0",
        "purl": "pkg:github/andyet/spacejam@1.6.0"
      }
    ]
  }
}
```
### What this enables in Lab 8
When Lab 8 runs cosign attest --type cyclonedx --predicate juice-shop-attestation.json ..., it cryptographically signs the entire attestation statement (the SBOM + image metadata) using your private key. This creates a non‑repudiable claim that the container image identified by its specific digest is provably linked to this exact CycloneDX SBOM. In terms of Lecture 8 slide 9, this moves the SBOM from an external artifact to an intoto attestation attached to the image itself, allowing downstream consumers (like policy controllers or defect‑dojo) to cryptographically verify the provenance of the software supply chain — proving not just what is in the image, but that the declared SBOM genuinely corresponds to the published image.
