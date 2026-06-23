# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **1846**
- `juice-shop.cdx.json` size: 1.5 MB (1,504,963 bytes)
- `juice-shop.spdx.json` component count: **911**

### Grype severity breakdown
```json
[
  {
    "severity": "Critical",
    "count": 7
  },
  {
    "severity": "High",
    "count": 52
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

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **105** |

### Top 10 CVEs (from Grype)
```json
[
  {
    "cve": "GHSA-c7hr-j4mj-j2w6",
    "severity": "Critical",
    "package": "jsonwebtoken",
    "version": "0.1.0",
    "fix": ["4.2.2"]
  },
  {
    "cve": "GHSA-c7hr-j4mj-j2w6",
    "severity": "Critical",
    "package": "jsonwebtoken",
    "version": "0.4.0",
    "fix": ["4.2.2"]
  },
  {
    "cve": "GHSA-jf85-cpcp-j695",
    "severity": "Critical",
    "package": "lodash",
    "version": "2.4.2",
    "fix": ["4.17.12"]
  },
  {
    "cve": "GHSA-xwcq-pm8m-c4vf",
    "severity": "Critical",
    "package": "crypto-js",
    "version": "3.3.0",
    "fix": ["4.2.0"]
  },
  {
    "cve": "CVE-2026-5450",
    "severity": "Critical",
    "package": "libc6",
    "version": "2.41-12+deb13u2",
    "fix": []
  },
  {
    "cve": "CVE-2026-34182",
    "severity": "Critical",
    "package": "libssl3t64",
    "version": "3.5.5-1~deb13u2",
    "fix": ["3.5.6-1~deb13u2"]
  },
  {
    "cve": "GHSA-5mrr-rgp6-x4gr",
    "severity": "Critical",
    "package": "marsdb",
    "version": "0.6.11",
    "fix": []
  },
  {
    "cve": "GHSA-35jh-r3h4-6jhm",
    "severity": "High",
    "package": "lodash",
    "version": "2.4.2",
    "fix": ["4.17.21"]
  },
  {
    "cve": "GHSA-8hfj-j24r-96c4",
    "severity": "High",
    "package": "moment",
    "version": "2.0.0",
    "fix": ["2.29.2"]
  },
  {
    "cve": "GHSA-p6mc-m468-83gw",
    "severity": "High",
    "package": "lodash.set",
    "version": "4.3.2",
    "fix": []
  }
]
```

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | none |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | none |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | none |

### Fix-available analysis
Out of the top 10 CVEs, 7 have fixes available (70%), with only libc6 (CVE-2026-5450), marsdb (GHSA-5mrr-rgp6-x4gr), and lodash.set (GHSA-p6mc-m468-83gw) having no fix. Following Lecture 4's triage shortcut—sort by fix-available AND severity ≥ HIGH first—the immediate priorities are: (1) jsonwebtoken 0.1.0/0.4.0 → 4.2.2 (Critical, verification bypass), (2) lodash 2.4.2 → 4.17.12 (Critical, prototype pollution), and (3) crypto-js 3.3.0 → 4.2.0 (Critical, PBKDF2 weakness). These three Critical vulnerabilities with available fixes represent the highest ROI for patching, as they address authentication bypass and cryptographic weaknesses that directly impact the application's security posture. The two Critical vulnerabilities without fixes (libc6 and marsdb) require either OS-level updates or application code changes to remove the dependency.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 52 | 43 | -9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **105** | **109** | **+4** |

### Why the difference?

**1. CVE-2026-5450 (libc6, Critical) — Found by Grype, missed by Trivy**

This is a Critical vulnerability in the GNU C Library (libc6) specific to Debian 13. Grype's database includes Debian Security Tracker advisories with more granular severity classifications for OS-level packages, while Trivy may have classified this as High or not yet ingested the advisory. The difference likely stems from different CVE database refresh cadences and severity mapping logic between the two tools' vulnerability databases.

**2. CVE-2026-45447 (libssl3t64, HIGH in Trivy vs CVE-2026-34182 Critical in Grype) — Different severity classification**

Both tools detected OpenSSL vulnerabilities, but Grype classified CVE-2026-34182 as Critical while Trivy classified CVE-2026-45447 as High. This demonstrates that even when both tools detect the same underlying issue, they may use different CVE IDs and severity mappings. Grype's use of GitHub Security Advisories (GHSAs) alongside NVD data can result in more aggressive severity classifications for recent vulnerabilities, while Trivy's reliance on multiple vendor advisories may apply more conservative severity ratings.

### When would you pick each?

**Syft+Grype's decoupled model wins** when you need SBOM-as-attestation for supply chain security (Lecture 4 + Lab 8). By generating the SBOM once with Syft and scanning it repeatedly with Grype, you can answer "are we affected by Log4Shell?" in seconds without re-pulling the image. This is critical for incident response: when a new CVE drops, you re-scan the cached SBOM rather than the entire image. The decoupled approach also enables signing the SBOM with Cosign (Lab 8), creating a cryptographically verifiable inventory that travels with the artifact through the pipeline. Additionally, Grype's integration with GitHub Security Advisories provides faster coverage of newly disclosed vulnerabilities in npm/PyPI packages.

**Trivy's all-in-one model wins** in CI pipelines where simplicity and breadth matter. Trivy scans images, filesystems, IaC configs (Terraform, Kubernetes), and secrets in a single binary with no external dependencies. For a DevSecOps team that wants one tool covering vulnerabilities + misconfigurations + secrets + license compliance, Trivy reduces operational overhead. It's also better for "shift-left" scanning in pre-commit hooks or PR checks, where you want fast feedback without managing separate SBOM artifacts. Trivy's secret scanning (which detected the RSA private keys in Juice Shop's insecurity.ts) provides additional security coverage that Grype alone doesn't offer.

---

## Bonus Task: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **1.6**
- `bomFormat`: **CycloneDX**

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 30 lines of juice-shop-attestation.json)
```json
{
    "subject":  [
                    {
                        "digest":  {
                                       "sha256":  "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
                                   },
                        "name":  "bkimminich/juice-shop:v20.0.0"
                    }
                ],
    "_type":  "https://in-toto.io/Statement/v1",
    "predicate":  {
                      "$schema":  "http://cyclonedx.org/schema/bom-1.6.schema.json",
                      "bomFormat":  "CycloneDX",
                      "specVersion":  "1.6",
                      "serialNumber":  "urn:uuid:e64baadf-bb24-40dc-b73d-3186f9d2cb3b",
                      "version":  1,
                      "metadata":  {
                                       "timestamp":  "2026-06-18T23:39:21+03:00",
                                       "tools":  {
                                                     "components":  [
                                                                        {
                                                                            "type":  "application",
                                                                            "author":  "anchore",
                                                                            "name":  "syft",
                                                                            "version":  "1.45.1"
                                                                        }
                                                                    ]
                                                 },
                                       "component":  {
                                                         "bom-ref":  "73ec537d8d158676",
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, it creates a cryptographically signed in-toto attestation that binds the SBOM to the specific image digest. This proves: (1) **Authenticity** — the SBOM was generated by an authorized party holding the signing key, (2) **Integrity** — the SBOM has not been tampered with since signing, and (3) **Provenance** — the SBOM corresponds to the exact image with the specified digest. This enables supply chain security by allowing consumers to verify that the SBOM they're examining is the authoritative inventory for that specific image build, preventing attackers from substituting a malicious SBOM that hides vulnerable dependencies.