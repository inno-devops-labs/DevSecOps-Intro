# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1834859
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown (paste table or JSON)

| Severity   | Count |
| ---------- | ----: |
| Critical   |     7 |
| High       |    51 |
| Medium     |    35 |
| Low        |     4 |
| Negligible |     7 |
| **Total**  |   104 |

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

Out of the top 10 CVEs, how many have a fix available? What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
_sort by fix-available AND severity ≥ HIGH first_.)

- Out of the top 10 CVEs, 7 have a fix available, while 3 do not. Applying Lecture 4's triage shortcut to sort by fix-available and severity ≥ HIGH first, my immediate patch cadence must prioritize deploying the 7 available fixes since all are Critical or High severity and actionable right now.

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity  | Grype | Trivy |   Δ |
| --------- | ----: | ----: | --: |
| Critical  |     7 |     5 |   2 |
| High      |    51 |    43 |   8 |
| Medium    |    35 |    39 |  -4 |
| Low       |     4 |    22 | -18 |
| **Total** |   104 |   109 |  -5 |

### Why the difference?

Pick **two specific CVEs** that ONE tool found and the other didn't. For each:

1. CVE ID + tool that found it + tool that missed it

2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?

- CVE ID: GHSA-35jh-r3h4-6jhm
  Found by: Grype
  Missed by: Trivy
  Why: Grype heavily integrates with the GitHub Advisory Database (GHSA), which is why it flags GHSA-prefixed IDs. Trivy primarily relies on the NVD (National Vulnerability Database) and OSV, so it might map this same vulnerability to a different CVE ID or miss the specific GHSA entry entirely due to different package matching rules for Node.js dependencies.
- CVE ID: CVE-2017-16016
  Found by: Trivy
  Missed by: Grype
  Why: Trivy scans the actual filesystem layers of the Docker image directly, allowing it to catch deeply nested transitive dependencies or OS-level packages that Syft might have overlooked when generating the SBOM. Additionally, Trivy's vulnerability database might have a more comprehensive historical mapping for older CVEs compared to Grype's focus on newer advisory databases.

### When would you pick each?

2-3 sentences each:

- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8)
- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig)

1. Syft+Grype's decoupled model:
   This model wins when you need to generate a signed SBOM-as-an-attestation for supply chain transparency and compliance. Because the SBOM is decoupled from the image, you can store it as an artifact and re-scan it against new vulnerability databases as they update, without needing to pull or re-analyze the container image.
2. Trivy's all-in-one model:
   Trivy wins when you want a simpler, single-step CI pipeline that scans beyond just software vulnerabilities. It provides a much broader security scope by simultaneously checking for Infrastructure as Code (IaC) misconfigurations, exposed secrets, and license compliance in one unified command.
