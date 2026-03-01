# Lab 4 Submission — SBOM Generation & Software Composition Analysis


## Task 1 — SBOM Generation with Syft and Trivy

### 1.1 Environment Setup

Commands used:

```bash
mkdir -p labs/lab4/{syft,trivy,comparison,analysis}
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```


### 1.2 SBOM Generation — Syft

Used commands provided in the lab

**Generated files:**

- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab4/syft/juice-shop-syft-table.txt`
- `labs/lab4/syft/juice-shop-licenses.txt`

**Example output from file `labs/lab4/syft/juice-shop-syft-table.txt`:**

```text
NAME                                VERSION            TYPE                      
1to2                                1.0.0              npm                       
@adraffy/ens-normalize              1.10.1             npm                       
@babel/helper-string-parser         7.27.1             npm                       
@babel/helper-validator-identifier  7.27.1             npm                       
@babel/parser                       7.28.3             npm                       
@babel/types                        7.28.2             npm                       
@colors/colors                      1.6.0              npm     (+1 duplicate)                   
```

### 1.3 SBOM Generation — Trivy

Used commands provided in the lab

**Generated files:**

- `labs/lab4/trivy/juice-shop-trivy-detailed.json`
- `labs/lab4/trivy/juice-shop-trivy-table.txt`

**Example output from `labs/lab4/trivy/juice-shop-trivy-table.txt`:**

```text
Report Summary

┌──────────────────────────────────────────────────────────────────────────────────┬──────────┬─────────────────┬─────────┐
│                                      Target                                      │   Type   │ Vulnerabilities │ Secrets │
├──────────────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ bkimminich/juice-shop:v19.0.0 (debian 12.11)                                     │  debian  │       27        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ juice-shop/build/package.json                                                    │ node-pkg │        0        │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
```

### 1.4 SBOM Analysis and Extraction

Used commands provided in the lab

**Output evidence:**

```text
=== SBOM Component Analysis ===

Syft Package Counts:
   1 binary
  10 deb
1128 npm

Trivy Package Counts:
1125 Node.js - unknown
  10 bkimminich/juice-shop:v19.0.0 (debian 12.11) - unknown

...
```

### 1.5 Analysis (SBOM)

#### Package Type Distribution (Syft vs Trivy)

| Metric | Syft | Trivy | Observation |
|---|---:|---:|---|
| Total packages/components | 1139 | 1135 | Syft found slightly more (binary + deb + npm); Trivy groups Node.js separately from OS. |
| OS packages detected | 10 deb, 1 binary | 10 debian | Both detected the same Debian base layer. |
| Language packages detected | 1128 npm | 1125 Node.js | Syft found 3 more npm packages; Trivy uses "Node.js" type. |

#### Dependency Discovery Analysis

Syft and Trivy both discovered core OS and Node.js dependencies for Juice Shop.  
From the measured outputs, **Syft** identified more total entries (1139 vs 1135), while **Trivy** provided better contextual grouping by target/layer (debian vs node-pkg) for operational triage.

#### License Discovery Analysis

Based on extracted license metadata, **Syft** surfaced more unique license identifiers (32 vs 28).  
For compliance workflows, this is useful because it improves visibility into potential copyleft or restricted-license dependencies before release.

---

## Task 2 — Software Composition Analysis with Grype and Trivy 
### 2.1 SCA with Grype

Used commands provided in the lab

### 2.2 SCA with Trivy

Used commands provided in the lab


**Example output from `trivy-secrets.txt`:**

```text
Report Summary

┌──────────────────────────────────────────────────────────────────────────────────┬──────────┬─────────┐
│                                      Target                                      │   Type   │ Secrets │
├──────────────────────────────────────────────────────────────────────────────────┼──────────┼─────────┤
│ bkimminich/juice-shop:v19.0.0 (debian 12.11)                                     │  debian  │    -    │
├──────────────────────────────────────────────────────────────────────────────────┼──────────┼─────────┤
│ juice-shop/build/package.json                                                    │ node-pkg │    -    
...
```

### 2.3 Vulnerability and Risk Analysis

Used commands from the lab


**Output from `labs/lab4/analysis/vulnerability-analysis.txt`:**

```text
=== Vulnerability Analysis ===

Grype Vulnerabilities by Severity:
  11 Critical
  86 High
   3 Low
  32 Medium
  12 Negligible

Trivy Vulnerabilities by Severity:
  10 CRITICAL
  81 HIGH
  18 LOW
  34 MEDIUM

=== License Analysis Summary ===
Tool Comparison:
- Syft found       32 unique license types
- Trivy found       28 unique license types

```

### 2.4 Analysis 

#### SCA Tool Comparison

- **Grype strengths:** Tight integration with Syft SBOMs, straightforward CVE-focused output, good for dedicated vulnerability pipelines.
- **Trivy strengths:** Broader all-in-one coverage (vulnerabilities + secrets + licenses) and simple operational footprint.
- **Observed difference in my run:** Grype found 11 Critical, 86 High, 32 Medium, 3 Low, 12 Negligible (144 total); Trivy found 10 CRITICAL, 81 HIGH, 34 MEDIUM, 18 LOW (143 total). Grype reports Negligible; Trivy does not. Only 26 CVEs overlapped between tools despite similar totals.

#### Critical Vulnerabilities Analysis (Top 5)

| Rank | Vulnerability ID | Package | Severity | Found by (Grype/Trivy/Both) | Recommended remediation |
|---:|---|---|---|---|---|
| 1 | CVE-2025-15467 | libssl3 | Critical | Both | Upgrade to 3.0.18-1~deb12u2 (Debian base image update) |
| 2 | CVE-2025-55130 | node | Critical | Grype | Upgrade Node.js to 20.20.0, 22.22.0, 24.13.0, or 25.3.0 |
| 3 | CVE-2023-32314 | vm2 | Critical | Both | Upgrade vm2 to 3.9.18 or remove if unused |
| 4 | CVE-2019-10744 | lodash | Critical | Both | Upgrade lodash to 4.17.12 |
| 5 | CVE-2015-9235 | jsonwebtoken | Critical | Both | Upgrade jsonwebtoken to 4.2.2 |

#### License Compliance Assessment

- Potentially risky licenses identified: GPL, GPL-2, GPL-3, LGPL, LGPL-3.0, GFDL (copyleft); Artistic, BlueOak-1.0.0.
- Compliance concern for commercial/internal distribution: Copyleft licenses (GPL, LGPL) require source disclosure and license compatibility. GFDL has documentation obligations.
- Mitigation actions:
  - Define organization-approved/denied license policy
  - Add CI gate for denied licenses
  - Track transitive dependency licenses in release checklist

#### Additional Security Features (Secrets Scanning)

Trivy secrets scanning result: No hardcoded secrets found in image layers. All targets (debian base, node-pkg) reported "-" for secrets.  
Operational implication: secrets scanning should still be run in source repos and CI artifacts, not only on final images.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One 

### 3.1 Accuracy and Coverage Analysis

Used commands provided in the lab

**Output of `labs/lab4/comparison/accuracy-analysis.txt`:**

```text
=== Package Detection Comparison ===
Packages detected by both tools:     1126
Packages only detected by Syft:       13
Packages only detected by Trivy:        9

=== Vulnerability Detection Overlap ===
CVEs found by Grype:       93
CVEs found by Trivy:       91
Common CVEs:       26
```

### 3.2 Analysis

#### Accuracy Analysis (Quantified)

| Metric | Value |
|---|---:|
| Packages detected by both tools | 1126 |
| Packages only in Syft | 13 |
| Packages only in Trivy | 9 |
| CVEs found by Grype | 93 |
| CVEs found by Trivy | 91 |
| CVEs found by both | 26 |

#### Tool Strengths and Weaknesses

- **Syft + Grype strengths:** modular architecture, strong SBOM-first workflow, easier to swap components.
- **Syft + Grype weaknesses:** two-tool maintenance, more pipeline wiring effort.
- **Trivy strengths:** single binary/toolchain, faster onboarding, supports vulnerabilities/secrets/licenses together.
- **Trivy weaknesses:** less separation of concerns; teams with strict SBOM governance may prefer dedicated SBOM tooling.

#### Use Case Recommendations

- Choose **Syft + Grype** when:
  - You need SBOM-centric workflows and flexible integrations
  - You want independent control over SBOM and vuln stages
  - You already standardize on Anchore ecosystem
- Choose **Trivy** when:
  - You want quick rollout with minimal operational overhead
  - You need multi-scanner output in one tool (vuln/secret/license)
  - You prioritize simple CI integration across many repos

#### Integration Considerations (CI/CD and Operations)

- Run scans on every pull request and on base-image refresh events.
- Archive SBOM and scan JSON artifacts for auditability.
- Add severity and license policy gates (fail build on defined thresholds).
- Schedule periodic re-scan jobs to catch newly disclosed CVEs without code changes.
