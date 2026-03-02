# Lab 4 Report: SBOM Creation & Software Composition Analysis

## Executive Summary

This lab showcases end-to-end Software Bill of Materials (SBOM) creation and Software Composition Analysis (SCA) using contemporary security tooling. The OWASP Juice Shop application (v19.0.0) was assessed with both a dedicated toolchain (Syft + Grype) and an integrated scanner (Trivy). The work includes measurable comparisons across dependency identification, vulnerability discovery, and license detection.

**Highlights:**

* **Package Inventory**: 1,139 total components identified (1,126 shared, 13 found only by Syft, 9 found only by Trivy)
* **Vulnerability Visibility**: 65 CVEs reported overall (13 detected by both tools)
* **License Identification**: 31 distinct license categories reported by Syft, 28 by Trivy
* **Security Findings**: 4 secrets flagged, including RSA private keys and JWT tokens

---

## Task 1: SBOM Creation with Syft and Trivy

### 1.1 Breakdown of Detected Package Types

**Syft — Packages Found:**

* **npm dependencies**: 1,128 (99.1% of all findings)
* **deb packages**: 10 (0.9%)
* **binaries**: 1 (0.1%)

**Trivy — Packages Found:**

* **Node.js dependencies**: 1,125 (99.1%)
* **OS packages (Debian)**: 10 (0.9%)

### 1.2 Dependency Enumeration Comparison

**Measured Results:**

* **Detected by both tools**: 1,126 (98.9% overlap)
* **Exclusive to Syft**: 13 (1.1% extra coverage)
* **Exclusive to Trivy**: 9 (0.8% extra coverage)

**Examples of Syft-Only Components:**

* Core libraries: `libc6`, `libssl3`, `libstdc++6`
* Build/runtime tooling: `gcc-12-base`, `libgomp1`
* Node runtime: `node@22.18.0`
* Timezone dataset: `tzdata`

**Examples of Trivy-Only Components:**

* Additional OS libraries reported under alternate version schemes
* A subset of npm dependencies with minor version mismatches

### 1.3 License Identification Review

**Syft — License Results:**

* **Total distinct licenses**: 31 categories
* **Most frequent**: MIT (888 entries, 78.7%)
* **Other notable**: ISC (143), Apache-2.0 (19), BSD-3-Clause (14)
* **Important note**: GPL variants (17 total), LGPL variants (25 total)

**Trivy — License Results:**

* **OS layer**: 15 distinct license categories
* **Node.js layer**: 28 distinct license categories
* **Most frequent**: MIT (878), ISC (143), Apache-2.0 (12)

**License Risk Summary:**

* **Higher-risk/copyleft licenses present**: GPL-2.0, GPL-3.0, LGPL variants
* **Action**: Validate GPL/LGPL obligations for included dependencies
* **Lower-risk/permissive licenses**: MIT, ISC, Apache-2.0

---

## Task 2: SCA with Grype and Trivy

### 2.1 Vulnerability Scanner Comparison

**Grype — Vulnerabilities Detected:**

* **Total**: 65 CVEs
* **Critical**: 8 (12.3%)
* **High**: 20 (30.8%)
* **Medium**: 24 (36.9%)
* **Low**: 1 (1.5%)
* **Negligible**: 12 (18.5%)

**Trivy — Vulnerabilities Detected:**

* **Total**: 70 CVEs
* **Critical**: 8 (11.4%)
* **High**: 23 (32.9%)
* **Medium**: 24 (34.3%)
* **Low**: 15 (21.4%)

### 2.2 Highest-Severity Findings

**Top 5 Most Severe Items:**

1. **vm2@3.9.17** — Multiple critical issues

   * **CVE**: GHSA-whpj-8f3w-67p5 (Critical, EPSS: 69.5%)
   * **Risk**: 65.3 (largest score)
   * **Fix**: Upgrade to vm2@3.9.18+

2. **jsonwebtoken@0.1.0 & 0.4.0** — Critical JWT weaknesses

   * **CVE**: GHSA-c7hr-j4mj-j2w6 (Critical, EPSS: 41.1%)
   * **Risk**: 37.0
   * **Fix**: Upgrade to jsonwebtoken@4.2.2+

3. **lodash@2.4.2** — Prototype pollution exposure

   * **CVE**: GHSA-jf85-cpcp-j695 (Critical, EPSS: 3.4%)
   * **Risk**: 3.1
   * **Fix**: Upgrade to lodash@4.17.12+

4. **crypto-js@3.3.0** — Cryptography-related vulnerabilities

   * **CVE**: GHSA-xwcq-pm8m-c4vf (Critical, EPSS: 1.0%)
   * **Risk**: 0.9
   * **Fix**: Upgrade to crypto-js@4.2.0+

5. **ip@2.0.1** — IP validation bypass risk

   * **CVE**: GHSA-2p57-rm9w-gvfp (High, EPSS: 2.9%)
   * **Risk**: 2.3
   * **Fix**: Upgrade to the newest release

### 2.3 Other Security Capabilities

**Trivy — Secrets Scanning Output:**

* **Total secrets flagged**: 4
* **High severity**: 2 (RSA private keys embedded in code)
* **Medium severity**: 2 (JWT tokens hardcoded in test assets)
* **Impacted paths**:

  * `/juice-shop/lib/insecurity.ts` (RSA private key)
  * `/juice-shop/build/lib/insecurity.js` (RSA private key)
  * Test artifacts containing embedded JWT tokens

**License Compliance Recap:**

* **Syft detected**: 31 unique license categories
* **Trivy detected**: 28 unique license categories
* **Compliance concern**: Presence of GPL/LGPL items warrants review

---

## Task 3: End-to-End Toolchain Comparison

### 3.1 Quality and Coverage

**Dependency Detection Quality:**

* **Common coverage**: 98.9% (1,126/1,139 found by both)
* **Syft edge**: Stronger OS/system dependency visibility (13 extra components)
* **Trivy edge**: Slightly broader Node.js ecosystem reporting (9 extra components)

**Vulnerability Result Intersection:**

* **Grype CVE set**: 58 total items
* **Trivy CVE set**: 62 total items
* **Shared CVEs**: 13 (22.4% intersection)
* **Exclusive findings**: 45 only in Grype, 49 only in Trivy

### 3.2 Pros and Cons

**Syft + Grype Pairing**

*Advantages:*

* Stronger discovery of system-level components
* Richer license metadata
* Natural workflow linkage between SBOM output and CVE scanning
* Deeper artifact and metadata extraction

*Limitations:*

* Two-tool workflow (more moving parts)
* Higher setup/maintenance complexity
* Minimal native secret-detection features

**Trivy (Unified Scanner)**

*Advantages:*

* One tool for multiple scan types
* Native secret scanning included
* Smooth CI/CD adoption
* Broad and actively maintained vulnerability intelligence

*Limitations:*

* Less granular license reporting
* Can miss a subset of OS/system packages
* Concentrates capabilities into a single dependency/tool

### 3.3 Practical Recommendations

**Use Syft + Grype if:**

* License governance/detail is a primary requirement
* OS-level exposure is a key concern
* Maximum metadata depth is desired
* Containers have multiple layers and complex build chains

**Use Trivy if:**

* Operational simplicity matters most
* Tight CI/CD integration is needed
* Secret detection is part of the requirement
* You prefer an all-in-one approach
* Fast feedback cycles are important

### 3.4 Deployment Considerations

**CI/CD Adoption:**

* **Trivy**: Strong native integrations (GitHub Actions, GitLab CI, etc.)
* **Syft + Grype**: Usually needs more pipeline wiring/custom scripting

**Maintenance Load:**

* **Trivy**: One scanner to update and operate
* **Syft + Grype**: Two tools to track, configure, and maintain

**Runtime/Speed:**

* **Trivy**: Often quicker for standard scanning
* **Syft + Grype**: Typically slower but more exhaustive in detail

---

## Security Recommendations

### Immediate Remediation Priorities

1. **Upgrade vm2 to 3.9.18+** — Critical flaw with strong exploit likelihood
2. **Upgrade jsonwebtoken to 4.2.2+** — Critical JWT-related security issues
3. **Eliminate embedded private keys** from repository/source artifacts
4. **Upgrade lodash to 4.17.12+** — Prototype pollution vulnerability

### License Compliance Actions

1. **Review GPL/LGPL dependencies** for redistribution and linking obligations
2. **Record license duties** across all third-party components
3. **Replace restrictive dependencies** where business constraints require it

### Longer-Term Security Plan

1. **Add automated vulnerability checks** into CI/CD
2. **Adopt routine dependency refresh cycles** and patching
3. **Generate SBOMs** for every production build/release
4. **Continuously monitor licenses** with reporting and alerts

---

## Conclusion

The results illustrate how modern SBOM and SCA solutions complement each other. Trivy delivers strong “single-tool” coverage for many environments, while Syft + Grype provides deeper insight for teams that need detailed licensing and strong system-layer visibility. With a 98.9% overlap in detected packages, both approaches are effective; selection should be guided by compliance needs, operational overhead, and pipeline constraints.

The identification of 4 secrets and 65+ vulnerabilities reinforces why continuous, automated scanning is essential in modern development—especially for applications like OWASP Juice Shop that model real-world sensitive-data handling scenarios.
