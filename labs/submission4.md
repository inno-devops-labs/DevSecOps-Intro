# Lab 4 — SBOM Generation & Software Composition Analysis

# Task 1 — SBOM Generation with Syft and Trivy

## 1. Package Type Distribution (Syft vs Trivy)

From `sbom-analysis.txt`:

### Syft package counts
- `npm`: **1128**
- `deb`: **10**
- `binary`: **1**

### Trivy package counts
- Node.js: **1125**
- OS packages (debian 12.11): **10**

**Interpretation**
- Both tools confirm that OWASP Juice Shop is dominated by **Node.js (npm) dependencies**, which represent the largest supply-chain surface area.
- Both tools also detect **OS-level packages** from the base Debian layer.
- Syft reports slightly more Node packages (1128 vs 1125). This difference is expected due to different cataloging/matching approaches and how each tool handles duplicates / “unknown” typed entries.

---

## 2. Dependency Discovery Analysis (coverage + metadata)

**Syft strengths observed**
- Syft native JSON contains rich metadata per component: package name/version, locations inside image filesystem, and identifiers like `purl`/CPE.  
- This SBOM format is well-suited to be used as an authoritative inventory and then scanned by Grype (SBOM-first workflow).

**Trivy strengths observed**
- Trivy provides a consolidated view per scan target (OS packages vs language packages), which is convenient in CI/CD and quick audits.

**Practical outcome**
- Both tools discover the main dependency ecosystems (Node + Debian base image), but Syft provides deeper SBOM metadata structure that is useful for downstream analysis.

---

## 3. License Discovery Analysis (Syft vs Trivy)

From `sbom-analysis.txt` license counts:

### Syft licenses (overall)
Syft discovered **32 unique license types**.

Top license families by count (high-level):
- MIT: **890**
- ISC: **143**
- Apache-2.0: **15**
- BSD-3-Clause: **16**
- BSD-2-Clause: **12**
- LGPL-3.0: **19**
- GPL family (GPL/GPL-2/GPL-3 and variants): present

### Trivy licenses
Trivy discovered **28 unique license types** total.

Breakdown shows:
- OS packages licenses include GPL/GFDL/LGPL variants typical for Debian packages.
- Node.js licenses are dominated by MIT and ISC, matching expectations.

**Interpretation**
- Syft found **more unique license types (32 vs 28)**, suggesting broader license discovery (or slightly different normalization).
- Most detected licenses are **permissive** (MIT, ISC, Apache-2.0, BSD), which generally represents low compliance risk.
- Presence of **copyleft licenses** (GPL/LGPL/GFDL) is important for compliance programs: even when legally acceptable, these licenses usually require policy review.

---

# Task 2 — Software Composition Analysis (SCA) with Grype and Trivy

## 1. Vulnerability detection capability (severity distribution)

From `vulnerability-analysis.txt`:

### Grype vulnerabilities by severity (SBOM-based scan)
- Critical: **11**
- High: **60**
- Medium: **31**
- Low: **3**
- Negligible: **12**
Total (from CVE list size): **90** CVEs.

### Trivy vulnerabilities by severity (image scan)
- CRITICAL: **10**
- HIGH: **55**
- MEDIUM: **33**
- LOW: **18**
Total (from CVE list size): **88** CVEs.

**Interpretation**
- Both tools detect a significant set of vulnerabilities with similar overall totals (Grype 90 vs Trivy 88).
- Minor discrepancies are expected due to different vulnerability databases, matching logic, and timing of DB updates.

---

## 2. Critical vulnerabilities — Top 5 and remediation

Below are the **Top 5 CRITICAL findings** prioritized for remediation.  
(Extracted from the Grype/Trivy reports; include one row per vulnerability.)

```bash
# Example: top 5 CRITICAL from Trivy JSON
jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL") |
"\(.VulnerabilityID) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "no fix") | \(.Title // "")"' \
labs/lab4/trivy/trivy-vuln-detailed.json | head -n 5

# Example: top 5 Critical from Grype JSON
jq -r '.matches[]? | select(.vulnerability.severity=="Critical") |
"\(.vulnerability.id) | \(.artifact.name) | \(.artifact.version) | \(.vulnerability.fix.versions[0] // "no fix") | \(.vulnerability.description // "")"' \
labs/lab4/syft/grype-vuln-results.json | head -n 5
```

## Critical Vulnerabilities — Top 5 Findings

| Vulnerability | Package | Installed Version | Fixed Version | Risk & Remediation |
|---|---|---|---|---|
| GHSA-whpj-8f3w-67p5 | vm2 | 3.9.17 | 3.9.18 | Sandbox escape risk. Upgrade vm2 to ≥3.9.18 |
| GHSA-g644-9gfx-q4q4 | vm2 | 3.9.17 | — | Critical sandbox vulnerability. Upgrade to latest vm2 |
| GHSA-c7hr-j4mj-j2w6 | jsonwebtoken | 0.1.0 / 0.4.0 | 4.2.2+ | Token validation bypass risk. Upgrade jsonwebtoken |
| GHSA-cchq-frgv-rjh5 | vm2 | 3.9.17 | 3.10.0 | Remote code execution risk. Upgrade vm2 |
| GHSA-jf85-cpcp-j695 | lodash | 2.4.2 | 4.17.12+ | Prototype pollution. Upgrade lodash |

* Prefer upgrading the **base image** to a newer patched Debian release where possible.
* Upgrade vulnerable npm dependencies (direct and transitive) using dependency update tooling and lockfile updates.
* Rebuild image and rerun SBOM + SCA scans to confirm risk reduction.

---

## 3. License compliance assessment

Summary from `vulnerability-analysis.txt`:

* Syft: **32** unique license types
* Trivy: **28** unique license types

**Compliance recommendations**

* Maintain an allow/deny policy for licenses.
* Track and review copyleft licenses (GPL/LGPL/GFDL) especially if redistributing binaries or SaaS licensing policy requires it.
* Automate license scanning in CI/CD to prevent drift.

---

## 4. Additional security features — secrets scanning (Trivy)

Trivy secret scanning output is available in:

* `labs/lab4/trivy/trivy-secrets.txt`

Result summary (from the scan output):

* Trivy secret scanning did not detect any embedded secrets or credentials in the container image.

* This indicates that the container image does not expose sensitive information such as API keys, tokens, or passwords.

---

# Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

## 1. Accuracy and coverage (quantitative overlap)

From `accuracy-analysis.txt`:

### Package detection overlap

* Packages detected by both tools: **1126**
* Packages only detected by Syft: **13**
* Packages only detected by Trivy: **9**

**Interpretation**

* Very high overlap indicates both tools are broadly consistent for this image.
* The small “only in X” sets likely come from differences in:

  * cataloging edge cases
  * duplicates
  * package typing / normalization

### Vulnerability overlap

* CVEs found by Grype: **90**
* CVEs found by Trivy: **88**
* Common CVEs: **26**

**Interpretation**

* The overlap of CVEs is meaningful but not complete, which highlights a real-world DevSecOps lesson:

  * different tools/databases yield different results
  * high-confidence remediation should cross-check critical/high findings across scanners

---

## 2. Strengths and weaknesses (practical observations)

### Syft + Grype (specialized toolchain)

**Strengths**

* SBOM-first workflow: Syft creates a detailed inventory; Grype scans it consistently.
* Rich SBOM metadata helps with compliance, auditability, and integrations.

**Weaknesses**

* Requires orchestrating two tools and managing multiple artifacts.
* Slightly higher operational overhead in CI/CD.

### Trivy (all-in-one)

**Strengths**

* Simpler operations: single tool for vulnerabilities + licenses + secrets.
* Very convenient for CI/CD quick checks.

**Weaknesses**

* SBOM detail can be less “SBOM-native” than Syft’s dedicated SBOM format.
* Results can vary depending on DB download/update behavior (needs caching/timeouts in slow networks).

---

## 3. Use-case recommendations

**Choose Syft + Grype when**

* We need authoritative SBOMs for compliance or audits.
* We want SBOM lifecycle management and downstream tooling integration.
* We prefer SBOM-first security workflows.

**Choose Trivy when**

* We want fast adoption and a single tool in CI/CD.
* We need integrated secret + license scanning without extra tools.
* We need quick vulnerability feedback during development.

## 4. Integration Considerations (CI/CD and Operations)

In CI/CD pipelines:

- Trivy provides quick feedback during build stages and can be integrated as a lightweight security gate.
- Syft + Grype enables a more mature SBOM-driven workflow, where SBOMs are generated once and reused for multiple security and compliance checks.

Operational considerations:

- Trivy is easier to onboard due to its all-in-one design.
- Syft + Grype requires orchestration but provides deeper visibility and traceability.
