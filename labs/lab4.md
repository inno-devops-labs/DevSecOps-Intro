# Lab 4 — SBOM Generation & Software Composition Analysis

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-SBOM%20%26%20SCA-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Generate Software Bills of Materials (SBOMs) for OWASP Juice Shop using Syft and Trivy, perform comprehensive Software Composition Analysis with Grype and Trivy, then compare the toolchain capabilities.  
> **Deliverable:** A PR from `feature/lab4` to the course repo with `labs/submission4.md` containing SBOM analysis, SCA findings, and comprehensive toolchain comparison. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Generating **SBOMs** with **Syft** and **Trivy** using Docker images for consistency
- Performing **Software Composition Analysis (SCA)** with **Grype** (Anchore) and **Trivy**
- **Comprehensive feature comparison** between **Syft+Grype** vs **Trivy all-in-one** approaches
- **License analysis**, **vulnerability management**, and **supply chain security assessment**

These skills are essential for supply chain security, vulnerability management, and regulatory compliance (Executive Order 14028, EU Cyber Resilience Act).

> Continue using the OWASP Juice Shop from previous labs (`bkimminich/juice-shop:v19.0.0`) as your target application.

---

## Tasks

### Task 1 — SBOM Generation with Syft and Trivy (4 pts)

**Objective:** Generate comprehensive SBOMs using both Syft and Trivy Docker images, extracting maximum metadata including licenses, file information, and dependency relationships.

#### 1.1: Setup SBOM Generation Environment

1. **Prepare Working Directory:**

   ```bash
   mkdir -p labs/lab4/{syft,trivy,comparison,analysis}
   ```

2. **Pull Required Docker Images:**

   ```bash
   docker pull anchore/syft:latest
   docker pull aquasec/trivy:latest
   docker pull anchore/grype:latest
   ```

#### 1.2: Comprehensive SBOM Generation with Syft

1. **Generate Multiple SBOM Formats:**

   ```bash
   # Syft native JSON format (most detailed)
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp anchore/syft:latest \
     bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json
   
   # Human-readable table
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp anchore/syft:latest \
     bkimminich/juice-shop:v19.0.0 -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt
   
   # Extract licenses directly from the native JSON format
   echo "Extracting licenses from Syft SBOM..." > labs/lab4/syft/juice-shop-licenses.txt
   jq -r '.artifacts[] | select(.licenses != null and (.licenses | length > 0)) | "\(.name) | \(.version) | \(.licenses | map(.value) | join(", "))"' \
     labs/lab4/syft/juice-shop-syft-native.json >> labs/lab4/syft/juice-shop-licenses.txt
   ```

#### 1.3: Comprehensive SBOM Generation with Trivy

1. **Generate Multiple SBOM Formats:**

   ```bash
   # SBOM with license information
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp aquasec/trivy:latest image \
     --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
     --list-all-pkgs bkimminich/juice-shop:v19.0.0
   
   # Human-readable table with package details
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp aquasec/trivy:latest image \
     --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
     --list-all-pkgs bkimminich/juice-shop:v19.0.0
   ```

#### 1.4: SBOM Analysis and Extraction

1. **Component Analysis:**

   ```bash
   # Count total packages by type
   echo "=== SBOM Component Analysis ===" > labs/lab4/analysis/sbom-analysis.txt
   echo "" >> labs/lab4/analysis/sbom-analysis.txt
   echo "Syft Package Counts:" >> labs/lab4/analysis/sbom-analysis.txt
   jq -r '.artifacts[] | .type' labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt   
   
   echo "" >> labs/lab4/analysis/sbom-analysis.txt
   echo "Trivy Package Counts:" >> labs/lab4/analysis/sbom-analysis.txt
   # Better approach: combine Target info with Package type
   jq -r '.Results[] as $result | $result.Packages[]? | "\($result.Target // "Unknown") - \(.Type // "unknown")"' \
     labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
   ```

2. **License Extraction:**

   ```bash
   # Extract license information
   echo "" >> labs/lab4/analysis/sbom-analysis.txt
   echo "=== License Analysis ===" >> labs/lab4/analysis/sbom-analysis.txt
   echo "" >> labs/lab4/analysis/sbom-analysis.txt
   echo "Syft Licenses:" >> labs/lab4/analysis/sbom-analysis.txt
   jq -r '.artifacts[]? | select(.licenses != null) | .licenses[]? | .value' \
     labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
   
   echo "" >> labs/lab4/analysis/sbom-analysis.txt
   echo "Trivy Licenses (OS Packages):" >> labs/lab4/analysis/sbom-analysis.txt
   jq -r '.Results[] | select(.Class // "" | contains("os-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
     labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
   
   echo "" >> labs/lab4/analysis/sbom-analysis.txt  
   echo "Trivy Licenses (Node.js):" >> labs/lab4/analysis/sbom-analysis.txt
   jq -r '.Results[] | select(.Class // "" | contains("lang-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
     labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
   ```

In `labs/submission4.md`, document:
- **Package Type Distribution** comparison between Syft and Trivy
- **Dependency Discovery Analysis** - which tool found more/better dependency data
- **License Discovery Analysis** - which tool found more/better license data

---

### Task 2 — Software Composition Analysis with Grype and Trivy (3 pts)

**Objective:** Perform comprehensive vulnerability analysis using both Grype (designed for Syft SBOMs) and Trivy's built-in vulnerability scanning.

#### 2.1: SCA with Grype (Anchore)

1. **Vulnerability Scanning Using Syft SBOM:**

   ```bash
   # Scan using the Syft-generated SBOM
   docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
     sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
     -o json > labs/lab4/syft/grype-vuln-results.json

   # Human-readable vulnerability report
   docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
     sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
     -o table > labs/lab4/syft/grype-vuln-table.txt
   ```

#### 2.2: SCA with Trivy (All-in-One)

1. **Comprehensive Vulnerability Scanning:**

   ```bash
   # Full vulnerability scan with detailed output
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp aquasec/trivy:latest image \
     --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
     bkimminich/juice-shop:v19.0.0
   ```

2. **Advanced Trivy Features:**

   ```bash
   # Secrets scanning
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp aquasec/trivy:latest image \
     --scanners secret --format table \
     --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
     bkimminich/juice-shop:v19.0.0
   
   # License compliance scanning
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$(pwd)":/tmp aquasec/trivy:latest image \
     --scanners license --format json \
     --output /tmp/labs/lab4/trivy/trivy-licenses.json \
     bkimminich/juice-shop:v19.0.0
   ```

#### 2.3: Vulnerability Analysis and Risk Assessment

1. **Comparative Vulnerability Analysis:**

   ```bash
   # Count vulnerabilities by severity
   echo "=== Vulnerability Analysis ===" > labs/lab4/analysis/vulnerability-analysis.txt
   echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
   echo "Grype Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
   jq -r '.matches[]? | .vulnerability.severity' labs/lab4/syft/grype-vuln-results.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
   
   echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
   echo "Trivy Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
   jq -r '.Results[]?.Vulnerabilities[]? | .Severity' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
   ```

2. **License Risk Analysis:**

   ```bash
   # License comparison summary
   echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
   echo "=== License Analysis Summary ===" >> labs/lab4/analysis/vulnerability-analysis.txt
   echo "Tool Comparison:" >> labs/lab4/analysis/vulnerability-analysis.txt
   if [ -f labs/lab4/syft/juice-shop-syft-native.json ]; then
     syft_licenses=$(jq -r '.artifacts[] | select(.licenses != null) | .licenses[].value' labs/lab4/syft/juice-shop-syft-native.json 2>/dev/null | sort | uniq | wc -l)
     echo "- Syft found $syft_licenses unique license types" >> labs/lab4/analysis/vulnerability-analysis.txt
   fi
   if [ -f labs/lab4/trivy/trivy-licenses.json ]; then
     trivy_licenses=$(jq -r '.Results[].Licenses[]?.Name' labs/lab4/trivy/trivy-licenses.json 2>/dev/null | sort | uniq | wc -l)
     echo "- Trivy found $trivy_licenses unique license types" >> labs/lab4/analysis/vulnerability-analysis.txt
   fi
   ```

In `labs/submission4.md`, document:
- **SCA Tool Comparison** - vulnerability detection capabilities
- **Critical Vulnerabilities Analysis** - top 5 most critical findings with remediation
- **License Compliance Assessment** - risky licenses and compliance recommendations
- **Additional Security Features** - secrets scanning results

---

### Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One (3 pts)

**Objective:** Comprehensive comparison of the specialized toolchain (Syft+Grype) versus the integrated solution (Trivy) across multiple dimensions.

#### 3.1: Accuracy and Coverage Analysis

1. **Package Detection Accuracy:**

   ```bash
   # Compare package detection
   echo "=== Package Detection Comparison ===" > labs/lab4/comparison/accuracy-analysis.txt
   
   # Extract unique packages from each tool
   jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
   jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt
   
   # Find packages detected by both tools
   comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt
   
   # Find packages unique to each tool
   comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
   comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt
   
   echo "Packages detected by both tools: $(wc -l < labs/lab4/comparison/common-packages.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
   echo "Packages only detected by Syft: $(wc -l < labs/lab4/comparison/syft-only.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
   echo "Packages only detected by Trivy: $(wc -l < labs/lab4/comparison/trivy-only.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
   ```

2. **Vulnerability Detection Overlap:**

   ```bash
   # Compare vulnerability findings
   echo "" >> labs/lab4/comparison/accuracy-analysis.txt
   echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt
   
   # Extract CVE IDs
   jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
   jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt
   
   echo "CVEs found by Grype: $(wc -l < labs/lab4/comparison/grype-cves.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
   echo "CVEs found by Trivy: $(wc -l < labs/lab4/comparison/trivy-cves.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
   echo "Common CVEs: $(comm -12 labs/lab4/comparison/grype-cves.txt labs/lab4/comparison/trivy-cves.txt | wc -l)" >> labs/lab4/comparison/accuracy-analysis.txt
   ```

#### 3.2: Tool Evaluation and Recommendations

In `labs/submission4.md`, document:
- **Accuracy Analysis** - package detection and vulnerability overlap quantified
- **Tool Strengths and Weaknesses** - practical observations from your testing
- **Use Case Recommendations** - when to choose Syft+Grype vs Trivy
- **Integration Considerations** - CI/CD, automation, and operational aspects

---

## Acceptance Criteria

- ✅ Branch `feature/lab4` exists with commits for each task.
- ✅ File `labs/submission4.md` contains required analysis for Tasks 1-3.
- ✅ SBOM generation completed successfully with both Syft and Trivy.
- ✅ Comprehensive SCA performed with both Grype and Trivy vulnerability scanning.
- ✅ Quantitative toolchain comparison completed with accuracy analysis.
- ✅ All generated SBOMs, vulnerability reports, and analysis files committed.
- ✅ PR from `feature/lab4` → **course repo main branch** is open.
- ✅ PR link submitted via Moodle before the deadline.

---

## How to Submit

1. Create a branch for this lab and push it to your fork:

   ```bash
   git switch -c feature/lab4
   # create labs/submission4.md with your findings
   git add labs/submission4.md labs/lab4/
   git commit -m "docs: add lab4 submission - SBOM generation and SCA comparison"
   git push -u origin feature/lab4
   ```

2. Open a PR from your fork's `feature/lab4` branch → **course repository's main branch**.

3. In the PR description, include:

   ```text
   - [x] Task 1 done — SBOM Generation with Syft and Trivy
   - [x] Task 2 done — SCA with Grype and Trivy  
   - [x] Task 3 done — Comprehensive Toolchain Comparison
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Rubric (10 pts)

| Criterion                                                        | Points |
| ---------------------------------------------------------------- | -----: |
| Task 1 — SBOM generation with Syft and Trivy + analysis          |  **4** |
| Task 2 — SCA with Grype and Trivy + vulnerability assessment     |  **3** |
| Task 3 — Comprehensive toolchain comparison + recommendations    |  **3** |
| **Total**                                                        | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission4.md`.
- Include both quantitative metrics and qualitative analysis for each task.
- Document all Docker commands used and any issues encountered.
- Provide actionable security recommendations based on findings.
- Focus on practical insights over theoretical comparisons.

> **SBOM Quality Notes**  
> 1. NYU research (SBOMit project) shows metadata-based SBOM generation has accuracy limitations.  
> 2. Pay attention to packages detected by one tool but not the other - document these discrepancies.  
> 3. Consider the "lying SBOM" problem when evaluating tool accuracy.

> **SCA Best Practices**  
> 1. Always cross-reference critical vulnerabilities between tools before taking action.  
> 2. Evaluate both direct and transitive dependency risks in your analysis.  
> 3. Consider CVSS scores, exploitability, and context when prioritizing vulnerabilities.  
> 4. Document false positives and tool-specific detection patterns.

> **Comparison Methodology**  
> 1. Use consistent container image and execution environment for fair comparison.  
> 2. Focus on practical operational differences, not just feature checklists.  
> 3. Consider maintenance overhead and community support in your analysis.  
> 4. Provide specific use case recommendations based on quantitative findings.