### Lab 10 — Vulnerability Management & Response with DefectDojo

## Key Metrics

*   **Total Vulnerability Count:** 292 Open findings were aggregated. Currently **0** findings have been closed, indicating a significant security debt and the need for a focused remediation sprint.
*   **Severity Distribution:** The stack is heavily weighted toward high-risk issues, with **21 Critical** and **152 High** findings. This indicates an extremely high attack surface.
    *   **Verification Status:** 143 findings (approx. 49%) were automatically verified upon import, while 149 findings remain "unverified," requiring manual security analyst triage.

*   **Findings Per Tool:**

| Security Tool | Total Findings | Active (Verified) | Status |
| :--- | :--- | :--- | :--- |
| **Trivy Scan** | 147 | 147 (143) | Most verified findings; targets OS/Library vulnerabilities. |
| **Anchore Grype** | 120 | 120 (0) | High volume of deep dependency vulnerabilities. |
| **Semgrep JSON** | 25 | 25 (0) | Precise code-level insecure pattern identification. |
| **Nuclei / ZAP** | 0* | 0 (0) | *Note: Active dynamic scans yielded 0 additional unique findings after deduplication.* |

*   **SLA & Governance Status:**
    *   **SLA Breaches:** 0. All findings are currently compliant as they were ingested on April 13, 2026.
    *   **Upcoming Deadlines:** All 21 Critical findings will breach SLA within 30 days if not mitigated, creating a high-pressure window for the engineering team.

*   **Top Recurring CWE Categories:**

| CWE ID | Count | Name | Impact / Context |
| :--- | :--- | :--- | :--- |
| **CWE-1333** | 29 | ReDoS | Inefficient Regex; high risk of server crashes in Node.js runtime. |
| **CWE-407** | 13 | Algorithmic Complexity | Resource exhaustion leading to potential Denial of Service (DoS). |
| **CWE-79** | 11 | XSS | Cross-site Scripting; the primary vector for user session hijacking. |
| **CWE-22** | 11 | Path Traversal | Risk of unauthorized access to sensitive files outside web root. |
| **CWE-89** | 6 | SQL Injection | Critical risk of total database compromise via malformed queries. |

## Program Analysis & Insights

*   **Centralization Value:** DefectDojo successfully consolidated data from four disparate security tools into a single pane of glass. This revealed that while Trivy provides the most "noise" (volume), the combined logic of XSS and Injection (CWE-79/89) represents the most exploitable business risk.
*   **Deduplication Efficiency:** By aggregating scans, the platform helped identify overlapping vulnerabilities across different layers (Container vs. Code), preventing redundant work for the development team.
*   **Remediation Strategy:** The immediate priority must be the **21 Critical findings** related to SQL Injection and XSS. Container-layer vulnerabilities (Grype/Trivy) should be addressed via base-image updates to resolve bulk findings efficiently.
