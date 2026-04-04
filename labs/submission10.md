# Lab 10 — Vulnerability Management & Response with DefectDojo

- The majority of findings are **active (open)**, with no closed/mitigated items observed. Most vulnerabilities fall into the **High (62)** and **Medium (33)** severity categories, followed by **Critical (11)**, **Low (4)**, and **Informational (35)**.

- The dominant source of findings is **Grype (dependency scanning)**, contributing the vast majority (~120 findings), while **Nuclei** contributes a smaller portion (~25 findings). This indicates that most issues originate from vulnerable dependencies rather than application logic or dynamic testing.

- No SLA breaches or upcoming deadlines (within 14 days) were identified in the dataset, suggesting that SLA tracking is either not configured or no due dates have been assigned. I saw SLA in range from 7 to 30. Also there are 90, 91 and 120 SLAs.

- The most common CWE category is **CWE-0 (unspecified)**, which dominates the dataset, followed by a smaller number of **CWE-200 (Information Exposure)** findings. This indicates limited classification of vulnerabilities into detailed CWE categories.

The most common are the following:

| # | Vulnerability | File Path | Line | Severity |
|---|---|---|---|---|
|1|SQL Injection in Sequelize query|`src/routes/search.ts`|23|High|
|2|SQL Injection in login logic|`src/routes/login.ts`|34|High|
|3|Path Traversal via file serving|`src/routes/fileServer.ts`|33|High|
|4|Unquoted template variable (XSS risk)|`frontend/src/app/navbar/navbar.component.html`|17|Medium|
|5|Hardcoded secret value|`lib/insecurity.ts`|56|Medium|

- Overall, the application demonstrates a **moderate-to-high risk posture**, primarily driven by dependency vulnerabilities, with relatively few low-severity issues and no evidence of remediation progress yet.