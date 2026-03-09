# Submission 5 --- SAST vs DAST Comparison

## SAST vs DAST Comparison

### Total Findings Comparison

Static Application Security Testing (SAST) analyzes the application
source code without executing the program. Dynamic Application Security
Testing (DAST) analyzes the running application by sending requests and
observing responses.

- **Total SAST findings:** 25
- **Total DAST findings (combined tools):** 84

In this specific lab, DAST found more issues because the target (Juice Shop) is intentionally riddled with runtime vulnerabilities and misconfigurations that are easily triggered by automated scanners.

------------------------------------------------------------------------

### Vulnerability Types Found ONLY by SAST

1.  **Hardcoded Secrets**
    -   SAST tools can detect API keys, passwords, or tokens embedded
        directly in the source code.
    -   These are not visible to DAST because they may never appear in
        runtime responses.
2.  **Insecure Cryptographic Usage**
    -   SAST can identify weak algorithms or insecure implementations in
        the code.
    -   DAST cannot easily detect these unless they affect observable
        behavior.
3.  **Dead Code Security Issues**
    -   Vulnerabilities inside code paths that are not executed during
        testing can still be detected by SAST.

------------------------------------------------------------------------

### Vulnerability Types Found ONLY by DAST

1.  **SQL Injection**
    -   DAST tools can detect SQL injection by sending malicious input
        and observing database-related errors or behavior.
2.  **Cross‑Site Scripting (XSS)**
    -   DAST discovers XSS by injecting scripts into inputs and
        verifying whether they execute in the browser.
3.  **Server Misconfiguration**
    -   DAST can identify exposed headers, insecure cookies, or other
        runtime configuration issues that are not visible in source
        code.

------------------------------------------------------------------------

### Why Each Approach Finds Different Things

**SAST** works directly with the application's source code. This allows
it to analyze internal logic, data flows, and code structures. Because
of this, it can detect vulnerabilities that exist in the code even if
they are never triggered during runtime.

**DAST**, on the other hand, interacts with the application while it is
running. It simulates real attacks and observes the system's responses.
This makes it effective at finding vulnerabilities that appear only
during execution, such as injection attacks or misconfigured servers.

In practice, both approaches complement each other. SAST provides early
detection during development, while DAST validates real-world behavior
and security of the deployed application.
