# Task 1

In `labs/submission5.md`, document:

**Required Sections:**

1. SAST Tool Effectiveness:
  - Describe what types of vulnerabilities Semgrep detected
  - Evaluate coverage (how many files scanned, how many findings)

2. Critical Vulnerability Analysis:
  - List **5 most critical findings** from Semgrep results
  - For each vulnerability include:
    - Vulnerability type (e.g., SQL Injection, Hardcoded Secret)
    - File path and line number
    - Severity level

## SAST Effectiveness

Semgrep detected mainly injection and storage vulnerabilities (user-tainted input, credentials store). Out of 1014 tracked files, it found 26 vulnerabilities.

## Critical Vulnerability Analysis

Top-5:
- Variable interpolation, ``yaml.github-actions.security.run-shell-injection.run-shell-injection``, line 24
- SQL injection, ``/src/data/static/codefixes/dbSchemaChallenge_1.ts``, line 5
- SQL injection, ``/src/data/static/codefixes/dbSchemaChallenge_3.ts``, line 11
- SQL injection, ``/src/data/static/codefixes/unionSqlInjectionChallenge_1.ts``, line 6
- SQL injection, ``/src/data/static/codefixes/unionSqlInjectionChallenge_3.ts``, line 10

# Task 2

## ZAP Scan Comparison: Authenticated vs Unauthenticated
Generated: Вт 12 мая 2026 16:28:08 MSK

Unauthenticated Scan:
-  Total alerts: 12
-  High: 0
-  Medium: 2
-  Low: 6
-  Info: 4
-  Unique URLs with findings: 19

Authenticated Scan:
-  Total alerts: 13
-  High: 1
-  Medium: 4
-  Low: 4
-  Info: 4
-  Unique URLs with findings: 23

Example admin endpoint: ``http://localhost:3000/rest/admin/application-configuration``

### Why authenticated scanning matters for security testing:
Authenticated scanning lets ZAP test parts of the application that are only available after login, such as user pages, internal forms, and protected API endpoints. This is important because many serious vulnerabilities cannot be detected from public access alone.

## Tool comparison matrix

|Tool|Findings|Severity Breakdown|Best Use Case|
|-|-|-|-|
|ZAP|12(unauth)+13(auth)|1 high 6 med 10 low| Broad DAST for webapp/API in real workflow |
|Nuclei|||Template checks across many targets|
|Nikto|2 error(s) and 80 item(s) reported on remote host|2 errors 80 warns|Basic misconfig/outdated components|
|SQLmap|||Deep SQL injection scan|

Some of the tools didn't work via provided commands.

# Task 3
## SAST/DAST Correlation Report

Security Testing Results Summary:

- SAST (Semgrep): 26 code-level findings
- DAST (ZAP authenticated): 8 alerts
- DAST (Nuclei): 0 template matches
- DAST (Nikto): 82 server issues
- DAST (SQLmap): 0 SQL injection vulnerabilities

## Key Insights:


    SAST (Static Analysis):
    - Finds code-level vulnerabilities before deployment
    - Detects: hardcoded secrets, SQL injection patterns, insecure crypto
    - Fast feedback in development phase

    DAST (Dynamic Analysis):
    - Finds runtime configuration and deployment issues
    - Detects: missing security headers, authentication flaws, server misconfigs
    - Authenticated scanning reveals 60%+ more attack surface

    Recommendation: Use BOTH approaches for comprehensive security coverage

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

