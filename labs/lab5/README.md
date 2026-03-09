# Lab 5 - SAST & DAST Security Analysis Results

## Summary

This directory contains the results of comprehensive security testing performed on OWASP Juice Shop v19.0.0 using both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) approaches.

## Directory Structure

```
lab5/
├── semgrep/              # SAST results
│   ├── semgrep-results.json
│   ├── semgrep-report.txt
│   └── juice-shop/       # Source code (not committed - too large)
├── zap/                  # ZAP DAST results
│   ├── report-noauth.html
│   ├── report-auth.html
│   ├── zap-report-noauth.json
│   └── zap-report-auth.json
├── nuclei/               # Nuclei template-based scan
│   ├── nuclei-results.json
│   └── nuclei-results.txt
├── nikto/                # Nikto web server scan
│   └── nikto-results.txt
├── sqlmap/               # SQLmap SQL injection testing
│   └── results-*.csv
├── scripts/              # Analysis scripts
│   ├── zap-auth.yaml
│   ├── compare_zap.sh
│   └── summarize_dast.sh
└── analysis/             # Correlation analysis
    ├── sast-analysis.txt
    └── correlation.txt
```

## Key Findings

### SAST (Semgrep)
- **Total Findings:** 25 vulnerabilities
- **Critical Issues:**
  - SQL Injection in login and search endpoints
  - Code Injection via eval() in user profile
  - Hardcoded JWT secrets
  - Path Traversal vulnerabilities

### DAST Results

#### ZAP (Authenticated)
- **Total Alerts:** 69
- **URLs Discovered:** 1,002 (via AJAX spider)
- **Key Findings:** CSP missing, CORS misconfiguration, XSS vectors

#### Nuclei
- **Total Findings:** 8
- **Severity:** 1 High, 4 Medium, 3 Info
- **Key Findings:** Weak JWT, CORS issues, exposed directories

#### Nikto
- **Total Findings:** 12
- **Key Findings:** Server information leaks, directory exposure, uncommon headers

#### SQLmap
- **SQL Injection:** 1 confirmed vulnerability
- **Endpoint:** `/rest/products/search?q=*`
- **Database:** SQLite confirmed

## Tools Used

1. **Semgrep** - Static code analysis
2. **OWASP ZAP** - Comprehensive web app scanner
3. **Nuclei** - Template-based vulnerability scanner
4. **Nikto** - Web server scanner
5. **SQLmap** - SQL injection testing tool

## How to Reproduce

See `../lab5.md` for detailed instructions on running each tool.

## Analysis

The complete analysis and recommendations are available in `../submission5.md`.

### Key Insights

- **SAST** identified code-level vulnerabilities that DAST cannot detect (hardcoded secrets, code patterns)
- **DAST** validated exploitability and found runtime configuration issues
- **Authenticated scanning** revealed 67% more attack surface than unauthenticated testing
- **Combined approach** provides comprehensive security coverage

## Cleanup

To remove large files:
```bash
rm -rf labs/lab5/semgrep/juice-shop  # ~200MB source code
```
