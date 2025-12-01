# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

![difficulty](https://img.shields.io/badge/difficulty-intermediate-orange)
![topic](https://img.shields.io/badge/topic-SAST%20%26%20DAST-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Perform Static Application Security Testing (SAST) using Semgrep and Dynamic Application Security Testing (DAST) using multiple tools (ZAP, Nuclei, Nikto, SQLmap) against OWASP Juice Shop to identify security vulnerabilities and compare tool effectiveness.  
> **Deliverable:** A PR from `feature/lab5` to the course repo with `labs/submission5.md` containing SAST findings, DAST results from multiple tools, and security recommendations. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Performing **Static Application Security Testing (SAST)** with **Semgrep** using Docker containers
- Conducting **Dynamic Application Security Testing (DAST)** using multiple specialized tools
- **Tool comparison analysis** between different DAST tools (ZAP, Nuclei, Nikto, SQLmap)
- **Vulnerability correlation** between SAST and DAST findings
- **Security tool selection** for different vulnerability types

These skills are essential for DevSecOps integration and security testing automation.

> Use the OWASP Juice Shop (`bkimminich/juice-shop:v19.0.0`) as your target application, with access to its source code for SAST analysis.

---

## Tasks

### Task 1 — Static Application Security Testing with Semgrep (3 pts)
⏱️ **Estimated time:** 15-20 minutes

**Objective:** Perform SAST analysis using Semgrep to identify security vulnerabilities in the OWASP Juice Shop source code.

#### 1.1: Setup SAST Environment

1. **Prepare Working Directory and Clone Source:**

   ```bash
   mkdir -p labs/lab5/{semgrep,zap,nuclei,nikto,sqlmap,analysis}
   git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop
   ```

#### 1.2: SAST Analysis with Semgrep

1. **Run Semgrep Security Scan:**

   ```bash
   docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
     -v "$(pwd)/labs/lab5/semgrep":/output \
     semgrep/semgrep:latest \
     semgrep --config=p/security-audit --config=p/owasp-top-ten \
     --json --output=/output/semgrep-results.json /src

   # Generate human-readable security report
   docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
     -v "$(pwd)/labs/lab5/semgrep":/output \
     semgrep/semgrep:latest \
     semgrep --config=p/security-audit --config=p/owasp-top-ten \
     --text --output=/output/semgrep-report.txt /src
   ```
   

#### 1.3: SAST Results Analysis

1. **Analyze SAST Results:**

   ```bash
   echo "=== SAST Analysis Report ===" > labs/lab5/analysis/sast-analysis.txt
   jq '.results | length' labs/lab5/semgrep/semgrep-results.json >> labs/lab5/analysis/sast-analysis.txt
   ```

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

---

### Task 2 — Dynamic Application Security Testing with Multiple Tools (5 pts)
⏱️ **Estimated time:** 60-90 minutes (scans run in background)

**Objective:** Perform DAST analysis using ZAP (with authentication) and specialized tools (Nuclei, Nikto, SQLmap) to compare their effectiveness.

#### 2.1: Setup DAST Environment

1. **Start OWASP Juice Shop:**

   ```bash
   docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
   
   # Wait for application to start
   sleep 10
   
   # Verify it's running
   curl -s http://localhost:3000 | head -n 5
   ```
   

#### 2.2: OWASP ZAP Unauthenticated Scanning
⏱️ ~5 minutes

1. **Run Unauthenticated ZAP Baseline Scan:**

   ```bash
   # Baseline scan without authentication
   docker run --rm --network host \
     -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
     zaproxy/zap-stable:latest \
     zap-baseline.py -t http://localhost:3000 \
     -r report-noauth.html -J zap-report-noauth.json
   ```
   

   > This baseline scan discovers vulnerabilities in publicly accessible endpoints.

#### 2.3: OWASP ZAP Authenticated Scanning
⏱️ ~20-30 minutes

> **⚠️ Important:** Authenticated scanning uses ZAP's Automation Framework. The configuration file is pre-created in `labs/lab5/scripts/zap-auth.yaml` for consistency.

1. **Verify Authentication Endpoint:**

   ```bash
   # Test login with admin credentials (default Juice Shop account)
   curl -s -X POST http://localhost:3000/rest/user/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@juice-sh.op","password":"admin123"}' | jq '.authentication.token'
   ```

   You should see a JWT token returned, confirming the endpoint works.

2. **Run Authenticated ZAP Scan:**

   ```bash
   docker run --rm --network host \
     -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
     zaproxy/zap-stable:latest \
     zap.sh -cmd \
      -autorun /zap/wrk/scripts/zap-auth.yaml
   ```

   <details>
   <summary>📝 ZAP Configuration Explained</summary>

   The `labs/lab5/scripts/zap-auth.yaml` file configures:
   - **Authentication**: JSON-based login with admin credentials
   - **Session Management**: Cookie-based session tracking
   - **Verification**: Uses regex to detect successful login (looks for "authentication" in response)
   - **Scanning Jobs**: Spider → AJAX Spider → Passive Scan → Active Scan → Report Generation
   - **AJAX Spider**: Discovers ~10x more URLs by executing JavaScript (finds dynamic endpoints)

   </details>
   

   **What this scan discovers:**
   - 🔓 **Authenticated endpoints** like `/rest/admin/application-configuration`
   - 🛒 **User-specific features** (basket, orders, payment, profile)
   - 🔐 **Admin panel** vulnerabilities
   - 📊 **10x more URLs** than unauthenticated scan (AJAX spider finds ~1,200 URLs)

   **Expected output:**
   ```
   Job spider found 112 URLs
   Job spiderAjax found 1,199 URLs  # AJAX spider discovers much more!
   Job report generated report /zap/wrk/report-auth.html
   ```

   > **Key Insight:** Look for `http://localhost:3000/rest/admin/` endpoints in the output - these prove authentication is working!

3. **Compare Authenticated vs Unauthenticated Scans:**

   Run: `bash labs/lab5/scripts/compare_zap.sh`

#### 2.4: Multi-Tool Specialized Scanning

> **💡 Networking Note:** Docker networking varies by tool:
> - `--network host`: Shares host's network (ZAP, Nuclei, Nikto)
> - `--network container:NAME`: Shares another container's network namespace (SQLmap)
> Use the pattern shown in each command for best compatibility.

1. **Nuclei Template-Based Scan:** ⏱️ ~5 minutes

   ```bash
   docker run --rm --network host \
     -v "$(pwd)/labs/lab5/nuclei":/app \
     projectdiscovery/nuclei:latest \
     -ut -u http://localhost:3000 \
     -jsonl -o /app/nuclei-results.json
   ```
   

2. **Nikto Web Server Scan:** ⏱️ ~5-10 minutes

   ```bash
   docker run --rm --network host \
     -v "$(pwd)/labs/lab5/nikto":/tmp \
     sullo/nikto:latest \
     -h http://localhost:3000 -o /tmp/nikto-results.txt
   ```
   

3. **SQLmap SQL Injection Test:** ⏱️ ~10-20 minutes per endpoint

   > **Network Solution:** Share the network namespace with Juice Shop container so SQLmap can access `localhost:3000`

   ```bash
   # Test both vulnerable endpoints - Search (GET) and Login (POST JSON)
   docker run --rm \
     --network container:juice-shop-lab5 \
     -v "$(pwd)/labs/lab5/sqlmap":/output \
     sqlmapproject/sqlmap \
     -u "http://localhost:3000/rest/products/search?q=*" \
     --dbms=sqlite --batch --level=3 --risk=2 \
     --technique=B --threads=5 --output-dir=/output

   docker run --rm \
     --network container:juice-shop-lab5 \
     -v "$(pwd)/labs/lab5/sqlmap":/output \
     sqlmapproject/sqlmap \
     -u "http://localhost:3000/rest/user/login" \
     --data '{"email":"*","password":"test"}' \
     --method POST \
     --headers='Content-Type: application/json' \
     --dbms=sqlite --batch --level=5 --risk=3 \
     --technique=BT --threads=5 --output-dir=/output \
     --dump
   ```
   

   **How this works:**

   **Networking:**
   - `--network container:juice-shop-lab5` - Shares network namespace with Juice Shop container
   - Inside SQLmap container, `localhost:3000` now directly reaches Juice Shop (no DNS/port forwarding needed)

   **Endpoint 1 - Search (GET):**
   - URL: `http://localhost:3000/rest/products/search?q=*`
   - `*` marks the `q` parameter for injection testing
   - `--technique=B` - Boolean-based blind SQL injection (true/false responses)
   - Faster scan, detects logic-based vulnerabilities

   **Endpoint 2 - Login (POST JSON):**
   - URL: `http://localhost:3000/rest/user/login`
   - Tests JSON `email` parameter with `*` marker
   - `--technique=BT` - Boolean + Time-based blind SQL injection
   - Time-based detects when responses take longer (SQL `SLEEP()` commands)
   - More thorough, bypasses authentication without valid credentials

   **Database & Extraction:**
   - `--dbms=sqlite` - Optimizes for SQLite-specific syntax (Juice Shop uses SQLite)
   - `--dump` - Automatically extracts database contents after confirming vulnerability
   - Will extract Users table including emails and bcrypt password hashes

   **Shell escaping:**
   - Single quotes `'...'` wrap the entire shell command to avoid JSON escaping issues

   > **Expected Results:** SQLmap will find SQL injection in both endpoints and extract ~20 user accounts with hashed passwords. Scan duration: 10-20 minutes.

#### 2.5: DAST Results Analysis

1. **Compare Tool Results:**

   Run: `bash labs/lab5/scripts/summarize_dast.sh`

In `labs/submission5.md`, document:

**Required Sections:**

1. Authenticated vs Unauthenticated Scanning:
  - Compare URL discovery count (use numbers from `compare_zap.sh` output)
  - List examples of admin/authenticated endpoints discovered
  - Explain why authenticated scanning matters for security testing

2. Tool Comparison Matrix:
  - Create a comparison table with columns: Tool | Findings | Severity Breakdown | Best Use Case
  - Include all 4 DAST tools: ZAP, Nuclei, Nikto, SQLmap
  - Use actual numbers from your scan outputs

3. Tool-Specific Strengths:
  - Describe what each tool excels at:
    - **ZAP**: (e.g., comprehensive scanning, authentication support)
    - **Nuclei**: (e.g., speed, known CVE detection)
    - **Nikto**: (e.g., server misconfiguration)
    - **SQLmap**: (e.g., deep SQL injection analysis)
  - Provide 1-2 example findings from each tool

---

### Task 3 — SAST/DAST Correlation and Security Assessment (2 pts)
⏱️ **Estimated time:** 20-30 minutes

**Objective:** Correlate findings from SAST and DAST approaches to provide comprehensive security assessment.

#### 3.1: SAST/DAST Correlation

1. **Create Correlation Analysis:**

   ```bash
   echo "=== SAST/DAST Correlation Report ===" > labs/lab5/analysis/correlation.txt
   
   # Count SAST findings
   sast_count=$(jq '.results | length' labs/lab5/semgrep/semgrep-results.json 2>/dev/null || echo "0")
   
   # Count DAST findings from all tools
   zap_med=$(grep -c "class=\"risk-2\"" labs/lab5/zap/report-auth.html 2>/dev/null)
   zap_high=$(grep -c "class=\"risk-3\"" labs/lab5/zap/report-auth.html 2>/dev/null)
   zap_total=$(( (zap_med / 2) + (zap_high / 2) ))
   nuclei_count=$(wc -l < labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
   nikto_count=$(grep -c '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo '0')
   
   # Count SQLmap findings
   sqlmap_csv=$(find labs/lab5/sqlmap -name "results-*.csv" 2>/dev/null | head -1)
   if [ -f "$sqlmap_csv" ]; then
     sqlmap_count=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l)
   else
     sqlmap_count=0
   fi
   
   echo "Security Testing Results Summary:" >> labs/lab5/analysis/correlation.txt
   echo "" >> labs/lab5/analysis/correlation.txt
   echo "SAST (Semgrep): $sast_count code-level findings" >> labs/lab5/analysis/correlation.txt
   echo "DAST (ZAP authenticated): $zap_total alerts" >> labs/lab5/analysis/correlation.txt
   echo "DAST (Nuclei): $nuclei_count template matches" >> labs/lab5/analysis/correlation.txt
   echo "DAST (Nikto): $nikto_count server issues" >> labs/lab5/analysis/correlation.txt
   echo "DAST (SQLmap): $sqlmap_count SQL injection vulnerabilities" >> labs/lab5/analysis/correlation.txt
   echo "" >> labs/lab5/analysis/correlation.txt
   
   echo "Key Insights:" >> labs/lab5/analysis/correlation.txt
   echo "" >> labs/lab5/analysis/correlation.txt
   echo "SAST (Static Analysis):" >> labs/lab5/analysis/correlation.txt
   echo "  - Finds code-level vulnerabilities before deployment" >> labs/lab5/analysis/correlation.txt
   echo "  - Detects: hardcoded secrets, SQL injection patterns, insecure crypto" >> labs/lab5/analysis/correlation.txt
   echo "  - Fast feedback in development phase" >> labs/lab5/analysis/correlation.txt
   echo "" >> labs/lab5/analysis/correlation.txt
   echo "DAST (Dynamic Analysis):" >> labs/lab5/analysis/correlation.txt
   echo "  - Finds runtime configuration and deployment issues" >> labs/lab5/analysis/correlation.txt
   echo "  - Detects: missing security headers, authentication flaws, server misconfigs" >> labs/lab5/analysis/correlation.txt
   echo "  - Authenticated scanning reveals 60%+ more attack surface" >> labs/lab5/analysis/correlation.txt
   echo "" >> labs/lab5/analysis/correlation.txt
   echo "Recommendation: Use BOTH approaches for comprehensive security coverage" >> labs/lab5/analysis/correlation.txt
   
   cat labs/lab5/analysis/correlation.txt
   ```



In `labs/submission5.md`, document:

**Required Sections:**

1. SAST vs DAST Comparison:
  - Compare total findings: SAST count vs combined DAST count
  - Identify 2-3 vulnerability types found ONLY by SAST
  - Identify 2-3 vulnerability types found ONLY by DAST
  - Explain why each approach finds different things

---

## Acceptance Criteria

- ✅ Branch `feature/lab5` exists with commits for each task.
- ✅ File `labs/submission5.md` contains required analysis for Tasks 1-3.
- ✅ SAST analysis completed with Semgrep.
- ✅ DAST analysis completed with ZAP and specialized tools.
- ✅ SAST/DAST correlation analysis completed.
- ✅ All generated reports, configurations, and analysis files committed.
- ✅ PR from `feature/lab5` → **course repo main branch** is open.
- ✅ PR link submitted via Moodle before the deadline.

---

## Cleanup

After completing the lab:

```bash
# Stop and remove containers
docker stop juice-shop-lab5
docker rm juice-shop-lab5

# Optional: Remove large source code directory (~200MB)
# rm -rf labs/lab5/semgrep/juice-shop

# Check disk space recovered
docker system df
```

---

## How to Submit

1. Create a branch for this lab and push it to your fork:

   ```bash
   git switch -c feature/lab5
   # create labs/submission5.md with your findings
   git add labs/submission5.md labs/lab5/
   git commit -m "docs: add lab5 submission - SAST/multi-approach DAST security analysis"
   git push -u origin feature/lab5
   ```

2. Open a PR from your fork's `feature/lab5` branch → **course repository's main branch**.

3. In the PR description, include:

   ```text
   - [x] Task 1 done — SAST Analysis with Semgrep
   - [x] Task 2 done — DAST Analysis (ZAP + Nuclei + Nikto + SQLmap)
   - [x] Task 3 done — SAST/DAST Correlation
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Rubric (10 pts)

| Criterion                                                           | Points |
| ------------------------------------------------------------------- | -----: |
| Task 1 — SAST with Semgrep + basic analysis                         |  **3** |
| Task 2 — DAST analysis (ZAP + Nuclei + Nikto + SQLmap) + comparison |  **5** |
| Task 3 — SAST/DAST correlation + recommendations                    |  **2** |
| **Total**                                                           | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission5.md`.
- Include evidence from tool outputs to support your analysis.
- Focus on practical insights about when to use each tool in a DevSecOps workflow.
- Provide actionable security recommendations based on findings.

<details>
<summary>Tool Comparison Reference</summary>

**SAST Tool:**
- **Semgrep**: Static code analysis using pattern-based security rulesets

**DAST Tools:**
- **ZAP**: Comprehensive web application scanner with integrated reporting
- **Nuclei**: Fast template-based vulnerability scanner with community templates
- **Nikto**: Web server vulnerability scanner for server misconfigurations
- **SQLmap**: Specialized SQL injection testing tool

**Tool Selection in DevSecOps:**
- **Semgrep**: Early in development pipeline (pre-commit, PR checks)
- **ZAP**: Staging/QA environment for comprehensive web app testing
- **Nuclei**: Quick scans for known CVEs in any environment
- **Nikto**: Web server security assessment during deployment
- **SQLmap**: Targeted SQL injection testing when SAST/DAST indicate database issues

</details>

<details>
<summary>Expected Vulnerability Categories</summary>

**SAST typically finds:**
- Hardcoded credentials and API keys in source code
- Insecure cryptographic usage patterns
- Code-level injection vulnerabilities (SQL, command, etc.)
- Path traversal and insecure file handling

**DAST typically finds:**
- Authentication and session management issues
- Runtime configuration problems (security headers, SSL/TLS)
- XSS, CSRF, and other runtime exploitation vectors
- Information disclosure through HTTP responses

</details>
