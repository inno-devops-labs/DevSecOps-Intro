#!/usr/bin/env bash
set -euo pipefail

# run_all_scans.sh
# Master script to run all security scans for Lab 5
# Run this from the repository root directory

echo "=========================================="
echo "Lab 5 - SAST & DAST Security Analysis"
echo "=========================================="
echo ""
echo "This script will run all required security scans."
echo "Total estimated time: ~90 minutes"
echo ""

# Verify we're in the correct directory
if [[ ! -d "labs/lab5" ]]; then
  echo "Error: Please run this script from the repository root directory"
  exit 1
fi

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker is not running. Please start Docker and try again."
  exit 1
fi

echo "Step 1: Setup"
echo "=============="
echo ""

# Check if Juice Shop source already cloned
if [[ ! -d "labs/lab5/semgrep/juice-shop" ]]; then
  echo "Cloning OWASP Juice Shop source code for SAST..."
  git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop
  echo "✓ Source code cloned"
else
  echo "✓ Juice Shop source already exists"
fi
echo ""

# Check if Juice Shop container is running
if docker ps | grep -q juice-shop-lab5; then
  echo "✓ Juice Shop container already running"
else
  echo "Starting OWASP Juice Shop container..."
  docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
  echo "Waiting for application to start (10 seconds)..."
  sleep 10
  
  # Verify it's running
  if curl -s http://localhost:3000 >/dev/null; then
    echo "✓ Juice Shop is running at http://localhost:3000"
  else
    echo "⚠ Warning: Juice Shop may not be ready yet. Check with: curl http://localhost:3000"
  fi
fi
echo ""
echo "Press Enter to continue with SAST scanning..."
read -r

echo ""
echo "Step 2: SAST with Semgrep (~10 minutes)"
echo "========================================"
echo ""

if [[ ! -f "labs/lab5/semgrep/semgrep-results.json" ]]; then
  echo "Running Semgrep security audit..."
  
  # JSON results
  docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
    -v "$(pwd)/labs/lab5/semgrep":/output \
    semgrep/semgrep:latest \
    semgrep --config=p/security-audit --config=p/owasp-top-ten \
    --json --output=/output/semgrep-results.json /src
  
  # Human-readable report
  docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
    -v "$(pwd)/labs/lab5/semgrep":/output \
    semgrep/semgrep:latest \
    semgrep --config=p/security-audit --config=p/owasp-top-ten \
    --text --output=/output/semgrep-report.txt /src
  
  # Generate analysis
  echo "=== SAST Analysis Report ===" > labs/lab5/analysis/sast-analysis.txt
  jq '.results | length' labs/lab5/semgrep/semgrep-results.json >> labs/lab5/analysis/sast-analysis.txt
  
  echo "✓ SAST scan complete"
  echo "  Results: labs/lab5/semgrep/semgrep-results.json"
  echo "  Report: labs/lab5/semgrep/semgrep-report.txt"
else
  echo "✓ SAST results already exist"
fi
echo ""
echo "Press Enter to continue with DAST scanning..."
read -r

echo ""
echo "Step 3: DAST - ZAP Unauthenticated (~5 minutes)"
echo "================================================"
echo ""

if [[ ! -f "labs/lab5/zap/report-noauth.html" ]]; then
  echo "Running ZAP baseline scan (unauthenticated)..."
  docker run --rm --network host \
    -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
    zaproxy/zap-stable:latest \
    zap-baseline.py -t http://localhost:3000 \
    -r report-noauth.html -J zap-report-noauth.json
  
  echo "✓ ZAP unauthenticated scan complete"
  echo "  Report: labs/lab5/zap/report-noauth.html"
else
  echo "✓ ZAP unauthenticated results already exist"
fi
echo ""
echo "Press Enter to continue with authenticated ZAP scanning..."
read -r

echo ""
echo "Step 4: DAST - ZAP Authenticated (~30 minutes)"
echo "==============================================="
echo ""
echo "This scan will take approximately 30 minutes."
echo "It will discover authenticated endpoints and test admin functionality."
echo ""

if [[ ! -f "labs/lab5/zap/report-auth.html" ]]; then
  echo "Running ZAP authenticated scan..."
  docker run --rm --network host \
    -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
    zaproxy/zap-stable:latest \
    zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml
  
  echo "✓ ZAP authenticated scan complete"
  echo "  Report: labs/lab5/zap/report-auth.html"
  echo ""
  
  # Run comparison
  echo "Comparing authenticated vs unauthenticated scans..."
  bash labs/lab5/scripts/compare_zap.sh
else
  echo "✓ ZAP authenticated results already exist"
  if [[ ! -f "labs/lab5/analysis/zap-comparison.txt" ]]; then
    echo "Running comparison..."
    bash labs/lab5/scripts/compare_zap.sh
  fi
fi
echo ""
echo "Press Enter to continue with Nuclei scanning..."
read -r

echo ""
echo "Step 5: DAST - Nuclei (~5 minutes)"
echo "==================================="
echo ""

if [[ ! -f "labs/lab5/nuclei/nuclei-results.json" ]]; then
  echo "Running Nuclei template-based scan..."
  docker run --rm --network host \
    -v "$(pwd)/labs/lab5/nuclei":/app \
    projectdiscovery/nuclei:latest \
    -ut -u http://localhost:3000 \
    -jsonl -o /app/nuclei-results.json
  
  echo "✓ Nuclei scan complete"
  echo "  Results: labs/lab5/nuclei/nuclei-results.json"
else
  echo "✓ Nuclei results already exist"
fi
echo ""
echo "Press Enter to continue with Nikto scanning..."
read -r

echo ""
echo "Step 6: DAST - Nikto (~10 minutes)"
echo "==================================="
echo ""

if [[ ! -f "labs/lab5/nikto/nikto-results.txt" ]]; then
  echo "Running Nikto web server scan..."
  docker run --rm --network host \
    -v "$(pwd)/labs/lab5/nikto":/tmp \
    sullo/nikto:latest \
    -h http://localhost:3000 -o /tmp/nikto-results.txt
  
  echo "✓ Nikto scan complete"
  echo "  Results: labs/lab5/nikto/nikto-results.txt"
else
  echo "✓ Nikto results already exist"
fi
echo ""
echo "Press Enter to continue with SQLmap scanning..."
read -r

echo ""
echo "Step 7: DAST - SQLmap (~30 minutes)"
echo "===================================="
echo ""
echo "This will test SQL injection on two endpoints:"
echo "  1. Search endpoint (GET parameter)"
echo "  2. Login endpoint (POST JSON)"
echo ""

echo "Testing search endpoint..."
docker run --rm \
  --network container:juice-shop-lab5 \
  -v "$(pwd)/labs/lab5/sqlmap":/output \
  sqlmapproject/sqlmap \
  -u "http://localhost:3000/rest/products/search?q=*" \
  --dbms=sqlite --batch --level=3 --risk=2 \
  --technique=B --threads=5 --output-dir=/output

echo ""
echo "Testing login endpoint (this may take longer)..."
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

echo "✓ SQLmap scans complete"
echo ""

echo ""
echo "Step 8: Generate Analysis Reports"
echo "=================================="
echo ""

echo "Generating DAST summary..."
bash labs/lab5/scripts/summarize_dast.sh

echo ""
echo "Generating correlation analysis..."

# Create correlation report
echo "=== SAST/DAST Correlation Report ===" > labs/lab5/analysis/correlation.txt

# Count SAST findings
sast_count=$(jq '.results | length' labs/lab5/semgrep/semgrep-results.json 2>/dev/null || echo "0")

# Count DAST findings from all tools
zap_med=$(grep -c "class=\"risk-2\"" labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
zap_high=$(grep -c "class=\"risk-3\"" labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
zap_total=$(( (zap_med / 2) + (zap_high / 2) ))
nuclei_count=$(wc -l < labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
nuclei_count=$(echo "$nuclei_count" | tr -d ' ')
nikto_count=$(grep -c '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo '0')

# Count SQLmap findings
sqlmap_csv=$(find labs/lab5/sqlmap -name "*.csv" 2>/dev/null | head -1)
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

cat >> labs/lab5/analysis/correlation.txt <<'EOFCORR'
Key Insights:

SAST (Static Analysis):
  - Finds code-level vulnerabilities before deployment
  - Detects: hardcoded secrets, SQL injection patterns, insecure crypto
  - Fast feedback in development phase

DAST (Dynamic Analysis):
  - Finds runtime configuration and deployment issues
  - Detects: missing security headers, authentication flaws, server misconfigs
  - Authenticated scanning reveals 60%+ more attack surface

Recommendation: Use BOTH approaches for comprehensive security coverage
EOFCORR

cat labs/lab5/analysis/correlation.txt

echo ""
echo "✓ All analysis reports generated"
echo ""

echo "=========================================="
echo "All Scans Complete!"
echo "=========================================="
echo ""
echo "Next Steps:"
echo "1. Review all scan results in labs/lab5/"
echo "2. Open labs/submission5.md and fill in all sections marked with [...]"
echo "3. Use data from:"
echo "   - labs/lab5/semgrep/semgrep-results.json"
echo "   - labs/lab5/zap/report-auth.html (open in browser)"
echo "   - labs/lab5/analysis/*.txt"
echo ""
echo "4. Create git branch and commit:"
echo "   git switch -c feature/lab5"
echo "   git add labs/submission5.md labs/lab5/"
echo "   git commit -m 'docs: add lab5 submission - SAST/multi-approach DAST security analysis'"
echo "   git push -u origin feature/lab5"
echo ""
echo "5. Open PR and submit via Moodle"
echo ""
echo "Generated files:"
echo "  - SAST: labs/lab5/semgrep/semgrep-results.json"
echo "  - DAST: labs/lab5/zap/report-auth.html"
echo "  - Analysis: labs/lab5/analysis/correlation.txt"
echo ""
