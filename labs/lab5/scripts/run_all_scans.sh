#!/bin/bash
# Automated script to run all Lab 5 security scans
# This script automates the execution of all SAST and DAST scans

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB5_DIR="$(dirname "$SCRIPT_DIR")"
BASE_DIR="$(dirname "$(dirname "$LAB5_DIR")")"

cd "$BASE_DIR"

echo "=== Lab 5 Security Scanning Automation ==="
echo ""

# Check if Juice Shop is running
if ! docker ps | grep -q juice-shop-lab5; then
    echo "Starting Juice Shop container..."
    docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
    echo "Waiting for Juice Shop to start..."
    sleep 15
    curl -s http://localhost:3000 > /dev/null && echo "Juice Shop is ready!" || echo "Warning: Juice Shop may not be ready yet"
else
    echo "Juice Shop container is already running"
fi

echo ""
echo "=== Task 1: SAST Analysis with Semgrep ==="
echo ""

# Check if source code is cloned
if [ ! -d "labs/lab5/semgrep/juice-shop" ]; then
    echo "Cloning Juice Shop source code..."
    git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop
else
    echo "Source code already cloned"
fi

# Run Semgrep scan
echo "Running Semgrep SAST scan (this may take a few minutes)..."
if docker run --rm \
    -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
    -v "$(pwd)/labs/lab5/semgrep":/output \
    semgrep/semgrep:latest \
    semgrep --config=p/security-audit --config=p/owasp-top-ten \
    --json --output=/output/semgrep-results.json /src 2>&1 | tee /tmp/semgrep.log; then
    echo "✓ Semgrep scan completed successfully"
    echo "Results: $(jq '.results | length' labs/lab5/semgrep/semgrep-results.json 2>/dev/null || echo '0') findings"
else
    echo "⚠ Semgrep scan encountered issues. Check /tmp/semgrep.log for details"
    echo "You may need to run Semgrep manually if network issues persist"
fi

# Generate text report
echo "Generating Semgrep text report..."
docker run --rm \
    -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
    -v "$(pwd)/labs/lab5/semgrep":/output \
    semgrep/semgrep:latest \
    semgrep --config=p/security-audit --config=p/owasp-top-ten \
    --text --output=/output/semgrep-report.txt /src 2>/dev/null || echo "Text report generation skipped"

echo ""
echo "=== Task 2: DAST Analysis ==="
echo ""

# ZAP Baseline Scan
echo "Running ZAP baseline scan (unauthenticated)..."
docker run --rm --network host \
    -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
    zaproxy/zap-stable:latest \
    zap-baseline.py -t http://localhost:3000 \
    -r report-noauth.html -J zap-report-noauth.json 2>&1 | tail -5
echo "✓ ZAP baseline scan completed"

# ZAP Authenticated Scan
echo ""
echo "Running ZAP authenticated scan (this will take 20-30 minutes)..."
docker run --rm --network host \
    -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
    zaproxy/zap-stable:latest \
    zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml 2>&1 | tee /tmp/zap-auth.log
echo "✓ ZAP authenticated scan completed"

# Nuclei Scan
echo ""
echo "Running Nuclei scan..."
docker run --rm --network host \
    -v "$(pwd)/labs/lab5/nuclei":/app \
    projectdiscovery/nuclei:latest \
    -ut -u http://localhost:3000 \
    -jsonl -o /app/nuclei-results.json 2>&1 | tail -10
echo "✓ Nuclei scan completed"

# Nikto Scan (try alternative image if default fails)
echo ""
echo "Running Nikto scan..."
if docker run --rm --network host \
    -v "$(pwd)/labs/lab5/nikto":/tmp \
    sullo/nikto:latest \
    -h http://localhost:3000 -o /tmp/nikto-results.txt 2>&1 | tail -10; then
    echo "✓ Nikto scan completed"
else
    echo "⚠ Nikto scan failed. Trying alternative approach..."
    echo "You may need to install Nikto locally or use an alternative scanner"
fi

# SQLmap Scan
echo ""
echo "Running SQLmap scan on search endpoint (this will take 10-20 minutes)..."
docker run --rm \
    --network container:juice-shop-lab5 \
    -v "$(pwd)/labs/lab5/sqlmap":/output \
    sqlmapproject/sqlmap \
    -u "http://localhost:3000/rest/products/search?q=*" \
    --dbms=sqlite --batch --level=3 --risk=2 \
    --technique=B --threads=5 --output-dir=/output 2>&1 | tail -20
echo "✓ SQLmap scan (search endpoint) completed"

echo ""
echo "Running SQLmap scan on login endpoint (this will take 10-20 minutes)..."
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
    --dump 2>&1 | tail -20
echo "✓ SQLmap scan (login endpoint) completed"

echo ""
echo "=== Task 3: Analysis ==="
echo ""

# Run comparison scripts
echo "Comparing ZAP scans..."
bash labs/lab5/scripts/compare_zap.sh

echo ""
echo "Summarizing DAST results..."
bash labs/lab5/scripts/summarize_dast.sh

echo ""
echo "=== All Scans Completed ==="
echo ""
echo "Next steps:"
echo "1. Review results in labs/lab5/"
echo "2. Update labs/submission5.md with your findings"
echo "3. Run correlation analysis: bash labs/lab5/scripts/correlation.sh (if exists)"
echo ""
echo "To clean up containers:"
echo "  docker stop juice-shop-lab5 && docker rm juice-shop-lab5"
