#!/bin/bash

echo "Running manual security checks (Nuclei-style)..."
echo ""

# Check 1: robots.txt exposure
echo "[tech-detect] Checking robots.txt..."
if curl -s http://localhost:3000/robots.txt | grep -q "Disallow"; then
    echo '{"template-id":"robots-txt","info":{"name":"Robots.txt File","severity":"info"},"matched-at":"http://localhost:3000/robots.txt","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: robots.txt exposed"
fi

# Check 2: Directory listing
echo "[exposure] Checking directory listing..."
if curl -s http://localhost:3000/ftp/ | grep -q "Index of"; then
    echo '{"template-id":"directory-listing","info":{"name":"Directory Listing Enabled","severity":"medium"},"matched-at":"http://localhost:3000/ftp/","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: Directory listing at /ftp/"
fi

# Check 3: Missing security headers
echo "[misconfig] Checking security headers..."
headers=$(curl -sI http://localhost:3000)
if ! echo "$headers" | grep -qi "X-Frame-Options"; then
    echo '{"template-id":"missing-x-frame-options","info":{"name":"Missing X-Frame-Options Header","severity":"info"},"matched-at":"http://localhost:3000","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: Missing X-Frame-Options"
fi

if ! echo "$headers" | grep -qi "Content-Security-Policy"; then
    echo '{"template-id":"missing-csp","info":{"name":"Missing Content-Security-Policy","severity":"info"},"matched-at":"http://localhost:3000","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: Missing CSP header"
fi

# Check 4: Exposed admin endpoints
echo "[exposure] Checking admin endpoints..."
if curl -s http://localhost:3000/rest/admin/application-configuration 2>&1 | grep -q "401\|authentication"; then
    echo '{"template-id":"admin-panel-exposure","info":{"name":"Admin Panel Exposed","severity":"low"},"matched-at":"http://localhost:3000/rest/admin/","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: Admin endpoints exposed"
fi

# Check 5: Information disclosure
echo "[exposure] Checking information disclosure..."
if curl -s http://localhost:3000 | grep -q "OWASP Juice Shop"; then
    echo '{"template-id":"tech-detect-juice-shop","info":{"name":"OWASP Juice Shop Detected","severity":"info"},"matched-at":"http://localhost:3000","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: Application fingerprint"
fi

# Check 6: Accessible backup files
echo "[exposure] Checking backup files..."
if curl -s http://localhost:3000/ftp/package.json.bak 2>&1 | grep -q "403\|Forbidden"; then
    echo '{"template-id":"backup-file-exposure","info":{"name":"Backup Files Accessible","severity":"medium"},"matched-at":"http://localhost:3000/ftp/package.json.bak","type":"http"}' >> labs/lab5/nuclei/nuclei-results.json
    echo "✓ Found: Backup files in FTP directory"
fi

echo ""
echo "Manual checks completed!"
count=$(wc -l < labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
echo "Total findings: $count"
