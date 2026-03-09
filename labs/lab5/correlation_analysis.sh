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