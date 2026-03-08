#!/usr/bin/env bash
set -euo pipefail

# compare_zap.sh
# Compares authenticated vs unauthenticated ZAP scan results
# Outputs comparison to labs/lab5/analysis/zap-comparison.txt

echo "=== ZAP Authenticated vs Unauthenticated Scan Comparison ==="
echo ""

OUTPUT_FILE="labs/lab5/analysis/zap-comparison.txt"
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Check if reports exist
NOAUTH_REPORT="labs/lab5/zap/report-noauth.html"
AUTH_REPORT="labs/lab5/zap/report-auth.html"

if [[ ! -f "$NOAUTH_REPORT" ]]; then
  echo "Error: Unauthenticated report not found at $NOAUTH_REPORT"
  echo "Run the ZAP baseline scan first."
  exit 1
fi

if [[ ! -f "$AUTH_REPORT" ]]; then
  echo "Error: Authenticated report not found at $AUTH_REPORT"
  echo "Run the ZAP authenticated scan first."
  exit 1
fi

# Initialize output file
cat > "$OUTPUT_FILE" <<'EOF'
=== ZAP Authenticated vs Unauthenticated Scan Comparison ===

EOF

# Extract URL counts
# ZAP reports contain a summary section with URL counts
echo "Analyzing URL discovery..." >&2

# Count unique URLs from reports (look for URL patterns in the HTML)
NOAUTH_URLS=$(grep -o 'http://localhost:3000[^"<>]*' "$NOAUTH_REPORT" 2>/dev/null | sort -u | wc -l | tr -d ' ')
AUTH_URLS=$(grep -o 'http://localhost:3000[^"<>]*' "$AUTH_REPORT" 2>/dev/null | sort -u | wc -l | tr -d ' ')

echo "URL Discovery:" >> "$OUTPUT_FILE"
echo "  Unauthenticated scan: $NOAUTH_URLS unique URLs" >> "$OUTPUT_FILE"
echo "  Authenticated scan: $AUTH_URLS unique URLs" >> "$OUTPUT_FILE"
echo "  Difference: $(($AUTH_URLS - $NOAUTH_URLS)) additional URLs discovered with authentication" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Find admin/authenticated endpoints
echo "Authenticated Endpoints Discovered:" >> "$OUTPUT_FILE"
grep -o 'http://localhost:3000[^"<>]*' "$AUTH_REPORT" 2>/dev/null | sort -u | grep -E '(admin|profile|basket|order|payment|wallet|delivery)' | head -20 >> "$OUTPUT_FILE" 2>/dev/null || echo "  (No authenticated endpoints pattern matched)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Count alerts by severity
echo "Alert Comparison:" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# High severity (risk-3)
NOAUTH_HIGH=$(grep -c 'class="risk-3"' "$NOAUTH_REPORT" 2>/dev/null || echo "0")
AUTH_HIGH=$(grep -c 'class="risk-3"' "$AUTH_REPORT" 2>/dev/null || echo "0")
NOAUTH_HIGH=$((NOAUTH_HIGH / 2))  # Each alert appears twice in HTML
AUTH_HIGH=$((AUTH_HIGH / 2))

echo "High Severity Alerts:" >> "$OUTPUT_FILE"
echo "  Unauthenticated: $NOAUTH_HIGH" >> "$OUTPUT_FILE"
echo "  Authenticated: $AUTH_HIGH" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Medium severity (risk-2)
NOAUTH_MED=$(grep -c 'class="risk-2"' "$NOAUTH_REPORT" 2>/dev/null || echo "0")
AUTH_MED=$(grep -c 'class="risk-2"' "$AUTH_REPORT" 2>/dev/null || echo "0")
NOAUTH_MED=$((NOAUTH_MED / 2))
AUTH_MED=$((AUTH_MED / 2))

echo "Medium Severity Alerts:" >> "$OUTPUT_FILE"
echo "  Unauthenticated: $NOAUTH_MED" >> "$OUTPUT_FILE"
echo "  Authenticated: $AUTH_MED" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Low severity (risk-1)
NOAUTH_LOW=$(grep -c 'class="risk-1"' "$NOAUTH_REPORT" 2>/dev/null || echo "0")
AUTH_LOW=$(grep -c 'class="risk-1"' "$AUTH_REPORT" 2>/dev/null || echo "0")
NOAUTH_LOW=$((NOAUTH_LOW / 2))
AUTH_LOW=$((AUTH_LOW / 2))

echo "Low Severity Alerts:" >> "$OUTPUT_FILE"
echo "  Unauthenticated: $NOAUTH_LOW" >> "$OUTPUT_FILE"
echo "  Authenticated: $AUTH_LOW" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Total
NOAUTH_TOTAL=$((NOAUTH_HIGH + NOAUTH_MED + NOAUTH_LOW))
AUTH_TOTAL=$((AUTH_HIGH + AUTH_MED + AUTH_LOW))

echo "Total Alerts:" >> "$OUTPUT_FILE"
echo "  Unauthenticated: $NOAUTH_TOTAL" >> "$OUTPUT_FILE"
echo "  Authenticated: $AUTH_TOTAL" >> "$OUTPUT_FILE"
echo "  Additional alerts with authentication: $(($AUTH_TOTAL - $NOAUTH_TOTAL))" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Key insights
cat >> "$OUTPUT_FILE" <<'EOF'
Key Insights:
  - Authenticated scanning discovers significantly more attack surface
  - Admin endpoints and user-specific features only visible when authenticated
  - AJAX spider finds dynamic endpoints by executing JavaScript
  - Authentication enables testing of authorization flaws and privilege escalation

Recommendation:
  Always perform authenticated scanning for applications with login functionality
  to ensure comprehensive security coverage of protected endpoints.
EOF

echo "Comparison saved to $OUTPUT_FILE"
cat "$OUTPUT_FILE"
