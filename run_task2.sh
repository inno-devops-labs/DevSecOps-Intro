#!/bin/bash
# Scan using the Syft-generated SBOM
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json -o json > labs/lab4/syft/grype-vuln-results.json

# Human-readable vulnerability report
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json -o table > labs/lab4/syft/grype-vuln-table.txt

# Full vulnerability scan with detailed output
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json bkimminich/juice-shop:v19.0.0

# Secrets scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --scanners secret --format table --output /tmp/labs/lab4/trivy/trivy-secrets.txt bkimminich/juice-shop:v19.0.0

# License compliance scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --scanners license --format json --output /tmp/labs/lab4/trivy/trivy-licenses.json bkimminich/juice-shop:v19.0.0

# Count vulnerabilities by severity
echo "=== Vulnerability Analysis ===" > labs/lab4/analysis/vulnerability-analysis.txt
echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Grype Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
jq -r '.matches[]? | .vulnerability.severity' labs/lab4/syft/grype-vuln-results.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt

echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Trivy Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
jq -r '.Results[]?.Vulnerabilities[]? | .Severity' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt

# License comparison summary
echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "=== License Analysis Summary ===" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Tool Comparison:" >> labs/lab4/analysis/vulnerability-analysis.txt
if [ -f labs/lab4/syft/juice-shop-syft-native.json ]; then
  syft_licenses=$(jq -r '.artifacts[] | select(.licenses != null) | .licenses[].value' labs/lab4/syft/juice-shop-syft-native.json 2>/dev/null | sort | uniq | wc -l)
  echo "- Syft found $syft_licenses unique license types" >> labs/lab4/analysis/vulnerability-analysis.txt
fi
if [ -f labs/lab4/trivy/trivy-licenses.json ]; then
  trivy_licenses=$(jq -r '.Results[].Licenses[]?.Name' labs/lab4/trivy/trivy-licenses.json 2>/dev/null | sort | uniq | wc -l)
  echo "- Trivy found $trivy_licenses unique license types" >> labs/lab4/analysis/vulnerability-analysis.txt
fi
