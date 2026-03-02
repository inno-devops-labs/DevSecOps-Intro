#!/bin/bash
set -e

echo "Fixing Task 1 and 2..."

# 1. Regenerate Syft SBOM (using Syft JSON format)
echo "Generating Syft SBOM..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp anchore/syft:latest bkimminich/juice-shop:v19.0.0 -o json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# 2. Run Grype on the SBOM
echo "Running Grype on SBOM..."
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json -o json > labs/lab4/syft/grype-vuln-results.json

# 3. Check if Grype output is not empty
if [ ! -s labs/lab4/syft/grype-vuln-results.json ]; then
    echo "Grype output is empty! Trying to run Grype directly on image..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest bkimminich/juice-shop:v19.0.0 -o json > labs/lab4/syft/grype-vuln-results.json
fi

# 4. Rerun Vulnerability Analysis
echo "Updating Vulnerability Analysis..."
echo "=== Vulnerability Analysis ===" > labs/lab4/analysis/vulnerability-analysis.txt
echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Grype Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
if [ -s labs/lab4/syft/grype-vuln-results.json ]; then
    jq -r '.matches[]? | .vulnerability.severity' labs/lab4/syft/grype-vuln-results.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
else
    echo "Grype results still empty or invalid!" >> labs/lab4/analysis/vulnerability-analysis.txt
fi

echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Trivy Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
if [ -s labs/lab4/trivy/trivy-vuln-detailed.json ]; then
    jq -r '.Results[]?.Vulnerabilities[]? | .Severity' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
fi

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

# 5. Rerun Comparison Analysis (Task 3)
echo "Updating Comparison Analysis..."
# Compare package detection
echo "=== Package Detection Comparison ===" > labs/lab4/comparison/accuracy-analysis.txt

if [ -f labs/lab4/syft/juice-shop-syft-native.json ]; then
    jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
fi

if [ -f labs/lab4/trivy/juice-shop-trivy-detailed.json ]; then
    jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt
fi

if [ -f labs/lab4/comparison/syft-packages.txt ] && [ -f labs/lab4/comparison/trivy-packages.txt ]; then
    comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt
    comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
    comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt

    echo "Packages detected by both tools: $(wc -l < labs/lab4/comparison/common-packages.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Packages only detected by Syft: $(wc -l < labs/lab4/comparison/syft-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Packages only detected by Trivy: $(wc -l < labs/lab4/comparison/trivy-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
fi

# Compare vulnerability findings
echo "" >> labs/lab4/comparison/accuracy-analysis.txt
echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt

if [ -s labs/lab4/syft/grype-vuln-results.json ]; then
    jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
fi

if [ -s labs/lab4/trivy/trivy-vuln-detailed.json ]; then
    jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt
fi

if [ -f labs/lab4/comparison/grype-cves.txt ] && [ -f labs/lab4/comparison/trivy-cves.txt ]; then
    echo "CVEs found by Grype: $(wc -l < labs/lab4/comparison/grype-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "CVEs found by Trivy: $(wc -l < labs/lab4/comparison/trivy-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Common CVEs: $(comm -12 labs/lab4/comparison/grype-cves.txt labs/lab4/comparison/trivy-cves.txt | wc -l | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
fi

echo "Fix completed."
