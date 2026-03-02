#!/bin/bash
set -e

echo "Starting Task 2 completion..."

# Full vulnerability scan with detailed output (Trivy)
if [ ! -f labs/lab4/trivy/trivy-vuln-detailed.json ]; then
    echo "Running Trivy Vulnerability Scan..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json bkimminich/juice-shop:v19.0.0
fi

# Secrets scanning
if [ ! -f labs/lab4/trivy/trivy-secrets.txt ]; then
    echo "Running Trivy Secrets Scan..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --scanners secret --format table --output /tmp/labs/lab4/trivy/trivy-secrets.txt bkimminich/juice-shop:v19.0.0
fi

# License compliance scanning
if [ ! -f labs/lab4/trivy/trivy-licenses.json ]; then
    echo "Running Trivy License Scan..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --scanners license --format json --output /tmp/labs/lab4/trivy/trivy-licenses.json bkimminich/juice-shop:v19.0.0
fi

# Count vulnerabilities by severity
echo "Generating Vulnerability Analysis..."
echo "=== Vulnerability Analysis ===" > labs/lab4/analysis/vulnerability-analysis.txt
echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Grype Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
if [ -f labs/lab4/syft/grype-vuln-results.json ]; then
    jq -r '.matches[]? | .vulnerability.severity' labs/lab4/syft/grype-vuln-results.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
else
    echo "Grype results not found!" >> labs/lab4/analysis/vulnerability-analysis.txt
fi

echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Trivy Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
if [ -f labs/lab4/trivy/trivy-vuln-detailed.json ]; then
    jq -r '.Results[]?.Vulnerabilities[]? | .Severity' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
else
    echo "Trivy results not found!" >> labs/lab4/analysis/vulnerability-analysis.txt
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

echo "Task 2 completed."
echo "Starting Task 3..."

# Compare package detection
echo "=== Package Detection Comparison ===" > labs/lab4/comparison/accuracy-analysis.txt

if [ -f labs/lab4/syft/juice-shop-syft-native.json ]; then
    # Extract unique packages from each tool
    jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
fi

if [ -f labs/lab4/trivy/juice-shop-trivy-detailed.json ]; then
    jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt
fi

if [ -f labs/lab4/comparison/syft-packages.txt ] && [ -f labs/lab4/comparison/trivy-packages.txt ]; then
    # Find packages detected by both tools
    comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt

    # Find packages unique to each tool
    comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
    comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt

    echo "Packages detected by both tools: $(wc -l < labs/lab4/comparison/common-packages.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Packages only detected by Syft: $(wc -l < labs/lab4/comparison/syft-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Packages only detected by Trivy: $(wc -l < labs/lab4/comparison/trivy-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
else
    echo "Package files missing for comparison" >> labs/lab4/comparison/accuracy-analysis.txt
fi

# Compare vulnerability findings
echo "" >> labs/lab4/comparison/accuracy-analysis.txt
echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt

if [ -f labs/lab4/syft/grype-vuln-results.json ]; then
    # Extract CVE IDs
    jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
fi

if [ -f labs/lab4/trivy/trivy-vuln-detailed.json ]; then
    jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt
fi

if [ -f labs/lab4/comparison/grype-cves.txt ] && [ -f labs/lab4/comparison/trivy-cves.txt ]; then
    echo "CVEs found by Grype: $(wc -l < labs/lab4/comparison/grype-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "CVEs found by Trivy: $(wc -l < labs/lab4/comparison/trivy-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Common CVEs: $(comm -12 labs/lab4/comparison/grype-cves.txt labs/lab4/comparison/trivy-cves.txt | wc -l | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
else
    echo "CVE files missing for comparison" >> labs/lab4/comparison/accuracy-analysis.txt
fi

echo "Task 3 completed."
