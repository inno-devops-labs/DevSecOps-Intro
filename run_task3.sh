#!/bin/bash
# Compare package detection
echo "=== Package Detection Comparison ===" > labs/lab4/comparison/accuracy-analysis.txt

# Extract unique packages from each tool
jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt

# Find packages detected by both tools
comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt

# Find packages unique to each tool
comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt

echo "Packages detected by both tools: $(wc -l < labs/lab4/comparison/common-packages.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Packages only detected by Syft: $(wc -l < labs/lab4/comparison/syft-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Packages only detected by Trivy: $(wc -l < labs/lab4/comparison/trivy-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt

# Compare vulnerability findings
echo "" >> labs/lab4/comparison/accuracy-analysis.txt
echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt

# Extract CVE IDs
jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt

echo "CVEs found by Grype: $(wc -l < labs/lab4/comparison/grype-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
echo "CVEs found by Trivy: $(wc -l < labs/lab4/comparison/trivy-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Common CVEs: $(comm -12 labs/lab4/comparison/grype-cves.txt labs/lab4/comparison/trivy-cves.txt | wc -l | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
