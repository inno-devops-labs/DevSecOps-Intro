#!/bin/bash
set -e

echo "Running final fix..."

# Run Grype directly on image and save to file using tee to ensure content is written
echo "Scanning with Grype..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest bkimminich/juice-shop:v19.0.0 -o json | tee labs/lab4/syft/grype-vuln-results.json > /dev/null

# Verify file size
if [ ! -s labs/lab4/syft/grype-vuln-results.json ]; then
    echo "Error: Grype results are still empty!"
    exit 1
fi

echo "Grype scan successful. Size: $(du -h labs/lab4/syft/grype-vuln-results.json)"

# Human-readable table for Grype
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest bkimminich/juice-shop:v19.0.0 -o table > labs/lab4/syft/grype-vuln-table.txt

# Re-generate analysis
echo "=== Vulnerability Analysis ===" > labs/lab4/analysis/vulnerability-analysis.txt
echo "" >> labs/lab4/analysis/vulnerability-analysis.txt
echo "Grype Vulnerabilities by Severity:" >> labs/lab4/analysis/vulnerability-analysis.txt
jq -r '.matches[]? | .vulnerability.severity' labs/lab4/syft/grype-vuln-results.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt

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

# Re-generate comparison
echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt
# (Clear output specifically for this part or append if fine? The file gets overwritten at start of accuracy-analysis usually. I should probably recreate the whole file or just append confidently.)
# Actually, I'll just append the overlap part again or overwrite the whole file to be clean.

echo "=== Package Detection Comparison ===" > labs/lab4/comparison/accuracy-analysis.txt
if [ -f labs/lab4/syft/juice-shop-syft-native.json ] && [ -f labs/lab4/trivy/juice-shop-trivy-detailed.json ]; then
    # packages logic repeated...
    # checking if packages files exist
    if [ ! -f labs/lab4/comparison/syft-packages.txt ]; then
         jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
    fi
     if [ ! -f labs/lab4/comparison/trivy-packages.txt ]; then
         jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt
    fi
    comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt
    comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
    comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt

    echo "Packages detected by both tools: $(wc -l < labs/lab4/comparison/common-packages.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Packages only detected by Syft: $(wc -l < labs/lab4/comparison/syft-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
    echo "Packages only detected by Trivy: $(wc -l < labs/lab4/comparison/trivy-only.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
fi

echo "" >> labs/lab4/comparison/accuracy-analysis.txt
echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt

# Extract CVE IDs
jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt

echo "CVEs found by Grype: $(wc -l < labs/lab4/comparison/grype-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
echo "CVEs found by Trivy: $(wc -l < labs/lab4/comparison/trivy-cves.txt | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Common CVEs: $(comm -12 labs/lab4/comparison/grype-cves.txt labs/lab4/comparison/trivy-cves.txt | wc -l | tr -d ' ')" >> labs/lab4/comparison/accuracy-analysis.txt

echo "Final fix completed."
