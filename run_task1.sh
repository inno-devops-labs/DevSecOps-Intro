#!/bin/bash
echo "Extracting licenses from Syft SBOM..." > labs/lab4/syft/juice-shop-licenses.txt
jq -r '.artifacts[] | select(.licenses != null and (.licenses | length > 0)) | "\(.name) | \(.version) | \(.licenses | map(.value) | join(", "))"' labs/lab4/syft/juice-shop-syft-native.json >> labs/lab4/syft/juice-shop-licenses.txt

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json --list-all-pkgs bkimminich/juice-shop:v19.0.0
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp aquasec/trivy:latest image --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt --list-all-pkgs bkimminich/juice-shop:v19.0.0

echo "=== SBOM Component Analysis ===" > labs/lab4/analysis/sbom-analysis.txt
echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Syft Package Counts:" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.artifacts[] | .type' labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt   

echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Trivy Package Counts:" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] as $result | $result.Packages[]? | "\($result.Target // "Unknown") - \(.Type // "unknown")"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt

echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "=== License Analysis ===" >> labs/lab4/analysis/sbom-analysis.txt
echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Syft Licenses:" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.artifacts[]? | select(.licenses != null) | .licenses[]? | .value' labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt

echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Trivy Licenses (OS Packages):" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] | select(.Class // "" | contains("os-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt

echo "" >> labs/lab4/analysis/sbom-analysis.txt  
echo "Trivy Licenses (Node.js):" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] | select(.Class // "" | contains("lang-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
