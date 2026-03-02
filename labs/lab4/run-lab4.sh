#!/usr/bin/env bash
# Lab 4 — SBOM Generation & SCA — full automation script
set -e

# Resolve repo root: same result whether you run ./run-lab4.sh or bash labs/lab4/run-lab4.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# Require docker and jq
if ! command -v docker &>/dev/null; then
  echo "Error: docker not found. Install Docker and ensure it is running." >&2
  exit 1
fi
if ! command -v jq &>/dev/null; then
  echo "Error: jq not found. Install jq (e.g. brew install jq on macOS)." >&2
  exit 1
fi

echo "Repo root: $ROOT"
echo "=== Pulling Docker images ==="
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest

echo "=== Task 1.2: Syft SBOM ==="
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt

echo "Extracting licenses from Syft SBOM..." > "$ROOT/labs/lab4/syft/juice-shop-licenses.txt"
jq -r '.artifacts[] | select(.licenses != null and (.licenses | length > 0)) | "\(.name) | \(.version) | \(.licenses | map(.value) | join(", "))"' \
  "$ROOT/labs/lab4/syft/juice-shop-syft-native.json" >> "$ROOT/labs/lab4/syft/juice-shop-licenses.txt" 2>/dev/null || true

echo "=== Task 1.3: Trivy SBOM ==="
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp aquasec/trivy:latest image \
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

echo "=== Task 1.4: SBOM Analysis ==="
echo "=== SBOM Component Analysis ===" > "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "Syft Package Counts:" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
jq -r '.artifacts[] | .type' "$ROOT/labs/lab4/syft/juice-shop-syft-native.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt" || true

echo "" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "Trivy Package Counts:" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
jq -r '.Results[] as $result | $result.Packages[]? | "\($result.Target // "Unknown") - \(.Type // "unknown")"' \
  "$ROOT/labs/lab4/trivy/juice-shop-trivy-detailed.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt" || true

echo "" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "=== License Analysis ===" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "Syft Licenses:" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
jq -r '.artifacts[]? | select(.licenses != null) | .licenses[]? | .value' \
  "$ROOT/labs/lab4/syft/juice-shop-syft-native.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt" || true

echo "" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "Trivy Licenses (OS Packages):" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
jq -r '.Results[] | select(.Class // "" | contains("os-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
  "$ROOT/labs/lab4/trivy/juice-shop-trivy-detailed.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt" || true

echo "" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
echo "Trivy Licenses (Node.js):" >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt"
jq -r '.Results[] | select(.Class // "" | contains("lang-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
  "$ROOT/labs/lab4/trivy/juice-shop-trivy-detailed.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/sbom-analysis.txt" || true

echo "=== Task 2.1: Grype SCA ==="
docker run --rm -v "$ROOT":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json > "$ROOT/labs/lab4/syft/grype-vuln-results.json"

docker run --rm -v "$ROOT":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table > "$ROOT/labs/lab4/syft/grype-vuln-table.txt"

echo "=== Task 2.2: Trivy vuln + secrets + license ==="
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp aquasec/trivy:latest image \
  --scanners secret --format table --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
  bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT":/tmp aquasec/trivy:latest image \
  --scanners license --format json --output /tmp/labs/lab4/trivy/trivy-licenses.json \
  bkimminich/juice-shop:v19.0.0

echo "=== Task 2.3: Vulnerability Analysis ==="
echo "=== Vulnerability Analysis ===" > "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
echo "" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
echo "Grype Vulnerabilities by Severity:" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
jq -r '.matches[]? | .vulnerability.severity' "$ROOT/labs/lab4/syft/grype-vuln-results.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt" || true

echo "" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
echo "Trivy Vulnerabilities by Severity:" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
jq -r '.Results[]?.Vulnerabilities[]? | .Severity' "$ROOT/labs/lab4/trivy/trivy-vuln-detailed.json" 2>/dev/null | sort | uniq -c >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt" || true

echo "" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
echo "=== License Analysis Summary ===" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
echo "Tool Comparison:" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
if [ -f "$ROOT/labs/lab4/syft/juice-shop-syft-native.json" ]; then
  syft_licenses=$(jq -r '.artifacts[] | select(.licenses != null) | .licenses[].value' "$ROOT/labs/lab4/syft/juice-shop-syft-native.json" 2>/dev/null | sort | uniq | wc -l | tr -d ' ')
  echo "- Syft found $syft_licenses unique license types" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
fi
if [ -f "$ROOT/labs/lab4/trivy/trivy-licenses.json" ]; then
  trivy_licenses=$(jq -r '.Results[].Licenses[]?.Name' "$ROOT/labs/lab4/trivy/trivy-licenses.json" 2>/dev/null | sort | uniq | wc -l | tr -d ' ')
  echo "- Trivy found $trivy_licenses unique license types" >> "$ROOT/labs/lab4/analysis/vulnerability-analysis.txt"
fi

echo "=== Task 3.1: Accuracy and Coverage ==="
SYFT_JSON="$ROOT/labs/lab4/syft/juice-shop-syft-native.json"
TRIVY_JSON="$ROOT/labs/lab4/trivy/juice-shop-trivy-detailed.json"
COMP="$ROOT/labs/lab4/comparison"

echo "=== Package Detection Comparison ===" > "$COMP/accuracy-analysis.txt"
jq -r '.artifacts[] | "\(.name)@\(.version)"' "$SYFT_JSON" 2>/dev/null | sort > "$COMP/syft-packages.txt" || true
jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' "$TRIVY_JSON" 2>/dev/null | sort > "$COMP/trivy-packages.txt" || true

comm -12 "$COMP/syft-packages.txt" "$COMP/trivy-packages.txt" 2>/dev/null > "$COMP/common-packages.txt" || true
comm -23 "$COMP/syft-packages.txt" "$COMP/trivy-packages.txt" 2>/dev/null > "$COMP/syft-only.txt" || true
comm -13 "$COMP/syft-packages.txt" "$COMP/trivy-packages.txt" 2>/dev/null > "$COMP/trivy-only.txt" || true

echo "Packages detected by both tools: $(wc -l < "$COMP/common-packages.txt" 2>/dev/null | tr -d ' ' || echo 0)" >> "$COMP/accuracy-analysis.txt"
echo "Packages only detected by Syft: $(wc -l < "$COMP/syft-only.txt" 2>/dev/null | tr -d ' ' || echo 0)" >> "$COMP/accuracy-analysis.txt"
echo "Packages only detected by Trivy: $(wc -l < "$COMP/trivy-only.txt" 2>/dev/null | tr -d ' ' || echo 0)" >> "$COMP/accuracy-analysis.txt"

echo "" >> "$COMP/accuracy-analysis.txt"
echo "=== Vulnerability Detection Overlap ===" >> "$COMP/accuracy-analysis.txt"
jq -r '.matches[]? | .vulnerability.id' "$ROOT/labs/lab4/syft/grype-vuln-results.json" 2>/dev/null | sort | uniq > "$COMP/grype-cves.txt" || true
jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' "$ROOT/labs/lab4/trivy/trivy-vuln-detailed.json" 2>/dev/null | sort | uniq > "$COMP/trivy-cves.txt" || true

echo "CVEs found by Grype: $(wc -l < "$COMP/grype-cves.txt" 2>/dev/null | tr -d ' ' || echo 0)" >> "$COMP/accuracy-analysis.txt"
echo "CVEs found by Trivy: $(wc -l < "$COMP/trivy-cves.txt" 2>/dev/null | tr -d ' ' || echo 0)" >> "$COMP/accuracy-analysis.txt"
echo "Common CVEs: $(comm -12 "$COMP/grype-cves.txt" "$COMP/trivy-cves.txt" 2>/dev/null | wc -l | tr -d ' ')" >> "$COMP/accuracy-analysis.txt"

echo "=== Lab 4 script finished ==="
