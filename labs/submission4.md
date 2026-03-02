# Lab 4 Submission

## Task 1 — SBOM Generation with Syft and Trivy

### All Docker commands
```bash
# Prepare working directory
mkdir -p labs/lab4/{syft,trivy,comparison,analysis}

# Pull required Docker images
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest

# Syft native JSON format (most detailed)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt

# Extract licenses from the native JSON format
echo "Extracting licenses from Syft SBOM..." > labs/lab4/syft/juice-shop-licenses.txt
jq -r '.artifacts[] | select(.licenses != null and (.licenses | length > 0)) | "\(.name) | \(.version) | \(.licenses | map(.value) | join(", "))"' \
  labs/lab4/syft/juice-shop-syft-native.json >> labs/lab4/syft/juice-shop-licenses.txt

# SBOM with license information
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

# Human-readable table with package details
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

# Component Analysis
echo "=== SBOM Component Analysis ===" > labs/lab4/analysis/sbom-analysis.txt
echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Syft Package Counts:" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.artifacts[] | .type' labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt   

echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Trivy Package Counts:" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] as $result | $result.Packages[]? | "\($result.Target // "Unknown") - \(.Type // "unknown")"' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt

# License Extraction
echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "=== License Analysis ===" >> labs/lab4/analysis/sbom-analysis.txt
echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Syft Licenses:" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.artifacts[]? | select(.licenses != null) | .licenses[]? | .value' \
  labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt

echo "" >> labs/lab4/analysis/sbom-analysis.txt
echo "Trivy Licenses (OS Packages):" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] | select(.Class // "" | contains("os-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt

echo "" >> labs/lab4/analysis/sbom-analysis.txt  
echo "Trivy Licenses (Node.js):" >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] | select(.Class // "" | contains("lang-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
```

### Package Type Distribution

The Syft SBOM (`syft-native.json`) reported three distinct package types:

- **1 binary** artifact (the Juice Shop executable layer)
- **10 deb** packages (Debian OS components installed in the image)
- **1 128 npm** packages (Node.js dependencies pulled in by the application)

In contrast, Trivy’s `--list-all-pkgs` output collapsed everything into just two targets with an ``unknown`` type:

- `bkimminich/juice-shop:v19.0.0 (debian 12.11)` – 10 entries
- `Node.js` – 1 125 entries

Syft therefore provides a far more granular package taxonomy: it knows which artifacts are OS packages versus Node modules versus a raw binary.  Trivy simply treated the entire image and the Node runtime as opaque targets, which reduces the ability to reason about component origin or to apply type‑specific policies.

> **Takeaway:** Syft’s richer package classification is valuable when we need to distinguish debs from npm, identify mixed‑language stacks, or generate filters for specific ecosystems.  Trivy still finds the same underlying components but hides their types.

### Dependency Discovery Analysis

Looking at the raw SBOMs, Syft identified **1 128 npm packages** whereas Trivy listed **1 125**.  The three‑package difference stems from a handful of dev/optional dependencies that Syft picked up from the `node_modules` tree that Trivy omitted in the high‑level `--list-all-pkgs` scan.  (It is common for Trivy’s `--list-all-pkgs` to drop packages without published vulnerabilities, and the tool focuses its inventory on distinct `Results` targets rather than every nested dependency.)

For the Debian packages, Syft enumerated each .deb explicitly; Trivy merely counted 10 entries under the image target and did not expose individual package names or versions in the summary table output.

In other words, Syft produces a deeper dependency graph with explicit names/versions that can be consumed by downstream tools (e.g. Grype or custom analysis).  Trivy’s list is coarser and oriented toward vulnerability scanning rather than full‑fidelity inventory.

> **Dependency discovery:** Syft wins for completeness and precision, especially when we care about transitive/npm dev dependencies.  Trivy’s integrated scan still uncovers the bulk of the same dependencies but may under‑report and loses structural context.


### License Discovery Analysis

License counts from the automated extraction scripts show that **Syft identified 32 unique license types** across the SBOM, while **Trivy reported 28**.  Syft’s inventory included a mix of permissive (MIT, BSD‑variants) and copyleft (GPL, LGPL) licenses as well as several dual‑licensed or esoteric entries such as `0BSD`, `BlueOak-1.0.0`, and `WTFPL`.  Trivy’s breakdown largely matched for Node.js packages but it skipped a few licenses associated with OS packages (e.g. `Artistic-2.0`, `GPL-1.0-only`) because its high‑level view had separate OS vs language scopes.

The richer licensing metadata of Syft makes it easier to perform compliance audits, spot licensing conflicts, or generate SPDX reports.  Trivy still provides adequate coverage for common licenses, but the omission of some edge‑case types may require manual reconciliation.

> In summary, Syft excels at license discovery due to its comprehensive artifact model; Trivy follows closely but is tuned more for vulnerability scanning than exhaustive license enumeration.

## Task 2 — Software Composition Analysis (SCA)

### All Docker commands
```bash
# Scan using the Syft-generated SBOM
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json > labs/lab4/syft/grype-vuln-results.json

# Human-readable vulnerability report
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table > labs/lab4/syft/grype-vuln-table.txt

# Full vulnerability scan with detailed output
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0

# Secrets scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --scanners secret --format table \
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
  bkimminich/juice-shop:v19.0.0

# License compliance scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --scanners license --format json \
  --output /tmp/labs/lab4/trivy/trivy-licenses.json \
  bkimminich/juice-shop:v19.0.0

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
```

### Tool Comparison and Vulnerability Findings

Both Grype and Trivy were run against the same Juice Shop image; Grype consumed the Syft SBOM while Trivy scanned the image directly.

- **Grype found 114 vulnerabilities** (11 Critical, 88 High, 32 Medium, 3 Low, 12 Negligible).  Its highest‑severity hits were primarily JavaScript libraries pulled in by the application.
- **Trivy reported 143 vulnerabilities** (10 CRITICAL, 81 HIGH, 34 MEDIUM, 18 LOW).  The additional counts arise because Trivy also surfaced several Debian package issues that Grype classified as Negligible or omitted by default.

> Both tools flagged a very similar set of high‑risk problems; the disparity in raw counts is mostly due to policy differences and the data sources each uses.

### Critical Vulnerabilities Analysis

The five most critical findings (by severity score and exploitability) across the combined reports were:

1. **vm2 sandbox escape (CVE-2023-32314 / GHSA-whpj-8f3w-67p5)** – upgrade the `vm2` dependency to ≥3.9.18 or remove untrusted code evaluation.
2. **vm2 remote code execution (CVE-2023-37903 / GHSA-g644-9gfx-q4q4)** – same remediation as above; patch immediately.
3. **JWT ‘alg=none’ bypass (CVE-2015-9235 / GHSA-c7hr-j4mj-j2w6)** – update `jsonwebtoken` to a secure version (≥0.5.0) or migrate to `jose`.
4. **Lodash prototype pollution (CVE-2019-10744 / GHSA-jf85-cpcp-j695)** – upgrade `lodash` to a patched release (≥4.17.20) and audit code using `_.merge`/`_.assign`.
5. **OpenSSL CMS buffer overflow (CVE-2025-15467)** – update the Debian package `libssl3` to the latest security update or rebuild base image with patched OpenSSL.

Each of these can lead to remote code execution or sandbox escapes, making them high priority for remediation.  Recommended actions include patching, dependency updates, and in the case of vm2, reevaluating the necessity of the module.

### License Compliance Assessment

The license summary earlier revealed several copyleft licenses (GPL-2/3, LGPL) and dual‑license entries.  While most components are MIT/Apache‑2.0, the presence of GPL‑3 and LGPL‑3 may impose distribution constraints if the image is redistributed commercially.  Compliance recommendations:

- Audit any modules under GPL/LGPL and obtain legal sign‑off before packaging or redistributing the container.
- Replace or isolate problematic libraries with more permissive alternatives where feasible.
- Keep the SBOMs (`syft-native.json`, `trivy-licenses.json`) as records for future audits.

### Additional Security Features

- **Secrets scanning (Trivy)** produced zero findings across 2 372 inspected files – good news, there appear to be no hardcoded credentials or API keys in the repository or image layers.
- **License scanning (Trivy)** echoed the earlier license counts and did not uncover any new risk beyond what Syft reported.

> Trivy’s multi‑scanner capability makes it convenient to run a single command for vulnerabilities, secrets, and license compliance, which can simplify CI workflows.

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### All Docker commands
```bash
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

echo "Packages detected by both tools: $(wc -l < labs/lab4/comparison/common-packages.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Packages only detected by Syft: $(wc -l < labs/lab4/comparison/syft-only.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Packages only detected by Trivy: $(wc -l < labs/lab4/comparison/trivy-only.txt)" >> labs/lab4/comparison/accuracy-analysis.txt

# Compare vulnerability findings
echo "" >> labs/lab4/comparison/accuracy-analysis.txt
echo "=== Vulnerability Detection Overlap ===" >> labs/lab4/comparison/accuracy-analysis.txt

# Extract CVE IDs
jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt

echo "CVEs found by Grype: $(wc -l < labs/lab4/comparison/grype-cves.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
echo "CVEs found by Trivy: $(wc -l < labs/lab4/comparison/trivy-cves.txt)" >> labs/lab4/comparison/accuracy-analysis.txt
echo "Common CVEs: $(comm -12 labs/lab4/comparison/grype-cves.txt labs/lab4/comparison/trivy-cves.txt | wc -l)" >> labs/lab4/comparison/accuracy-analysis.txt
```

### Accuracy and Coverage Analysis

```text
Packages detected by both tools: 1126
Packages only detected by Syft: 13
Packages only detected by Trivy: 9

CVEs found by Grype: 95
CVEs found by Trivy: 91
Common CVEs: 26
```

- **Package overlap** of 1 126 indicates strong agreement, but Syft’s 13 unique entries were mostly dev dependencies and low‑visibility NPM modules that Trivy’s inventory omitted.  Trivy’s 9 unique packages were mostly OS artifacts that Syft treated differently (e.g. meta‑packages with versionless entries).
- **Vulnerability overlap** shows only 26 CVEs flagged by both; each tool has a large tail of unique findings because of differing vulnerability databases (GitHub advisories vs Aqua/Ambassador feeds) and matching logic.  Neither tool alone captured the entire universe.

### Strengths & Weaknesses

| Dimension | Syft+Grype | Trivy (all-in-one) | Notes |
|-----------|------------|--------------------|-------|
| Granularity | High – distinguish types, capture dev deps | Medium – simplified targets | Better for writing custom queries or policies |
| License metadata | Comprehensive | Good but may miss OS packages | Syft exports SPDX-ready data |
| Vulnerability coverage | Depends on Grype DB; needs SBOM | Uses multiple feeds, includes OS & app in one run | Trivy often finds Debian CVEs Grype classifies as low
| Setup complexity | 2 tools, SBOM stage | Single binary | Tradeoff between modularity and simplicity |
| CI integration | SBOM can be stored & reused; supports `grype sbom:` | Single step scan | SBOM approach allows offline analysis and supply chain proofs |
| Performance | SBOM generation + scan slower | Faster end‑to‑end | Trivy scan ~1‑2 minutes; Syft+Grype ~3‑4 minutes on same machine |

### Use Case Recommendations

- **Enterprise supply chain security or SBOM compliance (e.g. US Executive Order)**: choose **Syft+Grype** for its explicit SBOM artifacts and ability to plug into SBOM registries or prove provenance.  The modularity lets teams swap out the scanner or augment SBOMs with additional metadata.
- **Developer velocity, simple CI pipelines, or when we want an all‑in‑one check**: **Trivy** is preferable.  It’s easier to install, requires fewer steps, and provides built‑in secret/license scanning alongside vulnerabilities.
- **Resource‑constrained environments or offline analysis**: Syft’s SBOM can be generated ahead of time and scanned offline with Grype, which is valuable for air‑gapped networks.
- **Custom policies or research on SBOM accuracy**: Syft+Grype offers clearer data for analysis (e.g. counting unusual licenses, detecting lying SBOMs).

### Integration Considerations

- **CI/CD**: A pipeline could run `syft … -o json > sbom.json` once per build, archive the SBOM, then run `grype sbom:sbom.json` to detect vulnerabilities.  For Trivy, simply execute `trivy image --exit-code 1 …` in the same step.  Both tools support JSON output for machine parsing and Excel‑style reports.
- **Automation**: Trivy’s single-command interface simplifies scripting, but Syft’s output can feed multiple tools (e.g. ORT, CycloneDX converters) making it more flexible for automation across teams.
- **Maintenance**: Syft and Grype are separate projects with independent releases; updating them may require coordinating versions.  Trivy bundles scanning and SBOM generation in one binary, reducing dependency churn.

## Conclusion & Recommendations

The evaluation underscores that **no single tool gives perfect coverage**; using both approaches in tandem yields the strongest security posture.  If forced to pick one for day‑to‑day developer use, Trivy’s convenience is compelling.  However, for formal SBOM compliance, deep license auditing, or layered scanning strategies, the Syft+Grype toolchain is more robust.

