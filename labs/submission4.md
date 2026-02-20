# Lab 4 Submission — SBOM Generation & Software Composition Analysis

## Task 1 — SBOM Generation with Syft and Trivy (4 pts)

### 1.1 Setup

Working directory structure prepared, Docker images pulled:

```bash
mkdir -p labs/lab4/{syft,trivy,comparison,analysis}

docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```

### 1.2 SBOM Generation with Syft

Generated SBOMs in Syft native JSON and human-readable table formats:

```bash
# Syft native JSON format (most detailed)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  docker:bkimminich/juice-shop:v19.0.0 \
  -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  docker:bkimminich/juice-shop:v19.0.0 \
  -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt
```

**Syft results:**
- **Total packages detected:** 1 139
- Output file size: 3.66 MB (native JSON), 82 KB (table)

### 1.3 SBOM Generation with Trivy

```bash
# SBOM with full package listing
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  --list-all-pkgs bkimminich/juice-shop:v19.0.0
```

**Trivy results:**
- **Total packages detected:** 1 135
- Output file size: 1.10 MB (JSON), 698 KB (table)

### 1.4 SBOM Analysis

#### Package Type Distribution

| Ecosystem | Syft Count | Trivy Count |
|-----------|-----------|-------------|
| npm / Node.js | 1 128 | 1 125 |
| deb (Debian OS) | 10 | 10 |
| binary | 1 | — |
| **Total** | **1 139** | **1 135** |

Syft detected 4 more packages than Trivy overall. The difference primarily comes from:
- Syft detects a `binary` artifact (`node@22.18.0`) that Trivy categorizes differently.
- Syft picks up test/mock packages with `UNKNOWN` versions (`baz`, `browser_field`, `false_main`, `invalid_main`, `hashids-esm`) — these are likely test fixtures in the Juice Shop source that Syft's broader filesystem scanning picks up.

#### Dependency Discovery Analysis

| Metric | Syft | Trivy |
|--------|------|-------|
| Unique packages (name@version) | 1 001 | 997 |
| Common packages | 988 | 988 |
| Tool-exclusive packages | 13 | 9 |

**Syft-only packages (13):** Includes test fixtures (`baz`, `browser_field`, `false_main`, `invalid_main`, `hashids-esm`), the Node.js binary itself, and Debian packages with full epoch/revision versioning (e.g., `gcc-12-base@12.2.0-14+deb12u1`).

**Trivy-only packages (9):** Includes `portscanner@2.2.0` and `toposort-class@1.0.1` (missed by Syft), and the same OS packages but with truncated version strings (e.g., `gcc-12-base@12.2.0` without revision).

**Key Observation:** Many "unique" packages are actually the same package with different version notation. Syft includes full Debian version strings with revision suffixes while Trivy strips them — these are the same packages reported differently, not fundamentally different detections.

#### License Discovery Analysis

| Metric | Syft | Trivy |
|--------|------|-------|
| Unique license types | 32 | 28 |
| Total license entries | 1 149 | 1 114 |

**Top licenses (both tools agree):**

| License | Syft | Trivy |
|---------|------|-------|
| MIT | 890 | 878 |
| ISC | 143 | 143 |
| LGPL-3.0 | 19 | 19 |
| BSD-3-Clause | 16 | 14 |
| Apache-2.0 | 15 | 13 |
| BSD-2-Clause | 12 | 12 |

Syft identified 4 more unique license types than Trivy, including informal license identifiers like `ad-hoc`, `public-domain`, and `GPL-1+`. Trivy uses SPDX-normalized license identifiers (e.g., `GPL-2.0-only` vs Syft's `GPL-2`), making its output more standardized for compliance workflows.

---

## Task 2 — Software Composition Analysis with Grype and Trivy (3 pts)

### 2.1 SCA with Grype

```bash
# Scan using the Syft-generated SBOM
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json > labs/lab4/syft/grype-vuln-results.json

docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table > labs/lab4/syft/grype-vuln-table.txt
```

### 2.2 SCA with Trivy

```bash
# Vulnerability scan
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
```

### 2.3 SCA Tool Comparison — Vulnerability Detection

| Severity | Grype | Trivy |
|----------|-------|-------|
| Critical | 11 | 10 |
| High | 60 | 55 |
| Medium | 31 | 33 |
| Low | 3 | 18 |
| Negligible / Info | 12 | — |
| **Total** | **117** | **116** |

Both tools found a very similar total number of vulnerabilities (117 vs 116), but with differences in severity classification. Grype reports a "Negligible" severity category (12 entries) that Trivy does not use, while Trivy classifies more vulnerabilities as Low (18 vs 3). This indicates different severity mapping approaches — Grype follows NVD CVSS while Trivy uses vendor-provided severity when available.

### 2.4 Critical Vulnerabilities Analysis — Top 5

| # | Package | CVE / GHSA | Description | Remediation |
|---|---------|------------|-------------|-------------|
| 1 | `vm2@3.9.17` | CVE-2023-37903 / GHSA-whpj-8f3w-67p5 / GHSA-g644-9gfx-q4q4 / GHSA-cchq-frgv-rjh5 / GHSA-99p7-6v5w-7xg8 | Multiple sandbox escape vulnerabilities allowing arbitrary code execution outside the VM2 sandbox. The vm2 project is **abandoned** and will not receive patches. | **Remove vm2 entirely.** Migrate to `isolated-vm` or Node.js built-in `vm` module with `--experimental-vm-modules`. No fix is available for vm2. |
| 2 | `jsonwebtoken@0.1.0` / `@0.4.0` | CVE-2015-9235 / GHSA-c7hr-j4mj-j2w6 | Verification bypass — allows attackers to forge JWT tokens by omitting the algorithm parameter. | Upgrade to `jsonwebtoken@9.x` which enforces algorithm specification. |
| 3 | `lodash@2.4.2` | CVE-2019-10744 / GHSA-jf85-cpcp-j695 | Prototype pollution via `defaultsDeep` / `merge` / `zipObjectDeep` functions, enabling RCE in some contexts. | Upgrade to `lodash@4.17.21+`. |
| 4 | `crypto-js@3.3.0` | CVE-2023-46233 / GHSA-xwcq-pm8m-c4vf | PBKDF2 implementation uses 1 iteration by default instead of 1 000, making key derivation 1.3 million times weaker than the current standard. | Upgrade to `crypto-js@4.2.0+` or migrate to Node.js built-in `crypto.pbkdf2`. |
| 5 | `libssl3@3.0.17-1~deb12u2` | CVE-2025-15467 | Stack buffer overflow when parsing CMS AuthEnvelopedData messages with oversized IV, enabling DoS or potential RCE without authentication. | Update the base image to a Debian 12 variant with `openssl@3.0.17-1~deb12u3+`. |

### 2.5 License Compliance Assessment

**Potentially risky licenses found:**

| License | Count | Risk Level | Notes |
|---------|-------|------------|-------|
| LGPL-3.0 | 19 | Medium | Copyleft — modifications to LGPL-licensed code must be shared; dynamic linking is typically permissible. |
| GPL-2.0 / GPL-3.0 | ~10 | High | Strong copyleft — any derivative work must be distributed under the same GPL license. Review whether these packages are dynamically linked. |
| GFDL-1.2 | 4 | Medium | Documentation license — generally acceptable for bundled docs, problematic if software includes GFDL content as functional code. |
| WTFPL | ~3 | Low | Permissive but not OSI-approved; some organizations reject it for lacking explicit patent/liability clauses. |

**Compliance recommendations:**
1. Audit the 10 GPL-licensed packages — verify they are used via dynamic linking only (Node.js `require()`/`import`), which most legal opinions consider non-derivative.
2. The 19 LGPL-3.0 packages are safe for runtime inclusion but any source modifications must be shared.
3. Generate an SPDX-compliant license report using Trivy's `--scanners license` for automated compliance checking in CI/CD.

### 2.6 Secrets Scanning Results

Trivy's secrets scanner found **no embedded secrets** in the Juice Shop image. The scan covered all file layers in the Docker image, checking for:
- API keys, access tokens
- Private keys, certificates
- Passwords, connection strings

This is a positive finding — the application does not leak credentials in its container image layers.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One (3 pts)

### 3.1 Accuracy and Coverage Analysis

#### Package Detection Overlap

| Metric | Value |
|--------|-------|
| Syft unique packages | 1 001 |
| Trivy unique packages | 997 |
| Detected by both tools | 988 (98.7% overlap) |
| Syft-only packages | 13 |
| Trivy-only packages | 9 |

**Analysis:** 98.7% overlap in package detection demonstrates both tools are highly consistent. Syft's 13 exclusive packages include test fixtures with `UNKNOWN` versions (false positives in most contexts) and the Node.js binary itself. Trivy's 9 exclusive packages include `portscanner` and `toposort-class` — genuine npm dependencies missed by Syft. Debian package version formatting also differs: Syft retains full epoch/revision strings while Trivy truncates them.

#### Vulnerability Detection Overlap

| Metric | Value |
|--------|-------|
| Grype unique CVEs | 90 |
| Trivy unique CVEs | 88 |
| Common CVEs | 26 (29% overlap) |
| Grype-only CVEs | 64 |
| Trivy-only CVEs | 62 |

**Analysis:** Only 29% CVE overlap between tools at identifier level is a notable finding. This apparent low overlap is largely explained by:
1. **Different identifier schemes:** Grype prefers GitHub Security Advisories (GHSA-xxx) while Trivy prefers CVE identifiers for the same vulnerability. Many "Grype-only" GHSAs have corresponding "Trivy-only" CVEs for the same issue.
2. **Different vulnerability databases:** Grype uses Anchore's feed (sourced from NVD, GitHub Advisories, vendor feeds); Trivy uses its own aggregated DB (NVD, vendor advisories, Debian tracker, etc.).
3. **Different advisory scope:** Grype scans GHSA data more aggressively for npm packages; Trivy covers more CVE-assigned OS-level advisories.

Despite different identifiers, the total vulnerability count is nearly identical (117 vs 116), confirming comparable overall coverage.

### 3.2 Tool Strengths and Weaknesses

| Dimension | Syft + Grype | Trivy |
|-----------|-------------|-------|
| **Architecture** | Modular — separate tools for SBOM generation and vulnerability scanning | Monolithic — single binary covers SBOM, vulns, secrets, licenses, IaC |
| **SBOM depth** | ✅ Richer metadata: file locations, CPE data, relationship mappings, multiple SBOM formats (SPDX, CycloneDX, native) | ⚠️ Good but less detailed; SBOM is generated as part of vulnerability scan |
| **Vulnerability DB** | ✅ Anchore-curated feed with GHSA emphasis; fast offline DB sync | ✅ Trivy DB with broad vendor advisory coverage; good Debian/Alpine tracking |
| **Scan scope** | ⚠️ Vulnerabilities only; no secrets or license scanning | ✅ Vuln + secrets + license + IaC + RBAC scanning in one tool |
| **Version detail** | ✅ Full Debian epoch/revision versions ensure precise matching | ⚠️ Truncated versions may cause missed or false-positive matches |
| **False positives** | ⚠️ Syft detects test fixtures as real packages; Grype then reports vulns against them | ✅ Fewer spurious packages in detection |
| **Output formats** | ✅ Native JSON, SPDX 2.3 JSON/TagValue, CycloneDX JSON/XML, table | ✅ JSON, table, SARIF, CycloneDX, SPDX, template-based |
| **Performance** | ⚠️ Two sequential scans required (Syft → Grype) | ✅ Single scan covers everything |
| **CI/CD integration** | ✅ GitHub Actions, modular pipeline stages | ✅ GitHub Actions, GitLab CI, native integrations |

### 3.3 Use Case Recommendations

| Use Case | Recommended Tool | Rationale |
|----------|-----------------|-----------|
| **Quick security audit** | Trivy | Single command covers vulnerabilities, secrets, licenses — minimal setup |
| **CI/CD pipeline gating** | Trivy | Simpler to integrate, fewer moving parts, supports `--exit-code 1` for policy enforcement |
| **Regulatory SBOM generation** (NTIA/EO 14028) | Syft | Superior SBOM metadata, proper SPDX/CycloneDX output with relationship data and file-level detail |
| **Deep supply chain analysis** | Syft + Grype | Syft's detailed SBOM enables custom analysis; Grype's GHSA emphasis catches npm-specific advisories |
| **Comprehensive security platform** | Both | Use Syft for SBOM generation/compliance, Trivy for runtime vulnerability + secrets + license scanning |
| **Small team / startup** | Trivy | Lower maintenance burden, single tool to learn, still produces SBOMs when needed |
| **Enterprise compliance** | Syft + Grype + Trivy | Syft for authoritative SBOMs, both scanners for cross-validation (26+ unique CVEs per tool missed by the other) |

### 3.4 Integration Considerations

**CI/CD Pipeline Design:**

```
┌──────────────┐    ┌───────────────┐    ┌──────────────────┐
│  Build Stage  │───▶│  SBOM (Syft)  │───▶│  Vuln (Grype)    │
│              │    │  CycloneDX    │    │  + Trivy scan    │
└──────────────┘    └───────────────┘    └──────────────────┘
                           │                      │
                           ▼                      ▼
                    ┌──────────────┐    ┌──────────────────┐
                    │ SBOM Archive │    │ Merge & Dedupe   │
                    │ (Compliance) │    │ Vuln Report      │
                    └──────────────┘    └──────────────────┘
```

**Operational recommendations:**
1. **Use Syft for SBOM generation** — store SBOMs alongside release artifacts for compliance and audit trail.
2. **Use both Grype and Trivy for vulnerability scanning** — the 29% identifier-level overlap means each tool catches vulnerabilities the other misses. Merge and deduplicate results.
3. **Use Trivy for secrets and license scanning** — Grype does not offer these capabilities.
4. **Automate DB updates** — both tools rely on vulnerability databases that must be refreshed regularly (`grype db update`, `trivy image --download-db-only`).
5. **Set severity thresholds** — block deployments on Critical/High findings; alert on Medium; track Low for future remediation.
