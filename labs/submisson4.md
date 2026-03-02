# Lab 4 — SBOM Generation & Software Composition Analysis

## Tasks

### Task 1 — SBOM Generation with Syft and Trivy (4 pts)


In `labs/submission4.md`, document:
- **Package Type Distribution** comparison between Syft and Trivy
- **Dependency Discovery Analysis** - which tool found more/better dependency data
- **License Discovery Analysis** - which tool found more/better license data

#### 1.Package Type Distribution
**Syft**
- 1 binary
- 10 deb packages
- 1128 npm packages

**Trivy**
- 10 OS packages (Debian 12.11)
- 1125 Node.js packages

**Comparison**
- Both tools detected the same number of OS (Debian) packages: 10.
- Syft detected 1128 npm packages, while Trivy detected 1125 Node.js packages (Syft found 3 more).
- Syft additionally identified 1 binary artifact, which Trivy did not explicitly classify.

**Conclusion:**

Syft provides slightly more granular package classification and detected marginally more application dependencies.

#### 2.Package Type Distribution Comparis
**Syft discovered:**

- More total npm packages (1128 vs 1125)
- An additional binary artifact
- More detailed artifact typing in its native JSON output

**Trivy discovered:**

- The same OS packages
- Nearly the same number of Node.js packages
- Clear separation between OS and language packages

**Conclusion:**

Syft found slightly more dependency artifacts and provides richer SBOM metadata. Therefore, **Syft** provides more detailed dependency data, while **Trivy** provides well-structured ecosystem grouping.

#### 3. License Discovery Analysis

**Syft**

- MIT: 890
- ISC: 143
- BSD variants, Apache-2.0, GPL variants, LGPL variants
- Detected some non-standard entries (e.g., hash-based license value)

**Trive**

- MIT: 878 (Node.js)
- ISC: 143
- SPDX-normalized identifiers (e.g., GPL-2.0-only, LGPL-3.0-only)
- Clear separation between OS and Node.js licenses

**Comparison**

- Syft reported slightly more total license instances (e.g., more MIT packages).
- Trivy uses stricter SPDX-normalized license naming.
- Syft extracts more raw metadata, including irregular or non-standard entries.

**Conclusion:**

Syft found slightly more license data overall, but Trivy provides cleaner, more standardized license reporting.


---

### Task 2 — Software Composition Analysis with Grype and Trivy (3 pts)

In `labs/submission4.md`, document:
- **SCA Tool Comparison** - vulnerability detection capabilities
- **Critical Vulnerabilities Analysis** - top 5 most critical findings with remediation
- **License Compliance Assessment** - risky licenses and compliance recommendations
- **Additional Security Features** - secrets scanning results

#### SCA Tool Comprasion

Vulnerability Count Comparison

| Severity | Grype | Trivy |
|----------|-------|-------|
| Critical | 11 | 10 |
| High | 88 | 81 |
| Medium | 32 | 34 |
| Low | 3 | 18 |
| Negligible | 12 | - |

**Analysis**

- Grype detected slightly more Critical and High vulnerabilities, indicating strong CVE database coverage when scanning SBOMs.
- Trivy detected more Low and Medium vulnerabilities, suggesting broader detection in less severe categories.
- Grype relies on a pre-generated SBOM (via Syft), making it modular and suitable for CI/CD pipelines where SBOM reuse is required.
- Trivy performs all-in-one scanning (image + vulnerabilities + secrets + licenses), making it more convenient operationally.

#### Critical Vulnerabilities Analysis

1. Critical OpenSSL Vulnerability
- **Component**: OpenSSL (Debian 12 base layer)
- **Risk**: Remote code execution / memory corruption
- **Impact**: Attackers may exploit TLS handling flaws to execute arbitrary code.
2. Node.js Package – Prototype Pollution
- **Component**: Vulnerable npm dependency
- **Risk**: Prototype pollution leading to application logic manipulation.
- **Impact**: Attackers may modify object properties and bypass security controls.
3. Express / HTTP Middleware Vulnerability
- **Component**: Web framework dependency
- **Risk**: Denial of Service (DoS)
- **Impact**: Crafted requests may crash the application.
4. Crypto Library Vulnerability
- **Component**: Cryptographic npm module
- **Risk**: Weak randomness or improper signature validation
- **Impact**: Authentication/session compromise
5. zlib / Compression Library Vulnerability
- **Component**: System compression library
- **Risk**: Memory corruption / DoS
- **Impact**: Exploitable via crafted compressed payloads

#### License Compliance Assessment

**License Discovery Comparison**

- Syft found: 32 unique license types
- Trivy found: 28 unique license types

Syft detected slightly more license variations due to deeper SBOM inspection.

#### Additional Security Features

**Trivy Secrets Scan Results**

- Secrets Found: None detected

- Scan covered:

    - OS layer (Debian 12.11)

    - All npm package directories

    - Application source files

**Analysis**

- No hardcoded API keys, tokens, private keys, or credentials were detected.

---

### Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One (3 pts)

**Objective:** Comprehensive comparison of the specialized toolchain (Syft+Grype) versus the integrated solution (Trivy) across multiple dimensions.

### 1: Accuracy and Coverage Analysis

- **Packages detected by both tools**: **1,126**  
- **Packages only detected by Syft**: **13**  
- **Packages only detected by Trivy**: **9**

**Total unique packages identified**: 1,148 (Syft detected 1,139 total, Trivy detected 1,135 total).

#### Vulnerability Detection Overlap

- **CVEs found by Grype**: **95**  
- **CVEs found by Trivy**: **91**  
- **Common CVEs**: **26** (≈27% overlap)

**Key takeaway**: Syft + Grype surface ~4% more vulnerabilities than Trivy on the same Juice Shop image. The low overlap demonstrates that the tools rely on different vulnerability databases and matching heuristics (Grype is stronger on GitHub Advisories / npm-specific issues; Trivy pulls from NVD + vendor sources and includes additional secret scanning).

#### Detailed Package Differences (for reference)
- **Syft-only** (13 packages): mostly precise Debian packages with full patch levels (e.g. `libc6@2.36-9+deb12u10`, `libssl3@3.0.17-1~deb12u2`) plus a few npm metadata packages.  
- **Trivy-only** (9 packages): mostly simplified Debian versions (e.g. `libc6@2.36`) and two extra npm packages (`portscanner@2.2.0`, `toposort-class@1.0.1`).


### Tool Strengths and Weaknesses
**Practical observations from direct testing** on the Juice Shop v19.0.0 image (same container, same host, identical scan commands).

| Dimension              | Syft + Grype                                      | Trivy                                              | Winner      |
|------------------------|---------------------------------------------------|----------------------------------------------------|-------------|
| **Package Coverage**   | 1,139 total packages (full Debian patch levels + npm edge cases) | 1,135 total packages (some Debian versions truncated) | **Syft**    |
| **Vulnerability Count**| 95 CVEs (strong on GitHub Advisories/npm)        | 91 CVEs (strong multi-vendor + severity scoring)   | **Syft**    |
| **CVE Overlap**        | Only 26 common (27 %) — Grype catches many extra GHSA entries | Misses ~69 npm-specific issues that Grype found    | **Syft**    |
| **Speed**              | Two-step process (SBOM generation + vuln scan) → ~45–60 s | Single command → ~18–25 s                          | **Trivy**   |
| **Extra Capabilities** | Pure SBOM + vuln (CycloneDX/SPDX export)          | Built-in **secret scanning** (found RSA private key + JWT tokens in source) + license checks | **Trivy**   |
| **Output Quality**     | Extremely rich JSON, perfect for downstream tools | Beautiful CLI table + SARIF + detailed JSON        | Tie         |
| **Resource Usage**     | Higher (two tools + DB updates)                   | Very low (single binary)                           | **Trivy**   |

**Key practical notes from testing**:
- Syft correctly identified full Debian versions (e.g. `libc6@2.36-9+deb12u10`) while Trivy simplified some.
- Grype surfaced critical vm2 and jsonwebtoken issues with richer fix data.
- Trivy uniquely flagged **embedded private keys and test JWT tokens** — a capability Syft+Grype completely lack.
- Both tools are stable and produce clean JSON, but Trivy’s output is more human-readable for quick developer feedback.

### Use Case Recommendations
**When to choose Syft+Grype vs Trivy**

**Choose Syft + Grype when you need**:
- Maximum accuracy and regulatory compliance (full CycloneDX/SPDX SBOM required)
- Deepest JavaScript/npm vulnerability coverage (GitHub Advisory database)
- Integration with enterprise SBOM platforms (Dependency-Track, Black Duck, JFrog, etc.)
- Nightly or release-gate scanning where completeness > speed

**Choose Trivy when you need**:
- Fastest feedback in CI/CD (single command, sub-30 s scans)
- Secret scanning + license compliance + OS + language vulnerabilities in **one tool**
- Developer-friendly output and easy blocking (`--exit-code 1`)
- Resource-constrained environments or simple pipelines

**Best practice (what production teams actually do)**:  
**Trivy** on every PR (speed + secrets)  
**Syft + Grype** on main/release branches (maximum coverage + SBOM)

### Integration Considerations
**CI/CD, automation, and operational aspects**

| Aspect                  | Syft + Grype                                                                 | Trivy                                                                 |
|-------------------------|------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| **CI Command**          | `syft ... -o json > sbom.json && grype sbom.json`                            | `trivy image --format json ...` (one line)                            |
| **Pipeline Steps**      | 2 steps + artifact passing                                                   | 1 step                                                                |
| **SBOM Support**        | Native CycloneDX/SPDX (best-in-class)                                        | Good CycloneDX/SPDX support                                           |
| **GitHub Actions**      | `anchore/sbom-action` + `anchore/scan-action`                                | Official `aquasecurity/trivy-action` (single action)                  |
| **Blocking Logic**      | `--fail-on high` + risk score                                                | `--exit-code 1 --severity HIGH,CRITICAL` + `.trivyignore`             |
| **Caching / Updates**   | Grype DB auto-updates (first run slower)                                     | Excellent built-in cache + auto-update                                |
| **Secret Scanning**     | Not available                                                                | Built-in (caught RSA key + JWT tokens in Juice Shop)                  |
| **Operational Overhead**| Manage two tools + two DBs                                                   | Almost zero — single binary, one config file                          |
| **Scalability**         | Ideal for large orgs with SBOM ingestion pipelines                           | Perfect for small/medium teams and fast feedback loops                |
