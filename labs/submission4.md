# Lab 4 - SBOM Generation & Software Composition Analysis

## Scope and Setup

In this lab I generated SBOMs for `bkimminich/juice-shop:v19.0.0` using two approaches:

- **Specialized toolchain:** Syft for SBOM + Grype for vulnerability analysis
- **Integrated tool:** Trivy for SBOM, vulnerability, secret, and license scanning

Because I worked on Windows PowerShell, I adapted several commands from the lab handout (which was written for bash) and used the `docker save` + `--input` / `oci-archive` flow to avoid Docker socket mounting issues.

---

## Task 1 - SBOM Generation with Syft and Trivy

### 1.1 Package Type Distribution

The generated SBOMs show that the target image is heavily dominated by Node.js dependencies, with a small set of Debian OS packages and one binary artifact.

**Syft package distribution:**
- `npm`: **1128**
- `deb`: **10**
- `binary`: **1**

**Trivy package distribution:**
- Total package entries detected in my analysis output: **1135**

This confirms that Juice Shop is primarily an application-layer dependency graph (Node.js ecosystem), while the base image contributes a relatively small OS package surface.

### 1.2 Dependency Discovery Analysis

Both tools detected very similar dependency coverage, but not identical.

- Packages detected by both tools: **988**
- Packages only detected by Syft: **13**
- Packages only detected by Trivy: **9**

This indicates strong overlap in core package discovery, but also shows that SBOM output is not perfectly identical between tools. In practice:

- **Syft** appears slightly more detailed for certain package representations and unknown-version entries.
- **Trivy** provides very strong integrated visibility, but its package normalization differs from Syft, so one-to-one matching is imperfect.

My conclusion is that both tools are usable for SBOM generation, but **Syft is slightly better when the SBOM itself is the main artifact**, while **Trivy is better when SBOM generation is part of a broader all-in-one scan workflow**.

### 1.3 License Discovery Analysis

License coverage also differed between tools:

- **Syft** found **32 unique license types**
- **Trivy** found **28 unique license types**

This suggests that **Syft exposed slightly broader license metadata** in this run, which is useful for compliance-oriented inventory generation.

At the same time, Trivy's license output is operationally convenient because it classifies licenses by severity/category (for example, notice/restricted/unknown), which is helpful when the goal is compliance triage rather than raw inventory.

### 1.4 Practical Takeaway

For SBOM-focused workflows:

- Choose **Syft** when you want a more SBOM-centric inventory artifact and broader raw metadata extraction.
- Choose **Trivy** when you want fast integrated package inventory as part of security scanning.

---

## Task 2 - Software Composition Analysis with Grype and Trivy

### 2.1 SCA Tool Comparison

The two scanners produced different vulnerability distributions.

**Grype vulnerabilities by severity:**
- High: **86**
- Medium: **32**
- Negligible: **12**
- Critical: **11**
- Low: **3**

**Trivy vulnerabilities by severity:**
- HIGH: **81**
- MEDIUM: **34**
- LOW: **18**
- CRITICAL: **10**

At the aggregate level:

- **Grype** reported **93 unique CVE/GHSA identifiers**
- **Trivy** reported **91 unique CVE identifiers**
- Common findings between both tools: **26**

This relatively small overlap compared with total finding counts shows that the tools use different advisory sources, matching logic, and normalization rules. So for real vulnerability triage, relying on only one scanner can miss issues that the other one surfaces.

### 2.2 Top 5 Critical Findings and Remediation

Based on the generated reports, the most important critical issues are concentrated in outdated JavaScript dependencies.

1. **`vm2@3.9.17` - sandbox escape / RCE class issue**
   - Finding: `GHSA-whpj-8f3w-67p5`
   - Severity: **Critical**
   - Fixed in: **3.9.18**
   **Remediation:** upgrade `vm2` to at least `3.9.18` immediately.

2. **`vm2@3.9.17` - additional critical advisory**
   - Finding: `GHSA-g644-9gfx-q4q4`
   - Severity: **Critical**
   - No fixed version shown in the reviewed table snippet
   **Remediation:** prioritize removing or upgrading `vm2`; if no safe version is acceptable, replace the dependency.

3. **`vm2@3.9.17` - another critical advisory**
   - Finding: `GHSA-cchq-frgv-rjh5`
   - Severity: **Critical**
   - Fixed in: **3.10.0**
   **Remediation:** prefer upgrading to the newest compatible secure version, not just the minimum patch.

4. **`jsonwebtoken@0.1.0` / `jsonwebtoken@0.4.0` - verification bypass**
   - Finding: `GHSA-c7hr-j4mj-j2w6`
   - Severity: **Critical**
   - Fixed in: **4.2.2**
   **Remediation:** upgrade all `jsonwebtoken` instances to at least `4.2.2`; ideally move to a modern maintained version and verify all transitive dependencies.

5. **`lodash@2.4.2` - critical vulnerable legacy version**
   - Finding: `GHSA-jf85-cpcp-j695`
   - Severity: **Critical**
   - Fixed in: **4.17.12**
   **Remediation:** replace or upgrade legacy `lodash` immediately, because very old utility libraries tend to accumulate multiple known issues.

### 2.3 Risk Prioritization

The highest-risk pattern in this image is not the Debian base layer; it is the **legacy Node.js dependency tree**.

Evidence for this:
- Trivy's table summary showed only **27 Debian vulnerabilities** in the OS layer.
- Most severe findings in the human-readable reports are tied to **npm packages**, especially `vm2`, `jsonwebtoken`, `lodash`, and related application dependencies.

So the most effective remediation strategy is:

1. **Patch high-risk npm dependencies first**
2. **Regenerate lockfiles / review transitive dependencies**
3. **Then patch the smaller OS package set**
4. **Rescan after each dependency update cycle**

### 2.4 License Compliance Assessment

License scanning did not indicate a catastrophic compliance issue, but it did show a mix of license categories that should be reviewed.

Key observations:
- Trivy reported both **notice-style licenses** (for example, MIT) and some **restricted/unknown** entries.
- Example restricted case in the report: **`GPL-2.0-only`** for `netbase`
- Example unknown/ad-hoc/public-domain style entries also appeared in the output

This means the image is **not automatically non-compliant**, but it does require legal/compliance review if used in a stricter enterprise environment.

**Compliance recommendations:**
- Export and review all non-permissive licenses separately
- Flag `GPL-*` packages for policy review
- Treat `unknown` / `ad-hoc` licenses as manual review candidates
- Maintain an allowlist/denylist policy in CI

### 2.5 Additional Security Features (Secrets Scan)

Trivy's secret scan is valuable because it catches issues outside classic CVE matching.

In this run, the summary table mostly showed clean entries, but the detailed secret scan output included **one high-severity secret finding**:

- File: `/juice-shop/build/lib/insecurity.js`
- Type: **AsymmetricPrivateKey**
- Severity: **HIGH**

This is an important reminder that a supply-chain scan should not stop at package CVEs: embedded secrets and keys can be equally dangerous.

**Recommendation:** remove embedded keys from the image, rotate any exposed material, and move secrets to proper secret management.

---

## Task 3 - Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1 Accuracy Analysis

#### Package Detection

- Packages detected by both tools: **988**
- Packages only detected by Syft: **13**
- Packages only detected by Trivy: **9**

Interpretation:
- The overlap is high, which means both tools are broadly consistent.
- The non-overlapping sets show that package parsing and normalization are still tool-dependent.
- For strict inventory reconciliation, results from different tools should not be assumed identical.

#### Vulnerability Detection Overlap

- CVEs/advisories found by Grype: **93**
- CVEs found by Trivy: **91**
- Common findings: **26**

Interpretation:
- The overlap is much smaller than the package overlap.
- This confirms that vulnerability databases and matching logic differ substantially.
- A single-scanner workflow is simpler, but a dual-scanner workflow gives broader coverage.

### 3.2 Tool Strengths and Weaknesses

#### Syft + Grype

**Strengths**
- Clear separation of concerns: SBOM generation and vulnerability analysis are decoupled
- Strong raw SBOM metadata
- Better fit when SBOMs need to be stored, shared, or reused as first-class artifacts
- Slightly broader license diversity discovered in this run

**Weaknesses**
- Requires multiple tools and multiple steps
- More moving parts in CI/CD
- Operational overhead is higher than an all-in-one scanner

#### Trivy

**Strengths**
- Single tool for SBOM, vulnerabilities, secrets, and licenses
- Easier to integrate into pipelines
- Good for fast operational scanning and developer workflows
- Convenient policy-oriented license output

**Weaknesses**
- Less modular
- Package/vulnerability normalization differs from specialized tools, so direct comparison can be noisy
- In all-in-one mode, output can be broader but less specialized for dedicated SBOM management

### 3.3 Use Case Recommendations

Use **Syft + Grype** when:
- You need a reusable SBOM artifact
- You want a modular supply-chain pipeline
- SBOM quality, metadata retention, and reusability matter more than operational simplicity

Use **Trivy** when:
- You want one command for multiple security checks
- You are integrating fast checks into CI/CD
- Developer convenience and quick triage are the priority

Use **both together** when:
- The environment is higher risk
- You need broader detection coverage
- You want to cross-check critical findings before remediation decisions

### 3.4 Integration Considerations

From an operational point of view:

- **Trivy** is easier to adopt in CI because one tool covers multiple security domains.
- **Syft + Grype** is better for mature pipelines where SBOM generation is a separate, auditable stage.
- On Windows, the lab's original bash-based commands required adaptation:
  - PowerShell does not support bash line continuations (`\`)
  - utilities like `jq`, `uniq`, and `comm` were not available by default
  - using `docker save` and scanning the image tar archive was the most reliable workaround

This is important in practice: the "best" tool is not only about detection quality, but also about how easily the workflow can be automated and maintained on the target platform.

---

## Final Conclusion

This lab demonstrated that **Syft+Grype** and **Trivy** are both effective, but they optimize for different goals.

- **Syft+Grype** is stronger as a specialized, modular supply-chain toolchain.
- **Trivy** is stronger as a practical all-in-one scanner for day-to-day DevSecOps use.
- The quantitative comparison shows strong package overlap but much weaker vulnerability overlap, so **cross-validation is valuable**, especially for critical findings.
- The highest practical risk in this image comes from **outdated Node.js dependencies**, with additional exposure from an embedded private key discovered by the secret scanner.

For a real CI/CD pipeline, my preferred approach would be:

1. Generate and archive an SBOM with **Syft**
2. Scan it with **Grype**
3. Run **Trivy** as an additional integrated control for vulnerabilities, licenses, and secrets
4. Fail the pipeline on critical findings and trigger remediation review

---

## Commands Used (Adapted for Windows PowerShell)

I used the lab workflow conceptually, but adapted execution for Windows PowerShell:

- `docker save` to export the target image into a tar archive
- Syft against `oci-archive`
- Trivy against `--input /tmp/labs/lab4/juice-shop.tar`
- PowerShell JSON parsing (`ConvertFrom-Json`) instead of `jq`
- PowerShell comparison logic instead of `uniq` / `comm`

This adaptation preserved the intended lab outcome while avoiding shell compatibility issues on Windows.
