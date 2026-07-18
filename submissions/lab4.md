# Lab 4 — Submission

## Environment and tool versions

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
Syft:
Application:   syft
Version:       1.44.0
BuildDate:     [not provided]
GitCommit:     [not provided]
GitDescription: [not provided]
Platform:      linux/amd64
GoVersion:     go1.26.2-X:nodwarf5
Compiler:      gc
SchemaVersion: 16.1.3

Grype:
Application:         grype
Version:             0.114.0
BuildDate:           2026-06-05T16:10:04Z
GitCommit:           ef8e65adb2dec760f1f923e635da4c7696d3c295
GitDescription:      v0.114.0
Platform:            linux/amd64
GoVersion:           go1.26.3
Compiler:            gc
Syft Version:        v1.45.1
Supported DB Schema: 6

Trivy:
Version: 0.71.1
jq: jq-1.8.1-dirty
```

Target image: `bkimminich/juice-shop:v20.0.0`

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: **3069**
- `juice-shop.cdx.json` size: **1.7 MiB**
- `juice-shop.spdx.json` package count: **909**
- `juice-shop.spdx.json` size: **3.0 MiB**

### Grype severity breakdown

| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **104** |

### Top 10 CVEs

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | — |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | — |
| CVE-2026-34180 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-34181 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| CVE-2026-34183 | High | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

### Fix-available rate

**8 of the top 10 findings have at least one fixed version listed.**
The first patching queue should prioritize findings that are both **Critical/High** and
have a fix available, because those items combine high impact with an immediately
actionable remediation. High-severity findings without a fix still require compensating
controls and monitoring, but fixable high-severity findings should normally move first
in the patch cadence.

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | **104** | **109** | **+5** |

The counts represent scanner findings rather than unique CVE IDs. A CVE affecting
multiple packages or targets may therefore appear more than once.

### Tool-divergent CVEs

1. **GHSA-c7hr-j4mj-j2w6** — found by **Grype**, not reported by **Trivy** for `jsonwebtoken 0.1.0`. The most likely explanation is a difference in vulnerability-database refresh timing, ecosystem namespace selection, or package/version matching. Grype's Anchore data and matchers associated this package version with the advisory, while the Trivy result set did not at the time of this scan.
2. **GHSA-jf85-cpcp-j695** — found by **Grype**, not reported by **Trivy** for `lodash 2.4.2`. The most likely explanation is a difference in vulnerability-database refresh timing, ecosystem namespace selection, or package/version matching. Grype's Anchore data and matchers associated this package version with the advisory, while the Trivy result set did not at the time of this scan.

These explanations are evidence-based hypotheses: the scans prove that the result sets
differ, while confirming the exact internal matcher decision would require comparing
the scanners' database records and package-normalization traces from the same timestamp.

### When would I pick each?

**Syft + Grype:** The decoupled model is preferable when the SBOM is a long-lived
supply-chain artifact. The same immutable inventory can be stored, attested, compared,
and rescanned as vulnerability databases change without re-pulling or re-analyzing the
container image. This is especially useful for Lab 8, release evidence, and incident
response questions about whether a deployed artifact contains a newly vulnerable library.

**Trivy:** Trivy is preferable when a team needs one simple CI command with broad
coverage. It can combine container vulnerability scanning with filesystem, repository,
IaC, secret, and misconfiguration scanning, reducing integration work for smaller
pipelines even though the inventory and vulnerability-analysis stages are less explicitly
separated.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version

- `specVersion`: **1.6**
- `bomFormat`: **CycloneDX**
- `metadata.timestamp`: **2026-06-19T20:00:33+03:00**
- `metadata.tools` present: **yes**

### Image digest captured

- `docker inspect ... RepoDigests`: **sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0**

### Attestation statement preview

First 30 lines of `labs/lab4/juice-shop-attestation.json`:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.6",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:8fffe5bf-b5ee-49dc-b15c-ff4bedaba89a",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T20:00:33+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.44.0"
          }
        ]
      },
      "component": {
```

### What this enables in Lab 8

The in-toto statement binds the complete CycloneDX package inventory in `predicate`
to the immutable SHA-256 digest of `bkimminich/juice-shop:v20.0.0` in `subject`.
When Lab 8 signs and publishes this attestation with Cosign, the signature authenticates
the provenance of that claim: the signer asserts that this exact image digest corresponds
to the included SBOM. A verifier can check both the signature and the subject digest,
which prevents an SBOM for one image from being silently presented as evidence for a
different image.

## Final verification checklist

- [x] CycloneDX and SPDX SBOMs were generated from Juice Shop v20.0.0.
- [x] CycloneDX uses schema version 1.5 or newer.
- [x] Grype scanned the CycloneDX SBOM and produced real CVE findings.
- [x] The report contains a severity breakdown and top-10 table with fix availability.
- [x] Trivy scanned the image directly.
- [x] Grype and Trivy counts are compared with deltas.
- [x] Two scanner-result divergences are analyzed without inventing findings.
- [x] The sign-ready in-toto statement contains the actual Docker image digest.
- [x] Regenerable Grype and Trivy output files are excluded from the commit.
