# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3068
- `juice-shop.cdx.json` size: 1832332 bytes (~1.8 MB)
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | — |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | — |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | — |

### Fix-available rate
Out of the top 10 CVEs, **7** have a fix available. The Lecture 4 triage shortcut —
sort by fix-available AND severity ≥ HIGH first — makes these the quick wins: high-impact
vulnerabilities you can close immediately by bumping a package version, so they belong at the
top of the patch queue. CVEs with no published fix can't be remediated by patching, so they
move to a different track (compensating controls, monitoring, or accepting the risk) instead
of blocking the release. In short, patch cadence should be driven by the intersection of
severity and fix-availability, not by severity alone.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ (Trivy−Grype) |
|----------|------:|------:|----------------:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | 104 | 109 | +5 |

### Why the difference?
**CVE #1:** CVE-2015-9235 — found by **Trivy**, missed by **Grype**.
**CVE #2:** GHSA-35jh-r3h4-6jhm — found by **Grype**, missed by **Trivy**.

A large part of the apparent divergence is **identifier convention**, not truly different
findings: Grype labels npm advisories with GitHub IDs (GHSA-…), while Trivy reports the same
underlying issues under their CVE numbers (CVE-…). That is why Grype's "unique" list is almost
all GHSA-* and Trivy's "unique" list is almost all CVE-* — the same vulnerable package often
appears in both, just under a different ID. On top of that, the two tools draw on **different
vulnerability databases** (Grype = Anchore's feed aggregating NVD + GitHub Security Advisories
+ distro sources; Trivy = Aqua's own DB) and **refresh on different cadences**, and they apply
**different package-matching rules**, so a few findings are genuinely present in one tool's DB
and absent in the other's.

### When would you pick each?
- **Syft + Grype (decoupled) wins** when the SBOM itself is a deliverable: you generate the
  inventory once, sign it as an attestation (Lab 8), and re-scan that same SBOM whenever a new
  CVE drops — without re-pulling the image. It gives a durable, portable supply-chain artifact
  and a clean separation between "what's inside" and "what's vulnerable".
- **Trivy (all-in-one) wins** when you want one simple CI step with the broadest coverage: a
  single `trivy image` call scans for CVEs plus IaC misconfigurations and **exposed secrets** —
  in this run Trivy flagged a hardcoded RSA private key in Juice Shop's `insecurity.js`/`.ts`
  that a pure CVE scanner like Grype never looks for. For pipelines that just need fast, wide
  coverage without a separate SBOM artifact, it's less to wire up and maintain.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.5
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (first 30 lines of juice-shop-attestation.json)
```
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
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:f6489946-ac93-442f-bd39-c0e5bbab2b6f",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T22:59:30+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.45.1"
          }
        ]
      },
      "component": {
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json`,
Cosign cryptographically signs the SBOM (the `predicate`) and binds it to the **exact image
identified by its digest** in the `subject`. What's being signed is the claim *"this specific
CycloneDX inventory is the authentic component list of the image with digest sha256:…, vouched
for by the holder of this signing key."* Because the subject pins the immutable digest (not a
mutable tag), the attestation can't be silently transferred to a different image, and any
tampering with the SBOM breaks the signature. This gives downstream consumers verifiable
supply-chain provenance: they can confirm the SBOM genuinely describes the image they are about
to run, and trace it back to a trusted signer.
