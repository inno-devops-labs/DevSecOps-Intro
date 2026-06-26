# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1.8 MB (1832321 bytes)
- `juice-shop.spdx.json` component count: 908 packages

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | |

### Fix-available rate
Out of the top 10 CVEs, how many have a fix available? What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
*sort by fix-available AND severity ≥ HIGH first*.)

Out of the top 10 Critical/High CVEs, 8 out of 10 have a fix available, giving an 80% fix rate. Following Lecture 4's triage shortcut — prioritize fix-available AND severity ≥ HIGH first — the immediate action items are jsonwebtoken (upgrade from 0.1.0/0.4.0 to 4.2.2), lodash (upgrade from 2.4.2 to 4.17.12+), and crypto-js (upgrade from 3.3.0 to 4.2.0). The two unfixable findings (libc6 CVE-2026-5450 marked "won't fix" and marsdb with no upstream patch) should be documented as accepted risks or mitigated at the network/runtime layer until upstream releases a fix.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 35 | -16 |
| Medium | 35 | 39 | 4 |
| Low | 4 | 22 | 18 |
| **Total** | 97 | 101 | 4 |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:
1. CVE ID + tool that found it + tool that missed it
**CVE-2026-5450** (libc6, Critical) — found by Grype, missed by Trivy.
Grype pulled this from the OSV/NVD feed and flagged it as Critical with
"won't fix" status. Trivy's Debian advisory DB hadn't ingested it yet at
scan time, so it simply doesn't appear in Trivy's output. This is a classic
DB refresh cadence gap — both tools scanned the same image on the same day
but disagreed because they pull from different upstream sources.

2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?
**CVE-2026-26996** (minimatch, High) — found by Trivy, not surfaced by Grype
under that CVE ID. Grype maps the same vulnerability to its GitHub Advisory
identifiers (GHSA-3ppc-4f35-3m26 and GHSA-7r86-cg39-jmmj) instead of the
NVD CVE ID. This is a package matching / ID aliasing difference — the
vulnerability is the same, but without cross-referencing both DBs it looks
like a discrepancy.
(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

### When would you pick each?
2-3 sentences each:
- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8)
**Syft+Grype (decoupled):** The decoupled model wins when the SBOM itself is
the deliverable — for example, when signing it as a Cosign attestation in
Lab 8 or sharing it with a customer for compliance audit. You generate the
SBOM once and re-scan it with Grype every time the CVE DB updates, without
re-pulling a multi-GB image each time.

- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig)
**Trivy (all-in-one):** Trivy wins when you want a single CI step with no
pipeline glue. Beyond SCA it also found the embedded RSA private key inside
`insecurity.js` — something Grype doesn't do at all since it's a pure
vulnerability scanner. If your team also needs IaC misconfiguration checks
and secret detection in the same tool, Trivy covers all of that in one command.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.6
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)
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
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:e8665704-8b40-4365-ac7b-9d1d430a8b55",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-19T20:10:52+03:00",
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

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json`,
it wraps this file in a cryptographic signature tied to the specific image digest
(sha256:fd58bdc9...) and pushes the attestation to the registry alongside the image.
This proves the supply-chain claim that the SBOM was produced by a trusted party and
hasn't been tampered with — anyone pulling the image can verify that it contains exactly
these 3069 components. This is the operational answer to the next Log4Shell-style incident:
instead of manually checking every service, you query the signed SBOM to instantly know
whether your image depends on the affected library.
