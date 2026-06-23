# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: <3068>
- `juice-shop.cdx.json` size: <1832332 bytes (~1.8 MB)>
- `juice-shop.spdx.json` component count: <909>

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | <7> |
| High | <50> |
| Medium | <35> |
| Low | <4> |
| Negligible | <7> |
| **Total** | <103> |
By status: 88 fixed, 15 not-fixed, 0 ignored.

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| <GHSA-c7hr-j4mj-j2w6> | <Critical> | <jsonwebtoken> | <0.1.0> | <4.2.2> |
| <GHSA-c7hr-j4mj-j2w6> | <Critical> | <jsonwebtoken> | <0.4.0> | <4.2.2> |
| <GHSA-jf85-cpcp-j695> | <Critical> | <lodash> | <2.4.2> | <4.17.12> |
| <GHSA-xwcq-pm8m-c4vf> | <Critical> | <crypto-js> | <3.3.0> | <4.2.0> |
| <CVE-2026-5450> | <Critical> | <libc6> | <2.41-12+deb13u2> | <empty> |
| <CVE-2026-34182> | <Critical> | <libssl3t64> | <3.5.5-1~deb13u2> | <3.5.6-1~deb13u2> |
| <GHSA-5mrr-rgp6-x4gr> | <Critical> | <marsdb> | <0.6.11> | <empty> |
| <GHSA-35jh-r3h4-6jhm> | <High> | <lodash> | <2.4.2> | <4.17.21> |
| <GHSA-8hfj-j24r-96c4> | <High> | <moment> | <2.0.0> | <2.29.2> |
| <GHSA-p6mc-m468-83gw> | <High> | <lodash.set> | <4.3.2> | <empty> |

### Fix-available rate
Out of the top 10 CVEs, how many have a fix available? 7

What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
*sort by fix-available AND severity ≥ HIGH first*.)
7: they are the highest-leverage backlog items because the fix is one version bump away. 
3: without a fix go into a separate stream: track upstream, apply compensating controls, and watch for a patch.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | <7> | <5> | <5-7=-2> |
| High | <50> | <42> | <42-50=-8> |
| Medium | <35> | <39> | <39-35=4> |
| Low | <4> | <22> | <22-4=18> |
| **Total** | <103> | <108> | <108-103=5> | also I counted Negligible <7> <0> <0-7=-7>

### Why the difference?
Out of 152 unique IDs across both tools, only 32 IDs overlap; Grype has 58 unique IDs, Trivy has 62. The root cause is that each tool uses a different identifier vocabulary for the same defects: Grype emits GHSA, Trivy emits CVE. So most of the "exclusive" findings in each tool are the same vulnerability under a different ID.

Pick **two specific CVEs** that ONE tool found and the other didn't. For each:
1. CVE ID + tool that found it + tool that missed it
1) GHSA-35jh-r3h4-6jhm + by Grype + by Trivy
2) CVE-2019-10744 + by Trivy + by Grype
2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?
1) It is a Prototype Pollution in lodash 2.4.2 registered in the GitHub Security Advisory database. Trivy maps to NVD CVE IDs first and has no matching CVE record for this advisory in its DB -> not surface.
2) It is a Prototype Pollution in lodash registered in NVD. Grype reports the same family of defects under its own GHSA IDs -> literal string comparison of identifiers shows the CVE as missing even though the underlying issue is covered.
(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

### When would you pick each?
2-3 sentences each:
- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8) When the SBOM is the artifact you ship and re-scan over time: generate the SBOM once at build time, store it next to the image, and re-run Grype every time the vulnerability DB updates — no re-pulling the image. 
- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig) When CI just needs one binary that covers the broadest scope.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: <1.6>
- `bomFormat`: <CycloneDX>

### Image digest captured
- `docker inspect ... RepoDigests`: <output — should be sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0>

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)
<{
"_type": "https://in-toto.io/Statement/v1",
"subject": [
{
"name": "bkimminich/juice-shop",
"digest": {
"sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"}
}],
"predicateType": "https://cyclonedx.org/bom/v1.6",
"predicate": { "specVersion": "1.6", "bomFormat": "CycloneDX", ... }}
>

### What this enables in Lab 8
1 paragraph: when Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`,
what specifically is being signed and what claim does it prove? (Reference Lecture 8 slide 9.)
in-toto attestation format. As the lecture puts it, "A signature proves who. An attestation proves what." The envelope follows the standard shape from the slide: "in-toto attestation format = the standard envelope. Subject identifies what's being attested; predicate is the claim's content" — so the `subject` field pins our exact image (`bkimminich/juice-shop`, `sha256…`), and the `predicate` carries the full CycloneDX SBOM under `predicateType: https://cyclonedx.org/bom/v1.6`. The signature therefore binds the exact image digest to the exact SBOM document, so any downstream verifier can prove that this SBOM is the authoritative inventory for this specific image and that nobody swapped the SBOM or re-pointed it at a different image after signing. 