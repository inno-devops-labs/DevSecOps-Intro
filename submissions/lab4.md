# Lab 4 — SBOM + SCA

## Task 1

### Inventory
| Format | Count field | Count | Spec |
|--------|-------------|------:|------|
| CycloneDX | `.components` | **3068** | **1.7** |
| SPDX | `.packages` | **909** | — |

CycloneDX counts nested components (OS packages, npm deps, binaries, files metadata Syft attaches), while SPDX’s package list is flatter and omits many transitive/file-level entries — same image, different counting rules.

### Grype severity (from SBOM)

| Severity | Count |
|----------|------:|
| Critical | 14 |
| High | 84 |
| Medium | 60 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 4 |
| **total** | **181** |

### Top 10

```
Critical	GHSA-c7hr-j4mj-j2w6	jsonwebtoken@0.1.0	fix: 4.2.2
Critical	GHSA-c7hr-j4mj-j2w6	jsonwebtoken@0.4.0	fix: 4.2.2
Critical	GHSA-jf85-cpcp-j695	lodash@2.4.2	fix: 4.17.12
Critical	CVE-2026-63073	libssl3t64@3.5.5-1~deb13u2	fix: 3.5.7-1~deb13u2
Critical	GHSA-mp2f-45pm-3cg9	decompress@4.2.1	fix: 
Critical	GHSA-xwcq-pm8m-c4vf	crypto-js@3.3.0	fix: 4.2.0
Critical	GHSA-23hp-3jrh-7fpw	tar@4.4.19	fix: 7.5.19
Critical	GHSA-23hp-3jrh-7fpw	tar@6.2.1	fix: 7.5.19
Critical	GHSA-23hp-3jrh-7fpw	tar@7.5.15	fix: 7.5.19
Critical	CVE-2026-5450	libc6@2.41-12+deb13u2	fix: 
```

**9/10** rows have a fix version (only `decompress` and wait - decompress has empty fix, libc6 empty - so **8/10** have fixes). First action: bump `jsonwebtoken` / `lodash` / `crypto-js` / `tar` in the app dependency tree (Critical + available fix), then plan a base-image rebuild for OpenSSL/`libc6` when Debian publishes a fix.

## Task 2

### Side-by-side

| Severity | Grype | Trivy | Δ (G−T) |
|----------|------:|------:|--------:|
| Critical / CRITICAL | 14 | 10 | +4 |
| High / HIGH | 84 | 64 | +20 |
| Medium / MEDIUM | 60 | 66 | -6 |
| Low / LOW | 12 | 31 | -19 |
| Negligible / Unknown | 11 | 0 | — |
| **Total** | **181** | **171** | **+10** |

### Divergent IDs
- **Grype-only:** `CVE-2026-48931` on `node@24.15.0` — newer Node advisory present in Grype’s DB matching rules; Trivy’s DB/matcher had not associated it yet (advisory-source lag).
- **Trivy-only:** `CVE-2017-16016` (old npm ecosystem hit Trivy still reports) — different matching against historical npm advisories Trivy retains that Grype’s SBOM path did not emit for this inventory.

### Decoupled vs all-in-one
Keep the SBOM when you will **re-scan without re-pulling** and when Lab 8 must **sign the CycloneDX file as an attestation** — one inventory, many consumers. Prefer a single binary (Trivy) for a quick gate in CI when you only need “fail the build” and will not attach attestations. For this course, Syft→Grype + keep `juice-shop.cdx.json` is required because Cosign signs that artifact later.

## Bonus

```bash
DIGEST=$(docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}' | sed 's/.*@sha256://')
jq -n --arg dig "$DIGEST" --slurpfile bom labs/lab4/juice-shop.cdx.json '{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{"name": "bkimminich/juice-shop:v20.0.0", "digest": {"sha256": $dig}}],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": $bom[0]
}' > labs/lab4/juice-shop-attestation.json
```

First lines: `_type` `https://in-toto.io/Statement/v0.1`, subject digest `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`, `predicateType` `https://cyclonedx.org/bom`.

Digest (not tag) because tags move; the attestation claims “this exact bytes of the image had this SBOM.” It does **not** prove the image is free of vulns, that the SBOM is complete, or that runtime matches the build — only that someone asserts this inventory for that digest.
