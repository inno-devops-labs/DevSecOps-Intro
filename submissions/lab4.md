# Lab 4 — SBOM Generation & Software Composition Analysis on Juice Shop

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: 1,43 MiB
- `juice-shop.spdx.json` package count: 911

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

| CVE                 | Severity | Package      | Installed | Fix     |
| ------------------- | -------- | ------------ | --------- | ------- |
| GHSA-35jh-r3h4-6jhm | High     | lodash       | 2.4.2     | 4.17.21 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0     | 4.2.2   |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0     | 4.2.2   |
| GHSA-87vv-r9j6-g5qv | Medium   | moment       | 2.0.0     | 2.11.2  |
| GHSA-jf85-cpcp-j695 | Critical | lodash       | 2.4.2     | 4.17.12 |
| GHSA-8hfj-j24r-96c4 | High     | moment       | 2.0.0     | 2.29.2  |
| GHSA-p6mc-m468-83gw | High     | lodash.set   | 4.3.2     | —       |
| GHSA-446m-mv8f-q348 | High     | moment       | 2.0.0     | 2.19.3  |
| GHSA-4xc9-xhrj-v574 | High     | lodash       | 2.4.2     | 4.17.11 |
| GHSA-fvqr-27wr-82fm | Medium   | lodash       | 2.4.2     | 4.17.5  |

### Fix-available rate

Out of the top 10 CVEs, 9 have a fix available. According to Lecture 4, fixable vulnerabilities with severity High or Critical should be patched first. Since most of the identified vulnerabilities meet both criteria, the project's patch cadence should prioritize dependency updates before investigating lower-severity or non-fixable findings.


## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 42 | -9 |
| Medium | 35 | 22 | -13 |
| Low | 4 | 39 | 35 |
| **Total** | 97 (excluding "Negligible") | 108 | 11 |

### Why the difference?

**1. CVE-2024-47764**

* Found by: **Trivy**
* Missed by: **Grype**
* Likely reason: Trivy and Grype use different vulnerability databases and update schedules. Trivy may have incorporated this advisory earlier or matched it through a different package metadata source, while Grype's matching logic did not associate the vulnerability with the SBOM component.

**2. GHSA-35jh-r3h4-6jhm**

* Found by: **Grype**
* Missed by: **Trivy**
* Likely reason: Grype includes GitHub Security Advisories (GHSA) directly in its matching process, whereas Trivy may prioritize CVE records or use different package-matching rules. As a result, some GHSA-only findings appear in Grype but not in Trivy.

### When would you pick each?

**Syft + Grype (decoupled model)**

> I would choose Syft + Grype when I need a reusable SBOM that can be generated once and scanned multiple times. The decoupled model is particularly useful for supply-chain security because the SBOM can later be signed, stored as an attestation, and reused in verification workflows. This aligns with the SBOM-as-an-attestation approach discussed in Lecture 4 and used again in Lab 8.

**Trivy (all-in-one model)**

> I would choose Trivy when I want a simple security scan integrated directly into a CI/CD pipeline. Trivy combines vulnerability scanning with checks for secrets, infrastructure-as-code issues, and misconfigurations, reducing the number of tools that need to be maintained. Its all-in-one approach provides broader coverage and a simpler developer experience.


## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: `1.5`
- `bomFormat`: `CycloneDX`

### Image digest captured
```
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Attestation predicate
Paste first 30 lines of `labs/lab4/juice-shop-attestation.json` here:

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
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {"$schema":"http://cyclonedx.org/schema/bom-1.5.schema.json","bomFormat":"CycloneDX","specVersion":"1.5","serialNumber":"urn:uuid:7f2dd659-90d2-45c6-8d16-ffa88825fb9b","version":1,"metadata":{"timestamp":"2026-06-17T21:51:26+03:00","tools":{"components":[{"type":"application","author":"anchore","name":"syft","version":"1.45.1"}]},"component":{"bom-ref":"73ec537d8d158676","type":"container","name":"bkimminich/juice-shop","version":"v20.0.0"},"properties":[{"name":"syft:image:labels:maintainer","value":"Bjoern Kimminich <bjoern.kimminich@owasp.org>"},{"name":"syft:image:labels:org.opencontainers.image.authors","value":"Bjoern Kimminich <bjoern.kimminich@owasp.org>"},{"name":"syft:image:labels:org.opencontainers.image.created","value":"”2026-05-12T21:09:09Z”"},{"name":"syft:image:labels:org.opencontainers.image.description","value":"Probably the most modern and sophisticated insecure web application"},{"name":"syft:image:labels:org.opencontainers.image.documentation","value":"https://help.owasp-juice.shop"},{"name":"syft:image:labels:org.opencontainers.image.licenses","value":"MIT"},{"name":"syft:image:labels:org.opencontainers.image.revision","value":"f356a09"},{"name":"syft:image:labels:org.opencontainers.image.source","value":"https://github.com/juice-shop/juice-shop"},{"name":"syft:image:labels:org.opencontainers.image.title","value":"OWASP Juice Shop"},{"name":"syft:image:labels:org.opencontainers.image.url","value":"https://owasp-juice.shop"},{"name":"syft:image:labels:org.opencontainers.image.vendor","value":"Open Worldwide Application Security Project"},{"name":"syft:image:labels:org.opencontainers.image.version","value":"20.0.0"}]},"components":[{"bom-ref":"pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed","type":"library","author":"Benjamin Byholm <bbyholm@abo.fi> (https://github.com/kkoopa/), Mathias Küsel (https://github.com/mathiask88/)","name":"1to2","version":"1.0.0","description":"NAN 1 -> 2 Migration Script","licenses":[{"license":{"id":"MIT"}}],"cpe":"cpe:2.3:a:nodejs:1to2:1.0.0:*:*:*:*:*:*:*","purl":"pkg:npm/1to2@1.0.0","externalReferences":[{"url":"git://github.com/nodejs/nan.git","type":"distribution"}],"properties":[{"name":"syft:package:foundBy","value":"javascript-package-cataloger"},{"name":"syft:package:language","value":"javascript"},{"name":"syft:package:type","value":"npm"},{"name":"syft:package:metadataType","value":"javascript-npm-package"},{"name":"syft:cpe23","value":"cpe:2.3:a:1to2:1to2:1.0.0:*:*:*:*:*:*:*"},{"name":"syft:location:0:layerID","value":"sha256:f4bb7ec73c07ef3ba9e341c378fc380442a5e7d2dcc7cab9ff556e2bbca7b5ed"},{"name":"syft:location:0:path","value":"/juice-shop/node_modules/nan/tools/package.json"}]},{"bom-ref":"pkg:npm/%40adraffy/ens-normalize@1.10.1?package-id=08449108469244be","type":"library","author":"raffy.eth <raffy@me.com> (http://raffy.antistupid.com)","name":"@adraffy/ens-normalize","version":"1.10.1","description":"Ethereum Name Service
}
```

### What this enables in Lab 8

When Lab 8 runs cosign attest --type cyclonedx --predicate juice-shop-attestation.json, the signed object is the attestation that contains the CycloneDX SBOM and the image digest of the specific Juice Shop container. The signature proves that this SBOM was produced for that exact image and has not been modified after signing. This provides verifiable supply-chain provenance, allowing anyone to confirm which dependencies were present in the container image at the time the attestation was created and signed.
