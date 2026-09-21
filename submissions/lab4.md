# Lab 4

## Task 1

```sh
 ✔ Loaded image                                                                                                                                                  bkimminich/juice-shop:v20.0.0
 ✔ Parsed image                                                                                                        sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
 ✔ Cataloged contents                                                                                                         eb837864866a371b897d36bd675da1f9f3a84389cb2911555987163553d3cbd6
   ├── ✔ Packages                        [908 packages]  
   ├── ✔ Executables                     [289 executables]  
   ├── ✔ File metadata                   [2,160 locations]  
 ✔ Loaded image                                                                                                                                                  bkimminich/juice-shop:v20.0.0
 ✔ Parsed image                                                                                                        sha256:99779f57113bd47312e8fe7b264ff402ee41da76ddda7f2fc842a92ad51827ce
 ✔ Cataloged contents                                                                                                         eb837864866a371b897d36bd675da1f9f3a84389cb2911555987163553d3cbd6
   ├── ✔ Packages                        [908 packages]  
   ├── ✔ Executables                     [289 executables]  
   ├── ✔ File metadata                   [2,160 locations]  
3069
909
1.7
```

Component count, CDX: 3069, CPDX: 909. They disagree because they count different inventory units. CycloneDX models a broad component graph, including many transitive npm dependencies and other artifacts as separate, while SPDX's package list is package-oriented.




Grype Verity table:
| severity  | count |
|--------------|----|
| critical     | 14 |
| High         | 85 |
| Medium       | 65 |
| Low          | 12 |
| Negligible   | 7  |
| Total        | 182 |


```sh
Critical        GHSA-c7hr-j4mj-j2w6     jsonwebtoken@0.1.0      fix: 4.2.2
Critical        GHSA-c7hr-j4mj-j2w6     jsonwebtoken@0.4.0      fix: 4.2.2
Critical        GHSA-jf85-cpcp-j695     lodash@2.4.2    fix: 4.17.12
Critical        CVE-2026-63073  libssl3t64@3.5.5-1~deb13u2      fix: 3.5.7-1~deb13u2
Critical        GHSA-mp2f-45pm-3cg9     decompress@4.2.1        fix: 
Critical        GHSA-xwcq-pm8m-c4vf     crypto-js@3.3.0 fix: 4.2.0
Critical        CVE-2026-34182  libssl3t64@3.5.5-1~deb13u2      fix: 3.5.6-1~deb13u2
Critical        GHSA-23hp-3jrh-7fpw     tar@4.4.19      fix: 7.5.19
Critical        GHSA-23hp-3jrh-7fpw     tar@6.2.1       fix: 7.5.19
Critical        GHSA-23hp-3jrh-7fpw     tar@7.5.15      fix: 7.5.19
```

9 of the top 10 have a fix available. I would patch the fixable Critical findings first: update `jsonwebtoken`, `lodash`, `crypto-js`, `tar`, and Debian `libssl3t64` before spending time on the no-fix `decompress` finding.


## Task 2

Comparison:

| Verity  | Grype | Trivy | delta |
|--------------|----|------|------|
| Critical     | 14 |10  | 4 |
| High         | 85 |64  | 21 |
| Medium       | 65 |68  |  -3 |
| Low          | 12 |31  | -19 |
| Negligible   | 7  |0   | 7 |
| Total        |182 |173 | -9 |


Unique advisory IDs: Grype found 156, Trivy found 145. 52 IDs appear in both lists, 104 appear only in Grype, and 93 appear only in Trivy.



Grype-only: `CVE-2026-48617` on `node@24.15.0` as a binary component. The likely cause is package ecosystem and matching coverage: Grype detects the embedded Node runtime binary from the SBOM and matches it to Node advisories, while Trivy's image result did not report `node` as a vulnerable package.


Trivy-only: `CVE-2015-9235` on `jsonwebtoken@0.1.0` and `jsonwebtoken@0.4.0`. Grype does flag vulnerable `jsonwebtoken`, but under GHSA identifiers such as `GHSA-c7hr-j4mj-j2w6`; this is best explained by different advisory sources and ID mapping, where Trivy reports the CVE and Grype prefers the GitHub Security Advisory ID.


The decoupled Syft plus Grype approach is worth the extra moving part when the SBOM is itself a deliverable: the same inventory can be rescanned later without pulling the image, imported into later vulnerability-management work, and signed in Lab 8 as a CycloneDX attestation. Trivy is the better answer for a quick CI gate when I need one command that catalogs and scans the image immediately. The tradeoff is that Trivy's JSON result is a scan report, while the CycloneDX SBOM is reusable supply-chain evidence that can be attached to the image digest.

