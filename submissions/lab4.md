# Lab 4 – SBOM Generation and Vulnerability Scanning

## Environment

Tools used:

* Syft 1.42.4
* Grype 0.111.0
* Trivy 0.70.0
* jq 1.7.1

Container analyzed:

```text
bkimminich/juice-shop:v20.0.0
```

---

## SBOM Generation

Generated two SBOM formats:

### CycloneDX

```bash
syft bkimminich/juice-shop:v20.0.0 \
-o cyclonedx-json=labs/lab4/juice-shop.cdx.json
```

Components:

* 3068 components

### SPDX

```bash
syft bkimminich/juice-shop:v20.0.0 \
-o spdx-json=labs/lab4/juice-shop.spdx.json
```

Packages:

* 909 packages

---

## Vulnerability Scanning with Grype

```bash
grype sbom:labs/lab4/juice-shop.cdx.json \
-o json \
--file labs/lab4/grype-from-sbom.json
```

Results:

* Critical: 7
* High: 51
* Medium: 35
* Low: 4
* Negligible: 7

Total findings: 104

Examples:

| Package      | Version | Vulnerability       | Severity | Fixed Version |
| ------------ | ------- | ------------------- | -------- | ------------- |
| jsonwebtoken | 0.1.0   | GHSA-c7hr-j4mj-j2w6 | Critical | 4.2.2         |
| lodash       | 2.4.2   | GHSA-jf85-cpcp-j695 | Critical | 4.17.12       |
| crypto-js    | 3.3.0   | GHSA-xwcq-pm8m-c4vf | Critical | 4.2.0         |
| lodash.set   | 4.3.2   | GHSA-p6mc-m468-83gw | High     | N/A           |
| moment       | 2.0.0   | GHSA-8hfj-j24r-96c4 | High     | 2.29.2        |

---

## Vulnerability Scanning with Trivy

```bash
trivy image bkimminich/juice-shop:v20.0.0
```

Trivy findings were saved in:

* labs/lab4/trivy-report.json
* labs/lab4/trivy-report.txt

---

## Conclusion

The Juice Shop image contains numerous vulnerable dependencies, including several critical issues. Most findings have available fixes and demonstrate why SBOM generation and automated vulnerability scanning are essential components of the software supply chain security process.

