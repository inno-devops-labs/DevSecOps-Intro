# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: 1504963 bytes
- `juice-shop.spdx.json` component count: 911

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 105 |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-87vv-r9j6-g5qv | Medium | moment | 2.0.0 | 2.11.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | none |
| GHSA-446m-mv8f-q348 | High | moment | 2.0.0 | 2.19.3 |
| GHSA-4xc9-xhrj-v574 | High | lodash | 2.4.2 | 4.17.11 |
| GHSA-fvqr-27wr-82fm | Medium | lodash | 2.4.2 | 4.17.5 |

### Fix-available rate
Out of the top 10 CVEs, 9 have a fix available (only GHSA-p6mc-m468-83gw for lodash.set has no fix). This means the majority of the highest-severity vulnerabilities in this image can be addressed by simply updating the affected packages. According to Lecture 4's triage shortcut, the immediate priority should be to patch the 7 Critical and 52 High vulnerabilities that have available fixes, as they present the highest risk with the lowest effort.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 52 | 43 | -9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 105 | 109 | +4 |

### Why the difference?
1. **System-level packages (libc6)** — Trivy found many CVEs in system packages like libc6 that Grype missed. This is because Grype focuses on application-level dependencies (Node.js packages), while Trivy scans both application and OS-level packages. The two tools use different vulnerability databases and different scopes.

2. **Different CVEs in Node packages** — Grype found vulnerabilities like GHSA-c7hr-j4mj-j2w6 in jsonwebtoken that Trivy did not report. This likely due to different detection rules and vulnerability matching logic between the two databases.

### When would you pick each?
- **Syft+Grype (decoupled)** — When you need SBOM as an artifact for signing and want to re-scan the same SBOM multiple times as new CVEs are discovered without re-downloading the image. The decoupled model also allows to keep an immutable inventory of what was in image at build time.

- **Trivy (all-in-one)** — When you need a fast, simple CI step that covers not only CVEs but also IaC misconfigurations, secrets, and other security issues in a single tool. It's more convenient when you want a broad security scan with one command and don't need SBOM as a separate artifact.