# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: 3.1.101

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 110 |
| 4 | Trivy Scan | trivy.json | 115 |
| 6 | Checkov Scan | results_json.json | 80 |
| 7 | Trivy Scan (image) | trivy-image.json | 51 |
| **Total raw imports** | | | 356 |
| **After dedup** | | | 152 |

### Dedup example (Lecture 10 slide 11)
- CVE/ID: CVE-2010-4756 (GHSA-35jh-r3h4-6jhm)
- Number of source tools: 2 (Anchore Grype + Trivy Scan)
- DefectDojo's single finding ID: 93

### Lab 9 – Falco runtime monitoring

Falco 0.43.1 was deployed with the modern BPF probe and custom rules.
It monitored a container named `lab9-target` (alpine:3.20). The log file
is located at `labs/lab9/logs/falco.log`.

**Detected events:**

| Timestamp (UTC)       | Priority | Rule                        | Description                                                                 |
|-----------------------|----------|-----------------------------|-----------------------------------------------------------------------------|
| 2026-07-17T08:12:23   | Notice   | Terminal shell in container | Shell spawned with attached terminal (`sh -lc echo "shell-in-container test"`) |
| 2026-07-17T08:12:33   | Warning  | Read sensitive file untrusted | `/etc/shadow` opened for reading by `cat`                                   |
| 2026-07-17T08:20:03   | Warning  | Write to /tmp by container  | Custom rule: file `/tmp/my-write.txt` created via `sh -lc echo "test" > /tmp/my-write.txt` |

**Rule counts by severity:**
- WARNING: 2
- NOTICE: 1

**Triggered rules:**
- Terminal shell in container
- Read sensitive file untrusted
- Write to /tmp by container (custom rule)

Not imported into DefectDojo. No native Falco parser exists.
Runtime findings were reviewed manually and are documented here for completeness.