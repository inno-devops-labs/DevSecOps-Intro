# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps program targeting OWASP Juice Shop — a deliberately vulnerable Node.js e-commerce app — across 10 weeks of hands-on labs, integrating security at every stage of the software delivery lifecycle. The toolchain covers 7+ scanners (Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Falco) with 385 findings centralized in DefectDojo, Cosign-signed container images, and Conftest policy gates at deploy time — everything running on an SLA matrix with explicit 24h/7d/30d/90d remediation windows.

## (0:30–2:00) Layers

The program follows a defense-in-depth model across five layers. Starting pre-commit, gitleaks catches secrets before they enter the repo, and every commit is SSH-signed for non-repudiation. At build time, Syft generates an SBOM, Grype and Trivy scan for known vulnerabilities, and Semgrep runs SAST rules against the codebase — findings go straight to DefectDojo. Pre-deploy, Checkov and KICS validate infrastructure-as-code, Cosign signs every container image, and Conftest policies gate Kubernetes manifests — blocking anything without runAsNonRoot, dropped capabilities, or resource limits. At runtime, Falco with modern eBPF detects anomalous behavior like cryptominer connections or unauthorized filesystem writes. The program layer ties it all together: DefectDojo aggregates every finding, deduplicates across tools, and applies the SLA matrix so I know which 17 Criticals need attention in 24 hours versus the 168 Mediums I can triage this sprint.

## (2:00–3:00) Findings + Closures

This initial import surfaced 385 active findings — 17 Critical, 164 High, 168 Medium, 27 Low. I risk-accepted three items with explicit expiry dates: CVE-2024-21626 in runc because this is a single-container lab environment with no multi-tenant isolation risk (expiring 2026-08-09), a hardcoded JWT secret in a Semgrep-detected test fixture that never reaches production (expiring 2026-09-01), and an S3 public ACL flagged by Checkov in lab IaC with no real AWS credentials (expiring 2026-10-08). The strongest correlated finding came from a cross-tool dedup — CVE-2024-21626 was caught by Trivy, Grype, AND Trivy image scan, giving me three pieces of evidence for one DefectDojo finding. The fix path is clear: bump the runc base image, verify with a re-scan, and close in under 7 days per SLA.

## (3:00–4:00) Metrics

This is Day 0 of the program, so the honest metrics story is: MTTD and MTTR are not yet measurable — all 385 findings were imported in one session, establishing the baseline. Vuln-age median is ~0 days today; the clock starts now. SLA compliance sits at 100%, but that's a fragile number — 17 Critical findings expire in 24 hours (by 2026-07-11), and if I don't triage them before then, compliance drops. The backlog trend is +385 versus a zero baseline — this first import IS the baseline for all future quarters. Compared to DORA Elite performers who close Criticals in under 1 hour, this program is just starting its measurement journey, which is exactly what Lecture 9 slide 13 predicts for a new program.

## (4:00–4:30) Next Steps

If I had another quarter, I'd ship automated assignment of Critical findings to the security on-call within 1 hour of detection and integrate Falco runtime alerts as a custom DefectDojo parser so runtime findings flow into the same SLA-tracked queue. This moves Defect Management from SAMM Level 1 (ad-hoc, baseline established) toward Level 2 (defined, repeatable SLAs with automated routing) — the concrete metric target is MTTR for High findings dropping from "not yet measurable" to under 7 days.

## (4:30–5:00) Q&A Anticipation

**Q1: "How would you handle a Log4Shell scenario?"**
First, I'd query the SBOM — because I generated one with Syft at build time, I can answer "do we have this?" in seconds, not weeks. The SBOM tells me exactly which services run Log4j and which version. Then I'd pull the relevant finding into DefectDojo (CVSS 10.0, EPSS ~0.97 within hours), assign it Critical SLA (24h), and route it to the owning service team via the auto-assignment pipeline I described as my next-quarter goal. The fix — bump the dependency — goes through the same CI pipeline that scans, signs, and gates before deploy. Verification re-scan closes the finding automatically. Without the SBOM, this is a quarter-long incident; with it, it's a 1-day exercise. That's exactly the Lesson of Lecture 10 slide 16.

**Q2: "Why didn't you use IAST or paid tools?"**
Honest tradeoff: this was an academic capstone built entirely on open-source tooling — Falco, DefectDojo, Grype, Trivy, Semgrep, ZAP are all CNCF/OWASP projects used in production by Fortune 500 teams. I deliberately avoided vendor lock-in because the skills transfer: if you can triage in DefectDojo, you can triage in Snyk or Wiz; if you can write Falco rules, you understand eBPF detection regardless of the commercial wrapper. IAST would add runtime-instrumented coverage I don't currently have, and in a production program I'd evaluate Contrast or Aqua for that layer — but the program's fundamentals (SBOM-driven discovery, cross-tool dedup, SLA-enforced remediation) work identically regardless of the scanner brand.
