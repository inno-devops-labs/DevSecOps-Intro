# 5-Minute DevSecOps Program Walkthrough — OWASP Juice Shop

## (0:00–0:30) Context
I built an end-to-end DevSecOps program using OWASP Juice Shop as the target application, covering the
whole path from commit to runtime. Across the program I signed commits, scanned dependencies, source, IaC
and images, signed and verified the container, gated Kubernetes manifests with policy-as-code, watched
runtime with eBPF, and aggregated every result into a single vulnerability-management program in DefectDojo.

## (0:30–2:00) Layers
I think of it as one pipeline with a security control at every stage.
- **Pre-commit:** gitleaks blocks hardcoded secrets before they ever land, and every commit is SSH-signed so
  GitHub shows "Verified" — that gives non-repudiation on authorship.
- **Build:** Syft generates a CycloneDX SBOM, Grype does SCA against it, and Semgrep runs SAST on the source.
  The SBOM is the keystone — I generate it once and rescan it whenever a new CVE drops, no rebuild needed.
- **Pre-deploy:** Checkov and KICS scan the Terraform/Ansible/Pulumi IaC, Cosign signs the image and I verify
  the signature, and Conftest/Rego gates the Kubernetes manifests — runAsNonRoot, drop ALL capabilities,
  no privilege escalation, digest-pinned images — so a non-compliant manifest fails in CI.
- **Runtime:** Falco with a modern-eBPF probe watches syscalls and fires on shell-in-container, sensitive-file
  reads, /tmp drift, and a custom cryptominer rule I wrote.
- **Program:** DefectDojo ingests all of it, deduplicates across tools, applies an SLA matrix, and tracks
  MTTR and vuln-age so the whole thing is measurable, not just a pile of scan output.

## (2:00–3:00) Findings + Closures
Across six tools I imported 342 findings; after enabling cross-tool deduplication, 338 stayed active and 80
collapsed as duplicates. I remediated three findings this term and formally risk-accepted one — the crypto-js
GHSA-xwcq-pm8m-c4vf Critical — with a hard expiry of 2026-10-10, because there was no non-breaking upstream
bump and I wanted it to come back for review automatically rather than disappear. The strongest correlation was
the marsdb command-injection Critical (GHSA-5mrr-rgp6-x4gr): Grype, Trivy-on-SBOM, and the Trivy image scan all
independently flagged it, and DefectDojo collapsed them into one finding — a clean demonstration of why you
aggregate instead of reading three tool outputs side by side.

## (3:00–4:00) Metrics
Honest caveat first: this was a capstone where a whole semester of reports imported in one day, so the
time-based numbers are instantaneous by construction. MTTR on the three closed findings is under a day, which
happens to match DORA Elite (<1 day) but isn't a fair benchmark here. Vuln-age median is 0 days, backlog is
+338 net-new against a zero baseline, and SLA compliance is 100% right now — but the 15 Criticals are on a
24-hour clock, so that number is designed to drop if I don't act. The point I'd make to an interviewer is that
the *instrumentation* is real even though the *values* are synthetic: the SLA matrix, dedup, and age tracking
are all live and would produce meaningful numbers against a real commit-to-close timeline.

## (4:00–4:30) Next Steps
With another quarter I'd wire finding-detection dates to CI build timestamps and ingest Falco runtime alerts
through a custom DefectDojo parser, so runtime becomes a real fourth finding source. That maps to maturing the
OWASP SAMM Defect-Management / Metrics practice one rung — moving from "we run tools" to "we measure real
High-severity MTTR and drive it under seven days."

## (4:30–5:00) Q&A Anticipation
**1. "How would you handle a Log4Shell scenario?"**
The SBOM is the answer. Because I keep a CycloneDX SBOM per image, I don't rebuild or re-scan the world — I
query the existing SBOMs for the affected coordinate (org.apache.logging.log4j) across every image, and Grype
rescans those SBOMs against the new advisory offline. That turns "which of our services are exposed?" from a
multi-day fire drill into a minutes-long query, and the signed SBOM attestation proves the inventory matches
the deployed digest, not just a tag.

**2. "Why didn't you use IAST or paid tools?"**
Honest tradeoff: the free stack (Syft/Grype/Semgrep/Trivy/Checkov/KICS/Falco/Cosign/DefectDojo) covers SCA,
SAST, DAST, IaC, supply-chain and runtime, which is the majority of the value for a portfolio program at zero
license cost. IAST and commercial DAST add real depth — runtime-informed taint tracking, fewer false positives —
but they need an instrumented running app and a budget. I'd add them once there's a production workload and a
team to triage the extra signal; for demonstrating the program design and the aggregation discipline, the open
stack is the right call.
