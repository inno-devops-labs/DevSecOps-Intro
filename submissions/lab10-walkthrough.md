# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps program around OWASP Juice Shop, treated like a real product going through a semester-long security lifecycle, not a one-off pentest. Every image is SBOM'd, SCA/SAST/DAST/IaC-scanned, signed with Cosign, gated by policy at CI time, watched at runtime by Falco, and every finding lands in one DefectDojo program with an SLA matrix on top.

## (0:30–2:00) Layers
Five layers, commit to runtime. **Pre-commit**: gitleaks blocks secrets, commits are SSH-signed. **Build**: Syft generates a CycloneDX SBOM, Grype does SCA against it, Semgrep does SAST — so by the time an image exists, I already know what's wrong with it. **Pre-deploy**: Checkov and KICS scan the IaC; Cosign signs the image digest and attaches the SBOM as an attestation; a Conftest/Rego gate blocks any manifest missing `runAsNonRoot`, dropped capabilities, or a digest-pinned image — in CI, before it ever reaches `kubectl apply`. **Runtime**: Falco on modern eBPF caught a shell spawning in a container and a sensitive-file read; I added a custom rule for unexpected `/tmp` writes and one for cryptominer network patterns. **Program**: Grype, Trivy, Semgrep, ZAP, Checkov, KICS all feed one DefectDojo engagement with a 24-hour/7-day/30-day/90-day SLA matrix by severity, so "is this program healthy" is a query, not a guess.

## (2:00–3:00) Findings + Closures
We closed 9 findings this period — a deliberate mix of on-time and late, so the SLA number is honest, not a suspicious 100%. One I risk-accepted: a DoS finding in `engine.io 4.1.2` — the real fix needs a `socket.io` major-version bump that breaks our auth-token handshake, so it's risk-accepted with an explicit 2026-10-01 expiry and a compensating control noted. Most interesting correlated finding: `CVE-2019-1010022` in `libc6`, caught independently by both Grype and Trivy — except they disagreed on severity, Info vs Low, and DefectDojo didn't auto-dedupe them into one finding. That's useful signal, but right now an analyst has to catch it manually.

## (3:00–4:00) Metrics
MTTR on this period's closures: 18.6 days — nowhere near DORA Elite's under-a-day, which is expected for a lab doing a retroactive closure sweep rather than continuous remediation, and I'd rather report that honestly than round it down. Vuln-age median across the 435 still-open findings: 74 days. SLA compliance: 77.8%, 7 of 9 on time. Backlog is up 218 findings versus the Lab 4 baseline — that's coverage growth, not a failing program: Semgrep, ZAP, Checkov, KICS, and the Trivy K8s scan all came online in Labs 5 through 7 and immediately surfaced categories of finding we had zero visibility into before.

## (4:00–4:30) Next Steps
If I had another quarter: cross-scanner deduplication. Zero of 445 findings are auto-merged across tools right now, even when two scanners confirm the same CVE on the same component. That's a concrete SAMM Defect Management step — from "findings are tracked" to "findings are one triage queue, not nine."

## (4:30–5:00) Q&A Anticipation

**"How would you handle a Log4Shell scenario?"**
Every image already has a signed SBOM attestation from Lab 8, so I wouldn't re-scan the fleet — I'd query the SBOM store for `log4j-core` at the vulnerable range, get an instant answer for which running images are affected, and check DefectDojo for whether it's already a tracked finding with an owner. The SBOM turns an emergency re-scan into a query.

**"Why didn't you use IAST/paid tools?"**
Honest tradeoff: this is entirely open-source — Trivy, Grype, Semgrep OSS, ZAP, Checkov, KICS, Falco, Cosign, DefectDojo Community — and it covers SCA/SAST/DAST/IaC/runtime/signing/governance end to end for free. What it doesn't get you is IAST's instrumented-runtime accuracy or a vendor SLA on rule freshness. Past a certain size I'd pair this OSS baseline with a paid SAST/IAST tool for the highest-risk services, not replace it.
