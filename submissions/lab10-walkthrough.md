# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around OWASP Juice Shop as the target app, covering the
whole path from commit to runtime. Across the pipeline I run secret scanning, SBOM + SCA, SAST,
DAST, IaC scanning, container + K8s hardening, image signing with attestations, and runtime
detection — and I aggregate every finding into DefectDojo so it's one triage queue, not nine
dashboards.

## (0:30–2:00) Layers
I think of it as four gates, each catching a different failure class:
- **Pre-commit:** gitleaks blocks secrets before they're committed, and commits are SSH-signed.
- **Build:** Syft generates a CycloneDX SBOM, Grype and Trivy scan it for CVEs, Semgrep runs SAST.
- **Pre-deploy:** Checkov and KICS scan the IaC (Terraform, Ansible, Pulumi); the image is hardened
  to Pod Security Standards `restricted`, signed with Cosign, and Conftest/Rego policies gate the
  K8s manifests in CI — runAsNonRoot, drop ALL capabilities, no `:latest`, resource limits.
- **Runtime:** Falco with modern eBPF watches syscalls — I wrote custom rules for writes to /tmp
  in a container and for cryptominer-style outbound connections.
The key idea is defense in depth: shift-left finds what it can, runtime catches what slipped past.

## (2:00–3:00) Findings + Closures
After importing everything into DefectDojo, 456 raw findings deduplicated to 310 unique — 11
Critical and 120 High active. I remediated three Critical dependency issues this period
(jsonwebtoken and lodash prototype-pollution CVEs). I risk-accepted two low-severity findings — a
`cookie` and a Node base-image CVE — both with a hard expiry of 2026-10-10, because a risk
acceptance with no re-review date is how programs quietly rot. The cleanest cross-tool correlation
was CVE-2023-46233 in crypto-js: Trivy flagged it in the SBOM, the image, and the running cluster,
and DefectDojo collapsed all three into one finding.

## (3:00–4:00) Metrics
This import is my baseline, so I'm honest that MTTR and vuln-age are point-in-time near-zero right
now — the value is the workflow being in place, not the number yet. What I *can* report: 310
unique findings, an 11 Critical / 120 High backlog, and 100% SLA compliance so far against a matrix
of 24h for Critical, 7 days High, 30 Medium, 90 Low. Against DORA Elite (MTTR under a day), the
Criticals are the ones on the tightest clock. Once this runs across a few sprints, MTTR and
vuln-age median become the real story.

## (4:00–4:30) Next Steps
If I had another quarter, I'd mature the OWASP SAMM **Defect Management** practice from Level 1 to
2: configure cross-parser deduplication so Grype and Trivy collapse on shared CVEs (not just
Trivy-on-Trivy), and wire Falco runtime alerts in as a finding source. That gets me one finding per
real vulnerability and detect-time coverage in the same queue as build-time.

## (4:30–5:00) Q&A Anticipation
**"How would you handle a Log4Shell scenario?"** — I'd query the signed SBOM attestation instead of
re-scanning the fleet: "does any image attest to depending on the vulnerable package + version?" is
a `jq` query against an already-verified document, so I get an answer in minutes. Then it's
finding → owner → fix → verify through the same DefectDojo workflow, prioritised by the Critical
24h SLA.

**"Why no IAST or paid tools?"** — Honest tradeoff: the open-source stack (Grype, Trivy, Semgrep,
Checkov, KICS, Falco, Cosign, DefectDojo) covers SCA, SAST, IaC, container, supply-chain, and
runtime for zero license cost, which is the right call for a learning project and most early-stage
teams. IAST and commercial DAST buy you lower false-positive rates and deeper reachability
analysis; I'd add them once the program is mature enough that triage time, not tooling cost, is the
bottleneck.
