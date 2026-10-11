# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps programme around OWASP Juice Shop — an intentionally vulnerable Node.js app —
as the target, running across 12 labs covering the full software-delivery lifecycle from commit to
runtime. The programme spans 9 automated scan tools, produces a signed SBOM, enforces runtime
detection with Falco eBPF, and aggregates 391 findings in DefectDojo with a 24h/7d/30d/90d SLA matrix.

## (0:30–2:00) Layers

The programme runs four defensive layers:

**Pre-commit:** Gitleaks scans for secrets before any push; all commits are SSH-signed. If a
developer accidentally commits an API key, it's caught before it ever reaches the repo history.
We demonstrated history rewriting with `git filter-repo` when a secret did slip through in an
earlier exercise.

**Build pipeline (CI):** Syft generates a CycloneDX SBOM from the source tree. Grype and Trivy
scan that SBOM for known CVEs. Semgrep runs SAST rules on the JavaScript source. Checkov and KICS
gate Terraform and Ansible IaC before it touches infrastructure. Total: 5 scanners, all producing
structured JSON fed to DefectDojo.

**Pre-deploy gate:** Cosign signs the container image digest after build and verifies the signature
before deploy. Conftest/Rego policies enforce Kubernetes manifest hardening (runAsNonRoot,
allowPrivilegeEscalation=false, drop ALL capabilities, memory limits, no :latest tags). A failing
policy blocks the deployment — admission-time and CI-time both run the same policies for
defence-in-depth.

**Runtime:** Falco 0.43.1 runs on the host with modern eBPF. Custom rules detect writes to /tmp
by containers, terminal shells spawned inside containers, and egress to known cryptominer pool
ports. On kernel 7.0.12+kali, all rules fire within seconds of trigger — verified with four JSON
alert captures.

**Programme layer:** DefectDojo v3.1.0 aggregates all scanner outputs. Product: Juice Shop.
Engagement: Labs 4-9 Capstone. SLA matrix: Critical 24h, High 7d, Medium 30d, Low 90d.

## (2:00–3:00) Findings + Closures

After import across all 7 scan types we have 391 active findings:
17 Critical, 163 High, 170 Medium, 29 Low, 12 Info.

The programme hasn't closed findings yet — this is a fresh semester baseline. But the triage
is clear: the 17 Criticals are all in either the base OS image (libc6, libssl3) or ancient
JavaScript packages (crypto-js 3.3.0, jsonwebtoken 0.1.0). The fix is a base-image rebuild
and a `package.json` upgrade — one change that closes 8+ Critical findings simultaneously.

The strongest correlated finding is **CVE-2023-46233** (crypto-js prototype pollution) — caught
independently by both Trivy SCA scanning the SBOM and Trivy scanning the built container image.
Two scanners, same CVE, one fix. This is exactly why you run both SCA and image scanning: the
SBOM gives you early signal, the image scan confirms it survived the build.

No Risk Accepted items exist. Per programme policy any risk accept must carry an explicit expiry
date and written business justification — the "silent programme killer" anti-pattern is a
no-expiry risk accept that drifts into permanent.

## (3:00–4:00) Metrics

- **MTTD:** Near-zero — findings surface at PR time via the pipeline gates, before code merges.
- **MTTR:** Not yet measured (Day 0 baseline). Target: Critical < 1 day, High < 7 days. DORA
  Elite organisations close Critical vulns in under 1 hour; we're using 24h as a realistic
  semester target.
- **Vuln-age median:** 0 days on import day. Will grow if findings are not remediated — the SLA
  dashboard turns red at 24h for Criticals.
- **SLA compliance:** 100% today. The 17 Criticals expire 2026-07-10; the programme's first real
  test is whether the base-image rebuild lands before that deadline.
- **Backlog trend:** +391 (initial). Success looks like a falling backlog curve after the image
  rebuild and package upgrades are deployed.

## (4:00–4:30) Next Steps

If I had another quarter, I'd ship **Falco-to-DefectDojo live ingestion** — writing a custom
parser that takes Falco's JSON alert stream and creates DefectDojo findings in real time, moving
MTTD from "scan-at-PR" to "seconds after exploit attempt." This advances the programme from
OWASP SAMM Defect Management Level 0 to Level 1 (formal tracking) and closes the gap between
static analysis and runtime telemetry in one step.

## (4:30–5:00) Q&A Anticipation

**Q1: "How would you handle a Log4Shell (CVE-2021-44228) scenario?"**

The SBOM is the first responder. Because we generate a CycloneDX SBOM on every build with Syft,
we can query `grype sbom:juice-shop.cdx.json --add-cpes-if-none -o json | jq '.matches[] |
select(.vulnerability.id=="CVE-2021-44228")'` within minutes of a CVE dropping. If the package
is present we know exactly which image version and which commit introduced it. The DefectDojo
engagement gives us a single ticket to track remediation across all affected services. The image
signing step means we can also pull-request-gate: any image that Grype flags for Log4Shell fails
the build pipeline before it reaches staging.

**Q2: "Why didn't you use IAST or paid tools like Snyk/Veracode?"**

Honest tradeoff: IAST (runtime instrumentation) has lower false-positive rates on SAST findings
but requires the application to be executing under instrumented traffic — it adds an agent and
needs integration test suites to get good coverage. For a course environment with no production
traffic, IAST would have given us lower signal than Semgrep+ZAP combined. Paid tools like Snyk
add better reachability analysis (they can tell you if a vulnerable code path is actually called)
but their value over Grype+Trivy for a Node.js monolith with a public SBOM is marginal. In a
production team I'd evaluate Snyk's reachability data for Java/JVM workloads where dependency
trees are deeply transitive — that's where false positives dominate and reachability matters most.
