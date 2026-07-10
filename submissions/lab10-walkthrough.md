# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built a DevSecOps program around OWASP Juice Shop as the target application, running it
through 9 labs across the full pipeline — secure git, SBOM/SCA, SAST/DAST, IaC scanning,
container hardening, supply-chain signing, runtime detection, and policy-as-code — with
DefectDojo aggregating everything into one governed backlog. Everything you'll hear numbers
for was scanned, signed, or verified by an actual tool run, not estimated.

## (0:30–2:00) Layers
Think of it as five layers stacked from commit to runtime:
- **Pre-commit:** SSH-signed commits plus gitleaks via pre-commit hooks catch secrets
  before they ever reach the remote.
- **Build:** Syft generates an SBOM (CycloneDX + SPDX), Grype and Trivy run SCA against it,
  and Semgrep does SAST on the application source — three independent lenses on the same
  codebase.
- **Pre-deploy:** Checkov scans the Terraform IaC, Conftest gates Kubernetes manifests
  against Rego hardening policies before they can even be applied, and Cosign signs the
  final container image so provenance is cryptographically verifiable downstream.
- **Runtime:** Falco with modern eBPF watches the running container — I've got custom rules
  for drift detection (unexpected `/tmp` writes) and a cryptominer-pattern rule layered on
  top of the baseline ruleset.
- **Program:** DefectDojo pulls every scan into one product, applies an SLA matrix by
  severity, and turns nine separate tool outputs into one number: 422 active findings,
  98.3% within SLA.

## (2:00–3:00) Findings + Closures
This run is a fresh capstone import rather than a full remediation cycle, so instead of
closures, the interesting story is agreement: the same finding — a High-severity OpenSSL
CVE in the base image, CVE-2026-45447 — showed up independently in Grype, two separate
Trivy scans, and the Kubernetes-layer Trivy scan. Four tools, one real vulnerability,
before I'd even started triaging. That's the kind of cross-validation that makes we trust
a Critical/High call over a single scanner's opinion. The strongest correlated finding
outside SCA was a SQL injection path caught by both Semgrep (static, pointing at the exact
line in `routes/search.ts`) and ZAP (dynamic, hitting the live `/rest/products/search`
endpoint) back in Lab 5 — static and dynamic testing agreeing on the same root cause is
about as high-confidence as findings get.

## (3:00–4:00) Metrics
Because this is a first import rather than a mature running program, MTTR is currently
undefined — nothing's been triaged to closure yet, so instead of over-claiming a number I
don't have, I'm reporting it honestly as the starting line, not a result. What I do have:
98.3% SLA compliance on day one (415 of 422 findings still inside their SLA window), a
severity mix of 22 Critical / 199 High / 168 Medium / 26 Low / 7 Info, and zero backlog
history simply because this report *is* the baseline. Compared to DORA Elite MTTR
(under 1 day), the honest answer is "not yet measurable" — and I'd rather say that than
paper over it with a made-up number.

## (4:00–4:30) Next Steps
If I had another quarter, I'd triage the 22 Critical findings inside their 1-day SLA and
close the top 20% of Highs inside 7 days, so MTTR and vuln-age stop being structural zeros
and become real trend lines. That maps directly to maturing the SAMM Defect Management
practice — right now the program can detect and aggregate, but it hasn't closed the loop
on remediation tracking yet.

## (4:30–5:00) Q&A Anticipation

**"How would you handle a Log4Shell scenario?"**
Because every build produces an SBOM via Syft, I wouldn't be grepping through servers
wondering where log4j lives — I'd query the SBOM inventory in DefectDojo/Grype for the
exact package+version across every scanned image in minutes, patch the confirmed
instances first, and use the SLA matrix's Critical 1-day window to force that turnaround
instead of letting it drift into a multi-week fire drill.

**"Why didn't you use IAST/paid tools?"**
Honest tradeoff: this was a learning-focused, budget-zero program built entirely on OSS
(Semgrep, ZAP, Trivy, Grype, Falco, DefectDojo Community). IAST would give richer
runtime-correlated findings than SAST+DAST run separately, but it also means licensing
cost and usually an app-server agent — for a program this size, the SAST+DAST+SCA+runtime
combination already gets meaningful cross-validation (see the CVE-2026-45447 and SQL
injection examples above) at zero tooling cost, which is the right tradeoff until the
program's scale actually justifies the IAST spend.
