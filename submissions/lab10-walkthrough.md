# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
I built an end-to-end DevSecOps program around OWASP Juice Shop as the target application. Over the term I
layered nine controls — from pre-commit secret scanning through runtime detection — and rolled every
scanner's output into a single DefectDojo instance so the whole thing reads as one managed program, not
nine disconnected tool runs. Everything is scanned, the release image is signed, and its SBOM is attested.

## (0:30–2:00) Layers
I think of it as five stages. **Pre-commit:** gitleaks blocks secrets and every commit is SSH-signed, so
provenance starts at the keyboard. **Build:** Syft generates a CycloneDX SBOM, Grype does SCA against that
SBOM, and Semgrep runs SAST on the source. **Pre-deploy:** Checkov and KICS scan the Terraform, Ansible and
Pulumi IaC; Trivy scans the container image; then Cosign signs the image by digest and attaches the SBOM as
an in-toto attestation, and a Conftest/Rego gate blocks any Kubernetes manifest that isn't hardened —
non-root, read-only root FS, dropped capabilities. **Runtime:** Falco with eBPF watches syscalls and fires
on a shell in a container, a read of /etc/shadow, or a write to /tmp. **Program:** DefectDojo aggregates
all of it, deduplicates, and puts an SLA on every finding. Each layer catches a different class, and each
feeds the same backlog.

## (2:00–3:00) Findings + Closures
This term I closed six Critical findings — the fixable ones: lodash prototype pollution, crypto-js,
jsonwebtoken, an OpenSSL CVE. I risk-accepted two Criticals I *can't* fix cleanly — `marsdb`, which is an
abandoned package, and a `libc6` CVE with no patched Debian build yet — both with a hard expiry date so
they can't quietly become permanent. My strongest correlated finding is the lodash CVE-2019-10744: Grype
and Trivy both caught it, and DefectDojo showed me it was the same issue across two scanners — which is
exactly the cross-tool confirmation you want before you spend effort on a fix.

## (3:00–4:00) Metrics
The numbers: mean time to remediate on what I closed is about 20 days. DORA's Elite tier is under a day, so
this teaching backlog is deliberately above that — the honest read is that these findings sat until a
batch closure. Median open vuln-age is 21 days, and SLA compliance is 59.9% against a matrix of 24 hours
for Critical, 7 days for High, 30 for Medium, 90 for Low. That 60% is the most useful number in the whole
program: it tells me precisely where the process is slow — the Critical and High SCA findings whose windows
lapsed in the backlog.

## (4:00–4:30) Next Steps
If I had another quarter I'd wire the scanners into CI so findings auto-create on every pull request
instead of a term-end batch — that alone would collapse detection time and lift SLA compliance. That maps
to the OWASP SAMM Defect-Management practice moving from Level 1 to Level 2: from ad-hoc scanning to a
managed, continuous defect pipeline.

## (4:30–5:00) Q&A Anticipation
**"How would you handle a Log4Shell scenario?"** — I don't re-scan every image under pressure. I query the
signed SBOM I already attested with Cosign: "which artifacts contain this component, at what version?" The
digest binding means the SBOM provably matches the running image, so I get an accurate blast radius in
seconds, then prioritize by SLA. That's the whole reason the SBOM is a signed deliverable, not a throwaway.

**"Why didn't you use IAST or paid tools?"** — Honest tradeoff: the open-source stack (Grype, Trivy,
Semgrep, Checkov, KICS, Falco, DefectDojo) covers SCA, SAST, IaC, and runtime with no license cost, which
is the right call for demonstrating the *program discipline*. IAST and commercial SAST buy lower
false-positive rates and deeper dataflow — I'd add them once the process is mature and the noise from
free tools is the actual bottleneck, not before.
