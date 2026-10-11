# 5-Minute DevSecOps Program Walkthrough — OWASP Juice Shop

## (0:00–0:30) Context

I built an end-to-end DevSecOps program around **OWASP Juice Shop** — a deliberately vulnerable
Node.js app — as the target, so I could exercise every layer of the pipeline against something
that actually bites back. The stack is all open-source: **Syft** for SBOMs, **Grype** and
**Trivy** for SCA, **Semgrep** for SAST, **OWASP ZAP** for DAST, **Checkov** and **KICS** for
IaC, **Cosign** for supply-chain signing, **Falco** for runtime, and **DefectDojo** as the
governance brain that ties it all together with an SLA matrix.

## (0:30–2:00) Layers

I think of it as five gates, each cheap and each catching a different class of bug:

- **Pre-commit** — `gitleaks` blocks secrets before they ever land, and commits are
  **SSH-signed**, so provenance starts at the keyboard.
- **Build** — every push generates a **Syft SBOM**, then **Grype** does SCA against it and
  **Semgrep** runs SAST on the source. Two independent lenses on the same code.
- **Pre-deploy** — **Checkov** lints the Terraform and **KICS** lints the Ansible and Pulumi, so
  misconfigurations die before they provision anything. The image is **Cosign-signed**, and a
  **Conftest/OPA** gate refuses to deploy anything unsigned.
- **Runtime** — **Falco** watches syscalls over eBPF and fires on things static analysis can't
  see: a shell spawning inside a container, an unexpected outbound connection.
- **Program** — everything above lands in **DefectDojo**, which dedups across tools, applies the
  **SLA matrix** — 24 h / 7 d / 30 d / 90 d for Critical / High / Medium / Low — and gives me
  MTTR, vuln-age, and SLA-compliance as living numbers instead of a pile of JSON.

## (2:00–3:00) Findings + Closures

The headline: **716 raw findings from four SCA scanners collapsed to 389 unique** once
DefectDojo deduped them. That collapse *is* the program — it's the difference between a backlog
you can govern and one you drown in, because Grype and three Trivy contexts were all reporting
the same `node_modules` CVEs four times over.

Of those 389, we closed 47, dismissed 18 as false positives, and consciously **risk-accepted 9**
— every one with an expiry date, no exceptions. The one I'd call out: **CVE-2024-21626**, the
runc "Leaky Vessels" Critical. I accepted it with a *short* 2-week expiry because the lab runtime
is gVisor-isolated and not internet-reachable — but a Critical never gets an open-ended pass.

The finding I'm proudest of catching was a **correlated one**: a stored-XSS path that **Semgrep**
flagged as an unsanitised sink in the source *and* **ZAP** independently confirmed as reflected
in the running app. Two tools, two angles, one real bug — the fix was tightening the
`sanitize-html` allow-list rather than trusting client-side escaping.

## (3:00–4:00) Metrics

- **MTTR: 6.8 days mean, 4 median.** Criticals close in **1.9 days**; the mean is dragged up by
  low-priority Mediums at 9 days. For context, DORA Elite performers restore in under a day — so
  on Criticals we're in range, on the long tail we're not, and I can *see* exactly where.
- **Vuln-age median: 34 days** across the open backlog.
- **SLA compliance: 61 % overall** — and I'll be honest about the weak spot: **Critical is 24 %**,
  because a 24-hour clock against a batch-imported backlog is brutal. That number is a feature,
  not an embarrassment: it tells me precisely where to invest.
- **Backlog trend: falling, −74** since import — triage is outrunning intake.

## (4:00–4:30) Next Steps

If I had another quarter, I'd ship a **custom DefectDojo parser for Falco runtime alerts**, so
eBPF detections enter the same SLA clock as build-time findings instead of living in a log file.
On the OWASP SAMM ladder that moves **Defect Management from Maturity 1 to 2** — runtime and
build-time defects sharing one metrics-driven workflow — and it directly attacks that 24 %
Critical-SLA gap by starting the clock the moment Falco fires.

## (4:30–5:00) Q&A Anticipation

**Q: "How would you handle a Log4Shell-style scenario?"**
I lean on the **SBOM**. Because Syft produces a component inventory on every build and it's
stored, a new zero-day becomes a *lookup*, not a fire drill: I query the SBOM corpus for the
affected package and version range, DefectDojo tells me every product and image that ships it,
and the SLA matrix auto-prioritises the Criticals. Detection time drops from "audit everything"
to minutes — the whole point of generating SBOMs *before* you need them.

**Q: "Why no IAST or paid tools?"**
Honest tradeoff: this was a learning program on a budget, and the open-source stack already
covers SAST + DAST + SCA + IaC + runtime. IAST would give me better *reachability* data — it'd
have told me automatically that half my risk-accepted lodash CVEs aren't reachable, instead of
me reasoning it manually. So it's a real gap, not a claim that free tools are equivalent. If
this were production with budget, IAST plus a reachability-aware SCA (to cut the SCA false-positive
tail) is the first paid line item I'd argue for — and I can point at the MTTR long tail as the
business case.
