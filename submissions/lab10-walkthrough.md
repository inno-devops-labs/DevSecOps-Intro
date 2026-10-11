# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps vulnerability-management program around OWASP Juice Shop, centralizing nine labs' worth of scanner output into a single DefectDojo instance. The goal wasn't just to run tools — it was to turn scattered scanner output into one owned backlog with SLA clocks attached.

Scope covered SCA (Trivy, attempted Grype), SAST (Semgrep), IaC scanning (Checkov, KICS), container scanning (Trivy image, Trivy Operator), plus DAST (ZAP) and runtime evidence (Falco) that I'll get to honestly in a minute.

## (0:30–2:00) Layers

At the build/CI level, I regenerated SCA evidence with Trivy against the SBOM from Lab 4 — Grype wasn't installed on this machine, so that source is a documented gap rather than a faked import.

At the application-security level, Semgrep gave code-level findings — 22 total, split between Medium and High. ZAP was supposed to add DAST coverage, but the DefectDojo ZAP parser rejected the JSON report outright with a "wrong format, use XML" error — I only had the JSON export from Lab 5, so that import failed and I documented it instead of forcing it through.

At the infrastructure level, Checkov and KICS covered Terraform and IaC configuration risk — 80 and 10 findings respectively, mostly around database encryption and IAM policy scope.

At the container level, Trivy image scanning added 50 findings; Trivy Operator (Kubernetes) came back with zero, which I take at face value rather than assuming it silently failed.

DefectDojo sits on top as the aggregation layer — six successful imports, 242 total findings, one duplicate test cleaned up along the way.

## (2:00–3:00) Findings + Closures

The baseline is 242 active findings: 11 Critical, 108 High, 118 Medium, 5 Low.

Nothing has been closed yet — this is a discovery baseline, not a remediation report. I didn't manufacture any "closed" or "risk-accepted" findings to make the numbers look better; open-ended risk acceptance without an expiry date is exactly the anti-pattern this program is supposed to catch.

One thing worth calling out honestly: I went looking for a clean cross-tool dedup example using the CVE the lab suggests checking, CVE-2024-21626. Instead of a dedup success story, I found 25 findings tagged with that CVE — all from Checkov, all against Terraform resources like `aws_db_instance` and `aws_iam_policy`. That CVE is actually the runc "Leaky Vessels" container-escape vulnerability, which has nothing to do with those resources. That's a parser mapping issue, not a real duplicate — and I'd rather surface a real anomaly like that than claim a dedup win I didn't actually observe. Deduplication was, in fact, off at the engagement level (`deduplication_on_engagement: false`) the whole time.

## (3:00–4:00) Metrics

242 is the backlog number that matters right now.

MTTR isn't measurable yet — zero findings mitigated. MTTD isn't measurable either, because the historical scanner files don't carry original detection timestamps; everything landed in DefectDojo in one import session, so vuln-age is 0 days at baseline by definition.

SLA exposure is explicit even without closures: 11 Critical findings are already on a 24-hour clock, 108 High on 7 days, 118 Medium on 30 days, 5 Low on 90 days.

The real takeaway isn't the finding count — it's that the backlog is now owned and time-bound instead of sitting in nine separate JSON files.

## (4:00–4:30) Next Steps

If I had another quarter, I'd fix the coverage gaps first: get Grype installed and re-run Lab 4 properly, export ZAP's XML report instead of JSON, and turn on deduplication at the product level before re-importing so the finding count actually reflects unique issues.

That maps to OWASP SAMM's Defect Management practice — right now I have discovery, but not yet consistent triage-to-closure discipline.

## (4:30–5:00) Q&A Anticipation

### Question 1: How would you handle a Log4Shell scenario?

I'd start at the SBOM layer — is the affected component present anywhere in the app or image dependency tree? If yes, I'd flag it Critical in DefectDojo, put it on the 24-hour SLA clock immediately, and track it through owner assignment and re-scan verification rather than just marking it fixed on someone's word. The SBOM tells me *if* I have it; DefectDojo tells me *who owns it and whether it's actually closed on time*.

### Question 2: Why didn't you use IAST or paid tools?

I stuck to open-source tools that reproduce locally: Trivy, Semgrep, Checkov, KICS, ZAP, DefectDojo. Along the way I also hit real friction — a parser rejecting the wrong file format, a CVE mismapped onto unrelated IaC resources, deduplication silently left off — and I think working through that friction honestly is a better signal of DevSecOps competence than a clean run with a paid platform smoothing everything over. IAST and paid correlation engines are a reasonable next step once the basic discover-triage-remediate loop is solid, not a substitute for understanding it.
