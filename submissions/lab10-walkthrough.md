# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context
[1 sentence: I built a DevSecOps program around OWASP Juice Shop as the target...
1 sentence: Tools used, scope, what's signed/scanned/verified.]
I built a DevSecOps program around OWASP Juice Shop, whcih is vulnerable. Program uses tools liek SAST, runtime monitoring etc.

## (0:30–2:00) Layers
[Draw the diagram from Lecture 9 slide 18 in your words. Talk through:
- Pre-commit: gitleaks for secrets + SSH-signed commits
- Build: SBOM (Syft), SCA (Grype), SAST (Semgrep)
- Pre-deploy: Checkov on IaC, Cosign sign + Conftest gate
- Runtime: Falco eBPF detection
- Program: DefectDojo aggregation + SLA matrix + MTTR/age]

On pre-commit stage there are signed commits and Gitleaks scan. Then CI (Syft, Grype and Semgrep). Pre-deploy: Checkov scans Terraform, Cosign signs images and also there is Conftest. There is Falco for runtime and DefectDojo then summarizes all findings.

## (2:00–3:00) Findings + Closures
[Talk through:
- "We closed <n> Critical findings this term."
- "Here's one I risk-accepted — <name> — expiring <date>, why: <reason>."
- "Strongest correlated finding: <name> — caught by both Semgrep and ZAP, fix was <X>."]
347 findings were identified from 6 tools. Currently none have been closed, however I am eager to work further. Currently there were no risk accepted items, and there is no dedup, however manually there was found a finding that was found by two versions of grype. Finding GHSA-c7hr-j4mj-j2w6.

## (3:00–4:00) Metrics
[Talk through:
- MTTR: <n> days (compare to DORA Elite which is <1 day, Lecture 9 slide 13)
- Vuln-age median: <n> days
- SLA compliance: <n>%
- Backlog trend: <stable/falling/rising>]

Current metrics are unfortunately poorly established, since there are yet no mitigated findings. There fore MTTR and SLA comliance cannot be established. New baseline is 347 active findings.

## (4:00–4:30) Next Steps
[1 sentence: "If I had another quarter, I'd ship..."
1 sentence: tied to OWASP SAMM ladder progression.]
If I had another quarter, I'd ship move to level 2 of SAMM ladder, i'd try to ship that when DefectDojo found a critical bug, it automatically created a Jira ticket.

## (4:30–5:00) Q&A Anticipation
Anticipate 2 likely questions and answer them in your script:
1. "How would you handle a Log4Shell scenario?" → I would keep SBOM lists of every package, that would be checked by Grype. Then in case of Log4Shell appearance, I would be able to track everything in DefectDojo.

2. "Why didn't you use IAST/paid tools?" → I used open-source tools. This project was for introductory study, therefore there was no need in paid tools.