# Lab 10 — Five-Minute Project Walkthrough

I built a security workflow around OWASP Juice Shop, an intentionally vulnerable
application. My aim was to turn security evidence into decisions: what matters,
who should act, and what would prove a fix. The course spans ten labs, from
deployment and threat modeling through repository protection, scanning,
hardening, signing, runtime detection, and vulnerability management. The
capstone brings that evidence together without pretending that every scanner
result is a separate vulnerability.

The first two stages establish the deployment and trust-boundary questions:
what is exposed, which data matters, and where untrusted input crosses into a
trusted operation. I used those questions to prioritize the application's
public search route and privileged infrastructure settings. Repository
protection then made the workflow more trustworthy: signed commits identify
the author, while secret checks reduce the chance of introducing credentials.
Neither control proves that the code itself is safe.

For dependencies, I generated an inventory and compared vulnerability results
against the same image identity. The decision was to preserve the digest and
package version, rather than treating a tag or a raw count as a stable baseline.
Source and web scanning added a different perspective: a vulnerable package
is a lead, while a reachable input flowing into a dangerous operation can
provide a much more immediate remediation target.

The clearest example was SQL injection in product search. Semgrep identified
user input interpolated into a Sequelize query in `routes/search.ts`, and ZAP
reported SQL injection on the corresponding public endpoint. I followed that
evidence with a controlled request: the response demonstrated that an input
could change query behavior and expose a hidden fixture row. That made this
more than a generic warning about string concatenation.

I then tested the proposed parameter-binding pattern using the application's
Sequelize installation and a separate in-memory SQLite database. Ordinary
searches still returned the expected visible product; a quote and the bypass
payload produced no hidden matches or SQL errors. I describe that accurately
as a proof-of-fix experiment, not a deployed production patch. The training
application remained vulnerable, and the capstone records the production-style
remediation deadline and the regression evidence needed before closure.

Infrastructure scanning showed why one correction can remove several findings:
a wildcard IAM statement triggered overlapping checks. Container hardening
addressed a separate problem, limiting what an exploited application could do
through non-root execution, a read-only filesystem, and network restrictions.
Signing bound release evidence to immutable content, while runtime detection
tested whether suspicious actions were actually observable. Those controls
complement a source fix; they do not replace it.

One thing that did not work was importing every report exactly as the lab's
example suggested. The pinned DefectDojo release rejected ZAP JSON because its
parser required XML. I converted the report structure and checked that all
24 alert groups and 63 instances retained the fields the parser consumed.
The Kubernetes report also needed the Trivy CLI parser rather than the
Operator parser. I treated parser compatibility as something to verify with
persisted findings, not something an HTTP success alone could establish.

The number I would put on a slide is **34 overdue Critical finding records**.
It prompts an ownership and triage discussion more directly than a large
undifferentiated total. For context, nine reports produced 735 records;
deduplication removed 152 repeat observations from the active queue, and one
documented training exception left 582 active records. I would show those
definitions beside the number, because neither deduplication nor accepting
risk is the same as fixing a vulnerability.

I set deadlines of three, fourteen, thirty, and ninety days by severity and
preserved original scan dates. The confirmed search issue received a specific
30 September deadline; the low-risk training exception expires on 27 October
and is limited to an isolated target with synthetic data. My final request
would be for named application and platform owners, a tested query fix, and
triage of the overdue dependency queue. The main lesson is that useful security
work ends with a reviewable decision and evidence of closure, not merely a
dashboard full of alerts.
