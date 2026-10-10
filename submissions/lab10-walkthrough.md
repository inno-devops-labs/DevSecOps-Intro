# Lab 10 bonus — The five-minute walkthrough

A spoken answer to *"Tell me about a security project you have worked on."*
About 700 words, roughly five minutes at a normal speaking pace. Every number is
from the Lab 1–10 submissions in this repository.

---

**The setup (30 seconds)**

Over ten weeks I built the security program for one web application, OWASP
Juice Shop, the way a small team would: from a threat model to a dashboard that
tells a manager what is late. My first real decision was to pin one image digest
in week four and never move it. Every comparison after that is only meaningful
because the bytes stayed the same: between scanners, between weeks, between
before and after hardening.

**What I built (1 minute)**

The threat model's top risks were about authentication and session tokens
crossing into the container network, so that is where I aimed the later testing. I signed commits and put a secret
scanner in a pre-commit hook, because stopping a key before the push is cheaper
than rotating it afterwards. For dependencies, I generated an SBOM once and
scanned it with two tools, because I wanted to know whether scanners agree on
identical bytes. They don't: 183 matches against 173, mostly the same advisories
under different names. I ran the web scanner authenticated, because the
unauthenticated baseline found nothing above Medium. I can't patch everything in
a week, so I deployed under Kubernetes' restricted profile with a read-only
filesystem and a default-deny network policy, to limit what any exploit can do.
I signed the image by digest and attached the SBOM as an attestation, so a
deployment can prove what it runs. I also wrote admission and runtime rules for
the cases the shipped rules missed. Last, I put everything into DefectDojo and
gave it deadlines.

**One finding, end to end (1 minute 20 seconds)**

The finding I'd pick is a SQL injection in product search. ZAP flagged it High,
but with Low confidence: it sent a quote and a bracket and got a SQLite syntax
error back. An error message isn't proof. Semgrep, independently, pointed at line
23 of the search route, where the search term goes straight into a raw SQL string.

So I made three requests with no session at all. A nonsense search returns zero
products. The same search with `')) OR 1=1--` appended returns all 56. With
`1=2` instead, zero again. That is an anonymous user controlling the query, which
in this app means reading the users table.

The fix is five lines: pass the search term as a bound parameter instead of
pasting it into SQL. Before proposing it, I tested it against an in-memory
database with the same attack strings. In DefectDojo, this bug and its twin in
the login handler are three rows from two tools. They're sixteen days old
against a fourteen-day deadline, and they're what I'd fix first.

**What didn't work (1 minute)**

In the last week the import script told me everything had loaded. It hadn't. The
Kubernetes scan reported success with zero findings, because it was mapped to a
parser that reads a different Trivy format and quietly returns nothing. ZAP
failed outright: this DefectDojo version only accepts ZAP's XML. Deduplication
was off by default. Even after I turned it on, the same CVE in the same image
still appeared twice, because every hash includes the Kubernetes workload name,
and an image scan doesn't have one. And every finding was dated the day I
imported it, so the dashboard said nothing was older than zero days and 100
percent was within SLA.

I read the parser source, re-imported with the right parser, converted the ZAP
report field by field, and set each finding's date back to its scan date. With
real dates, compliance under my deadlines is 64 percent, not 100. The lesson: a
green import is not evidence, so I check counts against the raw report every
time.

**The number on the slide (40 seconds)**

Not 590. That is three scanners counting one image. Matched across tools, it's
about 340 distinct issues, and the critical ones are thirteen issues in ten
package versions. So the slide says: **zero of thirteen critical issues are
inside SLA, and five upgrades close twelve of them.** A manager can staff that.
The thirteenth has no fix, so it needs a decision to replace the package, not
another week of waiting. The second line on the slide is the SQL injection,
because it's what an attacker would find first.
