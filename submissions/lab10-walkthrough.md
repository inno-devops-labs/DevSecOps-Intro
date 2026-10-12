# Five-Minute Walkthrough — A DevSecOps Project

*Spoken script, ~700 words / ~5 minutes. For the interview answer to "tell me about a security
project you've worked on."*

---

Over about ten weeks I took one deliberately vulnerable application — OWASP Juice Shop — and built
a security pipeline around it that covers the whole software lifecycle, from the dependencies it
ships with to how it behaves live in a cluster. The point wasn't to run a lot of tools; it was to
make them agree with each other and produce one backlog a team could actually work.

I'll start with the shape of it. I generated a software bill of materials for the image and scanned
it two ways, with Grype and Trivy, so I had a dependency inventory and its known CVEs. I scanned the
source with Semgrep for code-level bugs, and the running app with OWASP ZAP for things you can only
see at runtime. I scanned the infrastructure-as-code — Terraform, Ansible, Pulumi — with Checkov and
KICS, and wrote a custom policy neither tool ships, because generic rules don't know your org's
standards. I hardened the Kubernetes deployment under the `restricted` Pod Security Standard and
proved it: a plain deployment gets rejected by the admission controller, and the pod runs as a
non-root user I confirmed by reading its process from the node. I signed the image with Cosign and
attached the SBOM as a signed attestation, so a consumer can verify both *that* the image is
unchanged and *what's inside it*. And I set up Falco for runtime detection, writing rules for a
suspicious write to `/tmp` and for likely cryptomining. Finally I pulled every scanner's output into
DefectDojo, one system, and turned it into a governance report with SLAs.

Now the part that matters — one finding I traced end to end. Semgrep flagged
`express-sequelize-injection` in `routes/search.ts`: user input from the search query was being
concatenated straight into a SQL string. On its own that's a static finding — maybe reachable, maybe
not. But ZAP, scanning the *running* app, sent `?q='(` to `/rest/products/search` and got back a
500 with a raw SQLite syntax error reflecting the payload. That's the proof: the static tool pointed
at the exact line, and the dynamic tool showed it was actually exploitable from the outside. Two
independent tools, one vulnerability, no ambiguity about whether it's real. The fix is a one-line
change — parameterize the query with a bound replacement instead of string interpolation — and I'd
open that PR first, because I can attach both the vulnerable line and the working request to it.

One thing that didn't work, and what I did. When I loaded everything into DefectDojo, the ZAP import
failed outright — the parser is XML-only, but the report I'd generated was JSON. The easy move would
have been to shrug and say "ZAP's missing." Instead I wrote a small converter that transformed the
real scan data into the XML schema the parser expected, and the 13 findings came in correctly. It
was a small thing, but it's the whole lesson of the capstone in miniature: the friction in security
isn't usually the scanning, it's getting independent tools to agree on a format so you get one
number instead of nine. I hit the same theme twice more — Cosign's newest release had silently
dropped a flag the signing commands needed, so I pinned to a known-good version, and on my kernel
Falco couldn't resolve a network connection's port, so I built a fallback signal into the rule and
documented the limitation rather than hiding it.

The number I'd put on a slide: **678 raw findings in, but the number that mattered was one.** After
collapsing duplicate npm CVEs that three scanners each reported, and setting aside the 96
intentionally-broken IaC fixtures that were never going to deploy, the real actionable backlog was a
few dozen dependency upgrades — and exactly one confirmed, reachable, cross-validated SQL injection
sitting at the top. That gap, between 678 and 1, is the actual job: not finding more, but knowing
which one to hand a developer on Monday morning.

If I had to sum up what I learned: tools find things, but a program decides what's worth doing. The
value wasn't any single scanner — it was duplication collapsed, severities put against deadlines,
and one defensible "fix this first."
