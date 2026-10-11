# Five-minute walkthrough: a DevSecOps project

Over one semester I built a full security pipeline around a single application, OWASP Juice Shop, and
tracked every control from the developer's laptop through to a running cluster. The point was not to try
ten tools; it was to follow one app through every stage where security can go wrong and prove I could
measure what I found. Let me walk you through it the way it actually ran.

It starts at the commit. I set up SSH-signed commits and a pre-commit hook that runs gitleaks, so a secret
is blocked before it ever reaches history rather than caught after it leaks. That mattered in practice:
when I later wrote a report that quoted a fake token as an example, my own hook refused the commit, and I
had to write a value-scoped allowlist instead of switching the check off. That is the kind of decision I
care about, keeping the detection while removing the noise, not just turning red things green.

From there the app gets inventoried and scanned. I generated a software bill of materials, scanned it for
known vulnerabilities, and ran static analysis on the source and a dynamic scan on the running app. Then I
hardened it: the container runs as a non-root user with a read-only root filesystem and all Linux
capabilities dropped, under Kubernetes' restricted Pod Security Standard, behind a default-deny network
policy. I signed the image with cosign and attached the bill of materials as a signed attestation, so a
consumer can prove the image is the one I built. And I put runtime detection on the cluster with Falco, so
if something does break out at three in the morning, a rule fires.

The finding I am proudest of tracing end to end is a SQL injection. Static analysis flagged a line in the
product search route where a user's query string was concatenated straight into a database query. On its
own, a static finding is a maybe. So I went to the running app and sent the exact request the dynamic
scanner had used: a normal search term returned results and an HTTP 200, but a single quote returned a 500
Internal Server Error. That 500 on a crafted quote, where a benign term is fine, is the signature of an
unparameterised query. Two tools, one from reading the code and one from attacking the live app, pointing
at the same line. The fix is two lines: bind the input as a query parameter instead of concatenating it,
so a quote in the input is treated as data, not as SQL. I would ship that first, because it is reachable
without logging in, proven exploitable, and cheap to close.

One thing that did not work, and this is the honest part: when I turned on the read-only root filesystem,
the app crashed on startup. The instinct is to guess which directories it needs and mount volumes there,
but guessing is how you spend an afternoon. Instead I ran the container and used a diff of its filesystem
to see exactly which paths it wrote to at runtime. That found five. But a sixth only appeared once I turned
read-only on in Kubernetes and read the actual crash log, which named a file the idle diff had missed. And
three of those directories were not empty, they shipped files the app serves, so an empty volume over them
hid the real files and the app either crashed or served a blank page. I solved it with an init container
that copies the original files into the volumes before the main container starts. The lesson I took is
that you find the paths a process writes by watching it and reading its errors, not by assuming.

At the end I put nine weeks of scanner output into one vulnerability-management system to see the whole
picture. That surfaced the number I would put on a slide, and it is deliberately not the scary one. The
raw count was 562 findings, but most of that is deliberately vulnerable test fixtures that never ship, and
the same image vulnerabilities counted twice because two scans recorded them. The number that matters:
**36 critical findings, and zero of them inside a three-day fix deadline.** That reframes the conversation
from "we have hundreds of issues" to "we have a small number of real, overdue criticals and a clear plan,"
which is the conversation a manager can actually act on.

If I had to summarise what I learned: tools are easy and judgment is the job. Every stage produced findings;
the skill was deciding which were real, which were noise, and which one to fix first.
