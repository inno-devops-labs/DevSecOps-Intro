# Five-minute walkthrough

*Spoken script for "tell me about a security project you have worked on." Roughly 700 words.*

---

Over ten weeks I built a DevSecOps pipeline around one target: OWASP Juice Shop, a deliberately vulnerable web application. I didn't write the app. The whole point was to take something I didn't control and make shipping it safe — which is the actual job most of the time.

I'll start with the shape, then one finding end to end, then something that didn't work.

**The shape.** Controls at four moments. Before the commit: pre-commit hooks with gitleaks, and every commit SSH-signed. At build: an SBOM from Syft, scanned with Grype, plus Trivy on the image, and the SBOM signed with Cosign as an in-toto attestation bound to the image digest. At deploy: Checkov and KICS on infrastructure code, Conftest policies on the Kubernetes manifests, and the workload running under the `restricted` Pod Security Standard. At runtime: Falco watching syscalls, and a default-deny NetworkPolicy. Then everything lands in DefectDojo with an SLA attached.

I want to pull one thread out of that, because the tool list is not the interesting part.

**One finding, traced.** In week five I ran two scanners that have nothing to do with each other. Semgrep read the source and flagged `routes/login.ts`, line 34 — a template string interpolating `req.body.email` straight into a SQL query. Separately, ZAP attacked the running app and reported a High-severity SQL injection on `POST /rest/user/login`, having sent a single quote and received a 500.

Two tools, opposite directions, same defect. I confirmed it by hand: posting `' OR 1=1--` as the email returns HTTP 200 with a signed JWT for `admin@juice-sh.op`. Administrator session, no password. The fix is parameter binding — bind the email as `:email` instead of interpolating it — about four lines.

What I took from that wasn't "SQL injection is bad." It was the ordering. When I wrote the pull request, the first thing in the description was the two-line `curl` that logs in as admin. Not the Semgrep rule ID, not the CWE number. A reviewer who reads "SQL injection in login.ts" schedules it for the sprint; a reviewer who watches a request return an admin token merges it that day. The scanner output went underneath, as the answer to "how do we know it's the only one and how will we know if it comes back."

**Something that did not work.** Week seven, hardening the container: I added `readOnlyRootFilesystem: true` and the pod went into CrashLoopBackOff. The log said `EROFS` on `frontend/dist/frontend/index.html`.

My first instinct was to guess which directories needed to be writable and mount empty volumes over them. That made it worse — the app died differently, because Juice Shop rewrites `index.html` at startup to inject the application name, so that directory has to be both present *and* writable, and an empty volume hides the entire built frontend.

So I stopped guessing and asked the container. `docker diff` lists every path a running container has modified. Six directories, and the useful distinction was which of them ship files in the image and which start empty. Two could take a bare `emptyDir`. Four had to be pre-populated. And the image is distroless — no shell, no `cp` — so the initContainer that seeds them runs the image's own Node binary with `fs.cpSync`.

The lesson I'd actually repeat: I burned about forty minutes guessing at a question the tooling answers in one command. Hardening is an empirical exercise, not a design exercise — you find out what a process needs by watching it, not by reasoning about what it ought to need.

**The number for the slide.** Not 673, which is how many findings DefectDojo holds. That number is a sum of eight scanners that don't deduplicate against each other, and roughly a hundred of them are against sample code that will never deploy.

The number is **77 of 85** — the share of High and Critical findings in the production image that have a published fix available. That's the one I'd defend in a planning meeting, because it separates work from decisions. Seventy-seven are a patch someone applies. The remaining eight have no fix in existence, so they're a different conversation: remove the dependency, or accept the risk with a date and a compensating control. I accepted three of them until mid-December, backed by the read-only filesystem and the default-deny network policy, with a recheck scheduled rather than a promise to remember.

If I had to compress the whole ten weeks into one sentence: scanners are cheap and findings are abundant, and the engineering is in deciding which ones are real.
