# Five-minute walkthrough: "Tell me about a security project you have worked on"

*About 700 words spoken.*

---

Over one semester I built a security program around a single deliberately vulnerable web application, OWASP Juice Shop. The goal was not to run scanners. It was to end with a backlog someone could own, with deadlines attached.

**What I built.** I treated it like a product I was responsible for.
- **Threat model first,** so I knew what mattered before any tool said anything.
- **Secret scanning and signed commits** on the repository itself, so the pipeline could trust its own history.
- **An SBOM** for the container image, scanned with two different tools. I kept the SBOM because it outlives any one scan.
- **The running application**, attacked with ZAP, both anonymously and logged in, while Semgrep read the source at the same version.
- **Infrastructure code** scanned with Checkov and KICS, plus a policy of my own that neither tool ships.
- **Kubernetes:** the application deployed under the strictest Pod Security profile, with a read-only root filesystem and a default-deny network policy.
- **Supply chain:** I signed the image and attached the SBOM as a signed attestation.
- **Runtime:** Falco watching containers from the kernel, and Conftest rejecting bad manifests before they deploy.
- **All the results** loaded into DefectDojo, with deadlines I chose and defended.

**One finding, from scanner to fix.** The one I would pick is the SQL injection in product search.
- **SAST:** Semgrep flagged line 23 of `routes/search.ts`, where the search parameter is pasted straight into a SQL string.
- **DAST:** separately, ZAP's authenticated active scan raised a High on `/rest/products/search` with the payload quote-open-parenthesis.
- **Confirmation:** I sent that one request myself, and the response was a SQLite syntax error, so the quote was reaching the database parser.

That is the strongest evidence you can have: a static tool pointing at the line, a dynamic tool proving it is reachable, and both agreeing independently. The fix is to bind the value as a query parameter instead of interpolating it, and the same pattern exists in login. In the final report it is the single biggest risk. It needs no authentication and exposes the users table.

**Something that did not work.** In the supply-chain lab I signed the image with flags that were meant to keep the signatures off Sigstore's public transparency log, because a registry on a laptop has no business being in a public ledger. When I looked inside the signature bundle, there was a log entry from the public Rekor instance. In that version of Cosign, a default setting overrides the flag, so all five signing operations had been published.

I could not undo it, since the log is append-only. What I could do was find out exactly what had been exposed. I pulled the entries back from Rekor's API: they contain hashes, signatures and the public key, and no image names, repository URLs or SBOM content. I documented the cause, the correct flag and the exposure. The lesson I took is to verify that a privacy control worked, not trust that it did.

The final stage had the same pattern. The documented importer quietly loaded zero findings from my Kubernetes scan, because it used the wrong parser. The DefectDojo image tag the instructions pulled would also have been a different major version from the one the lab pins. Both "worked", and neither did what it said.

**The number on the slide.** DefectDojo reported 757 findings. After deduplication it was 592. The Critical row reads 33, but those are fourteen distinct vulnerabilities, closable with about six changes: four dependency bumps, one base-image update, and replacing one abandoned library that has no fix. That last one I formally risk-accepted for ninety days, behind the Kubernetes controls I had built.

So the slide says **757 → 14 → 6**: findings reported, vulnerabilities that are real, changes needed to close them. I also put my own SLA next to the default one. With mine, 68 percent of findings are on time; the default would have said 94 percent while 151 High findings sat unfixed. I chose the stricter number on purpose. A deadline that always looks green is not managing anything.

What I would say I learned is that every tool in the chain told me something true and something misleading. The work was deciding which was which, and leaving a record good enough for the next person to check my decision.
