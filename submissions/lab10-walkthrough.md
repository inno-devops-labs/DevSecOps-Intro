# Walkthrough

I built a security workflow around OWASP Juice Shop, an intentionally vulnerable application, across ten labs. My aim was to connect evidence to decisions: what was exposed, what needed changing, whether the change worked, and what risk remained. I kept the training environment separate from a production claim. A passing check meant that a particular control worked under the tested conditions, not that the entire application was secure.

In Lab 1, I deployed the application with its published port bound to localhost and inspected authentication, public APIs and response headers. That established the attack surface before I added scanners.

Lab 2 turned the architecture and login flow into threat models. Updating transport and authentication assumptions reduced the architecture model from 23 to 18 risks, but I explicitly retained application risks such as XSS: an architecture YAML change cannot repair vulnerable application code.

Lab 3 addressed trust in repository changes. I enabled SSH commit signing and tested secret-detection hooks with a fake token. The rejected commit showed that the hook blocked the example before it entered history. I also practiced history cleanup in a disposable repository. The operational decision was that removing a leaked credential from Git history must be followed by revocation or rotation, because existing copies cannot be recalled.

Lab 4 added an SBOM and dependency scans. I compared Grype and Trivy rather than treating their totals as interchangeable: advisory aliases, package matching and severity filters explained some differences.

Lab 5 combined authenticated dynamic testing with source analysis. In the capstone, the SQL-injection alert and suspicious query construction in login and search routes became my first application investigation. I would validate those runtime paths before treating static challenge examples as production defects, and I would use parameterized queries for confirmed unsafe construction.

Lab 6 applied scanning to Terraform, Ansible and Pulumi. I assigned coverage by format instead of assuming that one clean scanner result covered all infrastructure. Exposed databases and credential patterns deserved review before cosmetic naming rules. I tested a custom database-naming policy on a temporary copy, but did not present that naming change as protection against database compromise.

My clearest scanner-to-fix example came from Lab 7. Trivy identified KSV-0014: the container root filesystem was writable. I enabled a read-only root filesystem, identified the application's startup write paths with docker diff, and supplied writable directories through an ephemeral volume. A non-root init container copied the necessary original files into those directories. The final workload returned HTTP 200, ran as UID 65532, and had zero reported High/Critical misconfigurations. Vulnerable image packages remained: the fix reduced runtime permissions rather than patching dependencies. NetworkPolicy enforcement also needed its own test; an HTTP port-forward check did not prove it.

Lab 8 bound signatures and attestations to image digests. After replacing the image behind a tag, verification failed for the replacement while the original digest still verified. That made the deployment decision concrete: verify the digest actually being consumed, using a trusted key.

Lab 9 then added policy checks and runtime detection. A refused test connection initially lacked destination socket fields, so I used the connection address argument as a fallback and confirmed the expected Falco alert. Detection evidence complemented prevention controls rather than replacing them.

Lab 10 centralized the selected scan reports in DefectDojo. One import failure was useful: ZAP rejected JSON because its parser required XML. I converted the existing evidence and successfully imported 13 alerts. I also caught a misleading successful import: the Operator parser produced zero findings for a CLI Kubernetes report. Using the compatible Trivy parser imported 178 findings without changing the source report.

The slide number would be 763 active records, including 60 Critical, accompanied by a warning that records are not unique remediation tasks. Repeated image observations required grouping, and today's imports made all measured ages zero.