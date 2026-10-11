# Five-minute security project walkthrough

## 0:00–0:45 — The problem and scope

I used OWASP Juice Shop as the target for a ten-lab DevSecOps project. The application is intentionally vulnerable, so my objective was to build a repeatable security process around it, rather than promise that a teaching application could become production-safe. I started with deployment and scope, then threat modeling, Git integrity and secret controls. Those decisions defined what needed protecting, where trust boundaries sat, and which evidence I would need when a scanner reported a problem. I kept the vulnerable examples available for comparison instead of quietly changing the target and losing the baseline.

## 0:45–1:40 — Build, deployment and runtime decisions

I generated an SBOM and scanned dependencies to connect package advisories to an actual image inventory. I then compared source analysis with authenticated dynamic testing, because a code pattern and a reachable exploit are different kinds of evidence. Infrastructure scanning made me examine permissions and exposure before deployment. Container hardening reduced the impact of exploitation through a non-root user, dropped capabilities, a read-only root filesystem, restricted network access and Kubernetes policy enforcement. I checked actual runtime identity and readiness, because a secure-looking manifest is insufficient if the application cannot run or the controls are not applied.

Supply-chain work demonstrated why approval must bind to an immutable image digest: a signed original still verified after I replaced its tag, while the unsigned replacement failed verification. I attached and verified inventory evidence, while explicitly distinguishing my example provenance from proof that I built the upstream application. Runtime detection then caught terminal shells, sensitive-file reads and unexpected writable opens under `/tmp`. A mining detector combined a suspicious process name with a connection attempt; I tested only a refused localhost connection, not a real pool.

## 1:40–2:40 — One finding traced to a fix

The clearest remediation example came from the infrastructure lab. Checkov flagged an IAM statement allowing every action against every resource. That is a privilege design problem: a compromised workload could inherit permissions far beyond its purpose. I traced the alerts back to the Terraform policy rather than assigning a separate ticket to every rule match.

In a temporary copy, I replaced that statement with an allowlist for `s3:GetObject` on one application prefix. The rescan changed the Terraform results from 49 passed and 78 failed to 58 passed and 69 failed. One edit cleared nine overlapping failures. That was a verified least-privilege experiment, not a claim that the sample infrastructure had been deployed or the final application permissions had been established. In a real rollout, I would validate the workload's required actions, review the policy, deploy it, and verify allowed and denied requests.

## 2:40–3:40 — What did not work

At the capstone, the importer failed on the saved ZAP JSON: the pinned DefectDojo parser expected XML. The Kubernetes import was more deceptive: it returned success with zero findings because Trivy CLI output had been sent to an Operator parser. I inspected the versioned parser code, adapted the original evidence without rerunning the scans, and checked preservation of alerts, instances and resource results. The repaired imports produced 22 ZAP findings and 174 cluster records.

That failure changed how I judge integrations. An HTTP success proves delivery, not coverage. I need expected input counts, parser compatibility and representative findings before trusting the dashboard. I also found deduplication disabled by default and imported dates that made old findings look new. I enabled deduplication and restored the evidenced original dates before calculating deadlines.

## 3:40–5:00 — The number and the decision

My slide would show **518 active canonical scanner findings, with 65.22% of deadline-bearing findings inside SLA**. Nine reports initially produced 766 records; automated grouping and reviewed matches marked 248 duplicates. That reduction is an accounting improvement, not 248 security fixes. The remaining count still needs cross-tool alias, scope and reachability review.

I applied deadlines of 3, 14, 45 and 90 days by severity. Preserving original dates exposed 176 overdue critical/high records. My first application priority is the validated SQL injection evidence, with an owner, parameterized queries and regression plus dynamic verification. The project's value is that each decision can be traced from evidence to an owner, a deadline and a verification step.
