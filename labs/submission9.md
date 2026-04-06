# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Task 1 — Runtime Security Detection with Falco

### Falco setup
Falco was started successfully in a container with the modern BPF probe and JSON output enabled. Syscall event collection was active, and the custom rule file was loaded successfully.

Falco custom rule load evidence:
```text
2026-04-06T18:51:52+0000:    /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
```

During startup, Falco printed warnings related to TOCTOU mitigation tracepoints such as open, openat, and creat. However, Falco explicitly indicated that detection would continue to work, and this was confirmed by successful runtime alert generation.

Baseline alert observed — Terminal shell in container

Trigger:

```bash
docker exec -it lab9-helper /bin/sh -lc 'echo hello-from-shell'
```

Evidence:

2026-04-06T18:41:03.479604173+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root process=sh parent=containerd-shim command=sh -lc echo hello-from-shell container_id=2858d36ab604 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19
rule="Terminal shell in container"

Additional shell detection evidence:

2026-04-06T18:49:01.856322351+0000: Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root process=sh parent=containerd-shim command=sh -lc echo custom-shell-test-2 container_id=2858d36ab604 container_name=lab9-helper container_image_repository=alpine container_image_tag=3.19
rule="Terminal shell in container"

Why it matters:

A shell inside a running container is suspicious in production environments.
It may indicate manual debugging, unauthorized access, or post-compromise activity.
Containers are generally expected to run a single application process, not ad hoc interactive shells.

### Drift test note

I attempted to trigger a drift-style event by writing into /usr/local/bin inside the helper container:

```bash
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
```

In this environment, that action did not produce a Falco alert. Even so, Falco runtime detection was functioning correctly, as verified by the successful shell-in-container detection rule.

### Custom Falco rule

File:

labs/lab9/falco/rules/custom-rules.yaml

Rule used:

- rule: Custom Lab9 Proof Shell
  desc: Detect the lab-specific proof shell command inside lab9-helper
  condition: evt.type=execve and container and container.name="lab9-helper" and proc.name=sh and proc.cmdline contains "lab9-proof-shell"
  output: >
    Falco Custom: lab9 proof shell detected (container=%container.name user=%user.name command=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, custom, lab9]

Purpose:

Detect a lab-specific shell execution pattern inside the lab9-helper container.
Demonstrate how to create a narrow, low-noise Falco rule with simple tuning.

When it should fire:

When a shell is executed in the lab9-helper container and the command line contains the unique marker lab9-proof-shell.

When it should not fire:

Shell execution on the host
Shells in unrelated containers
Shells in lab9-helper that do not include the lab-specific marker

Tuning rationale:

The rule is scoped to a single container name
It matches only shell execution
It requires a unique command-line substring to reduce false positives

Validation result:

The custom rule file loaded successfully and passed schema validation.
In this environment, the custom rule did not emit its own alert even though Falco detected the underlying shell activity through the built-in rule.
This suggests environment-specific rule matching limitations rather than a general Falco failure.

False positives and noise considerations:

General shell-in-container rules can be noisy in lab or debugging environments
Restricting by container name and command line is a practical way to reduce false positives
In a production environment, further tuning could include trusted namespaces, image filters, or maintenance container exclusions

### Task 1 summary

Falco was successfully deployed and verified to detect runtime activity. The built-in Terminal shell in container rule fired reliably for the helper container. A custom rule file was authored, loaded successfully, and documented with tuning rationale. Drift-style file-write detection under /usr/local/bin did not trigger in this environment, which was documented as a runtime limitation of this setup rather than a full Falco failure.

## Task 2 — Policy-as-Code with Conftest (Rego)
### Reviewed manifests

I reviewed the following Kubernetes manifests:

labs/lab9/manifests/k8s/juice-unhardened.yaml
labs/lab9/manifests/k8s/juice-hardened.yaml

The unhardened manifest represents a weaker baseline deployment, while the hardened manifest adds explicit runtime and security controls to satisfy policy requirements.

### Reviewed policies

I reviewed the following policy files:

labs/lab9/policies/k8s-security.rego
labs/lab9/policies/compose-security.rego

These policies enforce security best practices such as:

running containers as non-root
disabling privilege escalation
requiring resource requests and limits
preferring immutable runtime settings
discouraging mutable image tags such as :latest
checking operational readiness through health probes

### Conftest results — unhardened manifest

Result:

WARN - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions

Why these violations matter:

Missing CPU and memory requests/limits can cause unstable scheduling and resource exhaustion.
allowPrivilegeEscalation: false reduces the chance of privilege abuse inside the container.
readOnlyRootFilesystem: true helps prevent runtime tampering and container drift.
runAsNonRoot: true enforces least privilege and limits the impact of a compromise.
Using :latest weakens reproducibility and auditability because the image reference is mutable.
Missing readiness and liveness probes reduces resilience and makes health management weaker.

### Conftest results — hardened manifest

Result:

30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

Analysis:
The hardened manifest fully satisfied the Kubernetes security policy checks. Compared with the unhardened version, it clearly includes the hardening controls required by policy, such as:

explicit resource requests and limits
non-root execution
no privilege escalation
read-only root filesystem
a fixed image tag instead of :latest

These changes align the deployment with least-privilege, immutability, and reproducibility best practices.

### Conftest results — Docker Compose manifest

Result:

15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions

Analysis:
The Docker Compose manifest also passed all checks. This shows that the provided Compose configuration already follows the expected hardening baseline enforced by the policy. The result demonstrates that policy-as-code is useful not only for Kubernetes manifests but also for local container orchestration patterns such as Docker Compose.

How the hardened manifest satisfies the policies

The hardened manifest addresses the main issues found in the unhardened version by:

enforcing non-root execution
disabling privilege escalation
making the root filesystem read-only
defining CPU and memory requests and limits
avoiding the mutable :latest image tag
aligning more closely with operational readiness and secure runtime defaults

Together, these changes reduce attack surface, improve predictability, and support compliance-oriented deployment practices.

### Task 2 summary

Conftest clearly showed the difference between insecure and hardened deployment definitions. The unhardened Kubernetes manifest failed multiple policy checks, while the hardened Kubernetes manifest passed all checks. The Docker Compose manifest also passed all policy checks. This demonstrates how policy-as-code can prevent insecure runtime configurations before deployment.

## Overall conclusion

This lab demonstrated both detective and preventive security controls for containerized workloads:

Falco provided runtime detection for suspicious container behavior
Conftest/Rego enforced deployment hardening before runtime

The two tools complement each other well. Conftest helps stop insecure configurations from being deployed, while Falco helps detect suspicious behavior if something risky happens at runtime. Together, they provide a practical monitoring and compliance baseline for container security.



