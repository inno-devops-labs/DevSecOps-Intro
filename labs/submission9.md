# Lab 9 — Monitoring & Compliance: Falco Runtime Detection + Conftest Policies

## Environment

- OS: Windows + PowerShell
- Docker: Docker Desktop with Linux containers / WSL2 backend
- Runtime detection tool: Falco 0.43.1
- Falco engine: modern BPF probe
- Policy-as-code tool: Conftest with OPA/Rego
- Runtime test container: alpine:3.19
- Branch: feature/lab9

## Task 1 — Falco Runtime Security Detection

### Falco setup

I started a helper container based on Alpine:

    docker run -d --name lab9-helper alpine:3.19 sleep 1d

Then I ran Falco in a privileged container with Docker socket and host system mounts. Falco loaded the default rules and my custom rule file from:

    labs/lab9/falco/rules/custom-rules.yaml

Falco logs show that the custom rules file was loaded successfully:

    /etc/falco/rules.d/custom-rules.yaml | schema validation: ok

Evidence files:

- labs/lab9/falco/logs/falco.log
- labs/lab9/analysis/falco-alerts-summary.txt
- labs/lab9/falco/rules/custom-rules.yaml

### Baseline alert: terminal shell in container

I triggered a shell event inside the helper container:

    docker exec -it lab9-helper /bin/sh -lc "echo hello-from-shell"

Falco detected this as:

    Terminal shell in container

This alert matters because an interactive shell inside a container can indicate manual debugging, lateral movement, or post-exploitation activity. In a production environment, unexpected shell execution inside a container should be investigated.

Evidence:

    rule="Terminal shell in container"
    container_name=lab9-helper
    process=sh
    command=sh -lc echo hello-from-shell
    priority=Notice

### Custom Falco rule

I created a custom rule named:

    Write Binary Under UsrLocalBin

Rule file:

    labs/lab9/falco/rules/custom-rules.yaml

The purpose of this rule is to detect write operations under /usr/local/bin inside a container. This is useful because writing new files into binary directories can indicate container drift, unauthorized tool installation, or persistence attempts.

Custom rule logic:

    evt.type in (open, openat, openat2, creat)
    evt.is_open_write=true
    fd.name startswith /usr/local/bin/
    container.id != host

### Custom rule validation

I triggered file writes inside the container:

    docker exec --user 0 lab9-helper /bin/sh -lc "echo boom > /usr/local/bin/drift.txt"
    docker exec --user 0 lab9-helper /bin/sh -lc "echo custom-test > /usr/local/bin/custom-rule.txt"

Falco detected both writes using my custom rule:

    Falco Custom: File write in /usr/local/bin

Evidence:

    rule="Write Binary Under UsrLocalBin"
    file=/usr/local/bin/drift.txt
    container_name=lab9-helper
    user=root
    priority=Warning

    rule="Write Binary Under UsrLocalBin"
    file=/usr/local/bin/custom-rule.txt
    container_name=lab9-helper
    user=root
    priority=Warning

### Tuning notes

This custom rule should fire when a process inside a container writes to /usr/local/bin. It is useful for detecting container drift and unexpected binary placement.

It should not fire for normal application writes outside binary directories, such as writes to /tmp, /var/log, or application data directories. In a production environment, this rule may need allowlists for trusted image build processes, package managers, init scripts, or containers that legitimately manage binaries at runtime.

### Falco event generator

I also ran the Falco event generator:

    docker run --rm --name eventgen --privileged -v /proc:/host/proc:ro -v /dev:/host/dev falcosecurity/event-generator:latest run syscall

Falco captured additional runtime security events, including:

- Disallowed SSH connection on a non-standard port
- Sensitive file read from /etc/shadow
- AWS credentials search activity
- Symlink and hardlink creation over sensitive files
- Fileless execution via memfd_create
- Execution from /dev/shm
- Netcat remote code execution pattern
- Log tampering activity
- PTRACE activity

These alerts show that Falco is able to detect suspicious runtime behavior from containers using syscall-level monitoring.

## Task 2 — Policy-as-Code with Conftest

### Reviewed files

Kubernetes manifests:

- labs/lab9/manifests/k8s/juice-unhardened.yaml
- labs/lab9/manifests/k8s/juice-hardened.yaml

Docker Compose manifest:

- labs/lab9/manifests/compose/juice-compose.yml

Rego policies:

- labs/lab9/policies/k8s-security.rego
- labs/lab9/policies/compose-security.rego

Evidence files:

- labs/lab9/analysis/conftest-unhardened.txt
- labs/lab9/analysis/conftest-hardened.txt
- labs/lab9/analysis/conftest-compose.txt

### Unhardened Kubernetes manifest result

The unhardened Kubernetes manifest failed Conftest checks:

    30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions

Policy warnings:

    container "juice" should define livenessProbe
    container "juice" should define readinessProbe

Policy failures:

    container "juice" missing resources.limits.cpu
    container "juice" missing resources.limits.memory
    container "juice" missing resources.requests.cpu
    container "juice" missing resources.requests.memory
    container "juice" must set allowPrivilegeEscalation: false
    container "juice" must set readOnlyRootFilesystem: true
    container "juice" must set runAsNonRoot: true
    container "juice" uses disallowed :latest tag

### Security analysis of the violations

Missing resource requests and limits are dangerous because a container can consume too much CPU or memory and affect other workloads on the same node. Resource limits support availability and isolation.

Missing allowPrivilegeEscalation: false is dangerous because a process may be able to gain more privileges than intended. Disabling privilege escalation is a standard hardening control.

Missing readOnlyRootFilesystem: true allows the container to write to its root filesystem. This increases the risk of persistence, tampering, and runtime drift.

Missing runAsNonRoot: true allows the container to run as root. Running as root increases the impact of a container escape or application compromise.

Using the :latest tag is unsafe because it is mutable. The deployed image may change without a manifest change, making deployments less reproducible and harder to audit.

Missing liveness and readiness probes reduce operational reliability. Kubernetes cannot accurately detect unhealthy containers or control when a pod is ready to receive traffic.

### Hardened Kubernetes manifest result

The hardened Kubernetes manifest passed all policy checks:

    30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions

This means the hardened manifest satisfies the policy requirements enforced by the Rego rules.

The hardening changes include:

- fixed image tag instead of :latest
- CPU and memory requests
- CPU and memory limits
- allowPrivilegeEscalation: false
- readOnlyRootFilesystem: true
- runAsNonRoot: true
- liveness probe
- readiness probe

These settings improve security, reproducibility, and reliability.

### Docker Compose manifest result

The Docker Compose manifest passed all policy checks:

    15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions

This means the Compose manifest satisfies the provided Docker Compose security policy. The policy checks help ensure that container configuration follows hardening expectations such as avoiding privileged execution and insecure runtime patterns.

## Conclusion

This lab demonstrated two important DevSecOps practices.

First, Falco was used for runtime detection. It detected an interactive shell in a container, writes into /usr/local/bin, and multiple suspicious behaviors generated by the Falco event generator.

Second, Conftest was used for policy-as-code. The unhardened Kubernetes manifest failed because it lacked several security controls, while the hardened manifest and Docker Compose manifest passed the policy checks.

Together, these tools show how runtime monitoring and preventive compliance checks can be combined to improve container and deployment security.
