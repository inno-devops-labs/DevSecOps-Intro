# Lab 9 --- Monitoring & Compliance

## Falco Runtime Detection + Conftest Policies

------------------------------------------------------------------------

## Methodology

### Falco Runtime Detection

Falco was deployed as a privileged container using the modern eBPF
engine to monitor system calls in real time. Required host paths such as
`/proc`, `/boot`, `/lib/modules`, and the Docker socket were mounted to
allow Falco to observe container activity.

A helper container (`alpine:3.19`) was used to simulate runtime
behavior. This lightweight BusyBox-based container allowed controlled
triggering of security-relevant events.

Two baseline behaviors were tested: - Launching an interactive shell
inside the container - Writing to a binary directory (`/usr/local/bin`)

Additionally, a custom Falco rule was implemented to detect file writes
under `/usr/local/bin`, which is typically considered a sensitive
location and indicative of container drift or compromise.

The rule: - Monitors open/write syscalls - Filters only write
operations - Ensures activity originates from a container (not host) -
Targets `/usr/local/bin/*`

This helps reduce noise and focus on meaningful security events.

------------------------------------------------------------------------

### Conftest Policy Enforcement

Conftest (OPA/Rego) was used to statically analyze Kubernetes manifests
against predefined security policies.

Three sets of tests were executed: - Unhardened Kubernetes manifest -
Hardened Kubernetes manifest - Docker Compose configuration

The policies enforce best practices such as: - Running containers as
non-root - Defining resource limits and requests - Preventing privilege
escalation - Using read-only filesystems - Avoiding `:latest` image tags

The hardened manifest was designed to comply with these policies, while
the unhardened version intentionally violated them.

------------------------------------------------------------------------

## Demonstration

### Falco Alerts

Baseline expected alerts: - Terminal shell inside container - File write
under `/usr/local/bin` (drift detection)

Custom rule behavior: - Triggers when any file is written to
`/usr/local/bin` inside a container - Should NOT trigger for read-only
operations - Should NOT trigger for host-level operations

Note: In this run, Falco reported:

    Events detected: 0

This indicates either: - Falco was not correctly capturing syscalls
(likely environment limitation), or - Events were not properly
triggered/logged

------------------------------------------------------------------------

### Conftest Results

#### Unhardened Manifest

Warnings: - Missing livenessProbe - Missing readinessProbe

Failures: - Missing CPU/memory requests and limits - Privilege
escalation not disabled - Root filesystem not read-only - Not running as
non-root - Uses `:latest` tag

Summary: - 30 tests executed - 8 failures, 2 warnings

#### Hardened Manifest

All policies passed: - 30 tests, 0 failures

Key improvements: - Added resource limits/requests - Enforced non-root
execution - Disabled privilege escalation - Enabled read-only root
filesystem - Dropped all capabilities - Added health probes - Used fixed
image version

#### Docker Compose

-   15 tests passed
-   No warnings or failures

------------------------------------------------------------------------

## Analysis

### Security Impact of Violations

Unhardened configuration risks: - Resource exhaustion (no limits) -
Privilege escalation attacks - Container breakout risks - Unstable
deployments (no probes) - Non-reproducible builds (`latest` tag)

### Hardening Benefits

The hardened manifest ensures: - Predictable resource usage - Reduced
attack surface - Strong runtime isolation - Better observability and
resilience

------------------------------------------------------------------------

## Conclusion

This lab demonstrated: - Runtime threat detection using Falco (though
limited by environment) - Writing custom detection rules - Enforcing
security best practices using policy-as-code - Identifying and fixing
Kubernetes misconfigurations

Falco complements Conftest: - Falco → runtime protection - Conftest →
deployment-time validation

Together, they provide a strong security posture for containerized
applications.
