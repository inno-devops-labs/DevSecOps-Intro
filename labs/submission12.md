# Lab 12 — Kata Containers: VM-backed Container Sandboxing

## Goal
Compare the default `runc` runtime with Kata Containers and document the isolation and performance trade-offs.

## What I did
- Built the Kata Rust shim with `labs/lab12/setup/build-kata-runtime.sh`.
- Verified the shim version with `containerd-shim-kata-v2 --version`.
- Configured `containerd` to expose `io.containerd.kata.v2`.
- Ran a `runc` Juice Shop container and captured health/latency data.
- Attempted to run Kata containers and documented why the guest could not boot in this host.

## Task 1 — Kata install and runtime config
- Shim version: `labs/lab12/setup/kata-built-version.txt`
- `containerd` runtime config: `labs/lab12/setup/build-kata-runtime.sh`
- Kata assets/config were installed and wired for `io.containerd.kata.v2`.

Status:
- Shim build and install: completed
- Kata guest boot: blocked in this environment

Blocker:
- This host is Docker Desktop / LinuxKit on macOS.
- `/dev/kvm` is not available in the container.
- `vmx/svm` CPU flags are not exposed.
- Kata tasks connect to the shim, but the guest never prints output.

Evidence:
- `labs/lab12/analysis/kata-blocker.txt`
- `labs/lab12/kata/test1.txt`
- `labs/lab12/setup/kata-built-version.txt`

## Task 2 — runc vs kata comparison

### runc evidence
- `runc` uname output: `labs/lab12/runc/uname.txt`
- Juice Shop health check: `labs/lab12/runc/health.txt`

Observed:
- `runc` uses the host kernel.
- Juice Shop on `runc` returned HTTP `200` on port `3012`.

### Kata evidence
- Kata runtime attempts were started through `io.containerd.kata.v2`.
- No successful guest output was produced in this environment.

Kernel comparison:
- Host kernel: `labs/lab12/analysis/host-kernel.txt`
- Comparison notes: `labs/lab12/analysis/kernel-comparison.txt`

CPU comparison:
- Comparison notes: `labs/lab12/analysis/cpu-comparison.txt`

Interpretation:
- `runc` shares the host kernel with the container.
- Kata would normally boot a separate guest kernel, but that could not be demonstrated here because the environment lacks nested virtualization support.

## Task 3 — Isolation tests
What was intended:
- Compare `/proc` visibility.
- Compare kernel behavior.
- Compare network and guest visibility.

What was actually observed:
- The host has no `/dev/kvm`.
- Kata guest boot did not complete.
- Because the guest never booted, isolation proof points like guest `dmesg` and guest `/proc` enumeration are unavailable in this environment.

Evidence:
- `labs/lab12/analysis/kata-blocker.txt`
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/analysis/cpu-comparison.txt`

## Task 4 — Performance snapshot
### runc
- Startup time: `labs/lab12/bench/runc-startup.txt`
- HTTP latency on Juice Shop: `labs/lab12/bench/http-latency.txt`

Observed values:
- `runc startup=441ms`
- `HTTP 200` on Juice Shop
- Average response time across 50 requests: `0.0019s`

### Kata
- Startup time could not be measured here because the guest did not boot.

## Summary
The Kata shim and containerd wiring were completed, and the `runc` side of the lab was measured successfully. The limiting factor is the execution environment: Docker Desktop / LinuxKit on macOS does not expose nested virtualization, so Kata cannot complete a VM-backed boot here.

If this lab is graded in a real Linux environment with `/dev/kvm` enabled, the Kata runtime comparison and isolation tests should be rerun there.

## Artifacts
- `labs/submission12.md`
- `labs/lab12/setup/kata-built-version.txt`
- `labs/lab12/runc/uname.txt`
- `labs/lab12/runc/health.txt`
- `labs/lab12/bench/runc-startup.txt`
- `labs/lab12/bench/http-latency.txt`
- `labs/lab12/analysis/host-kernel.txt`
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/analysis/cpu-comparison.txt`
- `labs/lab12/analysis/kata-blocker.txt`
- `labs/lab12/kata/test1.txt`

## Checklist
- [x] Kata shim built and verified
- [x] containerd configured for `io.containerd.kata.v2`
- [x] `runc` workload reachable and measured
- [x] Runc latency snapshot recorded
- [ ] Kata guest boot demonstrated
- [ ] Isolation tests completed in Kata guest
- [ ] Kata startup/performance comparison completed
