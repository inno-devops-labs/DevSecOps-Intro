# Lab 12 - Kata Containers: VM-backed Container Sandboxing (Local)

## Scope

- Analysis date: `2026-04-27`
- Host/runtime: `WSL2 Ubuntu 24.04` on Windows host
- Stack path: `labs/lab12`
- Evidence directories:
  - `labs/lab12/setup`
  - `labs/lab12/runc`
  - `labs/lab12/kata`
  - `labs/lab12/isolation`
  - `labs/lab12/bench`
  - `labs/lab12/analysis`

## Task 1 - Install and Configure Kata

### 1.1 Kata runtime/shim and assets

- Kata shim installed and verified:
  - `labs/lab12/setup/kata-built-version.txt`
  - Output:
    - `Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.29.0, commit: 8dccf4cf37aeea4b6c2caacf3e61510d6eef2f71`
- Shim path:
  - `labs/lab12/setup/kata-shim-command-path.txt` -> `/usr/local/bin/containerd-shim-kata-v2`
- Kata runtime-rs config symlink:
  - `labs/lab12/setup/kata-config-link.txt` -> `/etc/kata-containers/runtime-rs/configuration.toml`

Note:

- `build-kata-runtime.sh` was attempted first, but repeated transient Git clone TLS failures occurred inside the Rust build container.
- To continue the lab with working Kata 3 artifacts, I installed official `kata-static` release assets and then installed/verified `containerd-shim-kata-v2`.

### 1.2 containerd runtime configuration

- `io.containerd.kata.v2` was configured in `/etc/containerd/config.toml`:
  - Evidence: `labs/lab12/setup/containerd-kata-config-snippet.txt`
  - Snippet:
    - `[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]`
    - `runtime_type = 'io.containerd.kata.v2'`
- Service status after configuration:
  - `labs/lab12/setup/containerd-active-after-kata.txt` -> `active`

### 1.3 Kata test run

- Successful Kata runtime test:
  - `labs/lab12/setup/kata-test-uname.txt`
  - Output:
    - `Linux ... 6.18.15 ... x86_64 Linux`

Task 1 status: complete.

## Task 2 - Run and Compare Containers (runc vs kata)

### 2.1 runc Juice Shop baseline

- Container started with default runtime and published on `3012`:
  - `labs/lab12/runc/juice-runc-container-id.txt`
  - `labs/lab12/runc/nerdctl-ps-a.txt`
- Health check:
  - `labs/lab12/runc/health.txt` -> `juice-runc: HTTP 200`

### 2.2 Kata container tests

- `labs/lab12/kata/test1.txt`:
  - `Linux ... 6.18.15 ...`
- `labs/lab12/kata/kernel.txt`:
  - `6.18.15`
- `labs/lab12/kata/cpu.txt`:
  - `model name : AMD EPYC`

### 2.3 Kernel comparison

- Evidence: `labs/lab12/analysis/kernel-comparison.txt`
- Host kernel (`runc` uses host kernel):
  - `5.15.167.4-microsoft-standard-WSL2`
- Kata guest kernel:
  - `Linux version 6.18.15 ...`

Conclusion:

- `runc` shares host kernel.
- `kata` runs workload in a separate guest kernel.

### 2.4 CPU comparison

- Evidence: `labs/lab12/analysis/cpu-comparison.txt`
- Host:
  - `AMD Ryzen 7 5800H with Radeon Graphics`
- Kata VM:
  - `AMD EPYC` (virtualized CPU model exposed in guest)

Isolation implications:

- `runc`: namespace/cgroup isolation on shared host kernel.
- `kata`: container payload runs inside a lightweight VM boundary with separate kernel.

Task 2 status: complete.

## Task 3 - Isolation Tests

### 3.1 dmesg access

- Evidence: `labs/lab12/isolation/dmesg.txt`
- Kata output shows guest boot logs from kernel `6.18.15` and guest command line.

Key observation:

- Boot logs prove a separate VM kernel context for Kata workloads.

### 3.2 /proc visibility

- Evidence: `labs/lab12/isolation/proc.txt`
- Host `/proc` entries: `131`
- Kata VM `/proc` entries: `51`

### 3.3 Network interfaces

- Evidence: `labs/lab12/isolation/network.txt`
- Kata guest has its own network stack view (`lo`, `eth0`, guest IP `10.4.0.16/24`).

### 3.4 Kernel modules

- Evidence: `labs/lab12/isolation/modules.txt`
- Host modules: `114`
- Kata guest modules: `72`

Isolation boundary differences:

- `runc`: processes are isolated but still tied to host kernel attack surface.
- `kata`: extra virtualization boundary separates guest workload from host kernel.

Security implications:

- Container escape in `runc`: likely immediate host-kernel compromise path.
- Container escape in `kata`: first compromises guest VM; attacker still needs VM escape/hypervisor-level break to reach host.

Task 3 status: complete.

## Task 4 - Performance Comparison

### 4.1 Startup overhead

- Evidence: `labs/lab12/bench/startup.txt`
- runc startup:
  - `real 0m1.316s`
- Kata startup:
  - `real 0m3.181s`

Observation:

- Kata startup is slower due VM boot/init overhead.

### 4.2 HTTP latency baseline (runc)

- Evidence:
  - `labs/lab12/bench/curl-3012.txt` (50 samples)
  - `labs/lab12/bench/http-latency.txt`
- Result:
  - `avg=0.0031s min=0.0024s max=0.0061s n=50`

Trade-off analysis:

- Startup overhead:
  - `kata` > `runc` (extra VM init time).
- Runtime overhead:
  - Small-to-moderate depending on IO/syscall profile; generally acceptable for stronger isolation needs.
- CPU overhead:
  - Some overhead from virtualization boundary and guest scheduling.

When to use each:

- Use `runc` when:
  - Fast startup/high density and minimal overhead are top priorities in trusted or lower-risk workloads.
- Use `kata` when:
  - Strong workload isolation is required for multi-tenant, untrusted code, or stricter defense-in-depth requirements.

Task 4 status: complete.

## Deliverable Checklist

- [x] Task 1 - Kata install + runtime config
- [x] Task 2 - runc vs kata runtime comparison
- [x] Task 3 - isolation tests and boundary/security analysis
- [x] Task 4 - startup and latency performance snapshot
