# Lab 12 — Kata Containers: VM-backed Container Sandboxing (Local)

## Environment and Tooling Evidence
- Host model: Windows + WSL2 (Linux backend)
- Docker Engine: 28.3.2
- containerd: 1.7.27
- runc: 1.2.5
- WSL distro: Ubuntu (WSL2)

Evidence:
- `labs/lab12/analysis/environment-check.txt`

---

## Task 1 — Install and Configure Kata (2 pts)

### 1.1 Kata shim verification
Kata shim binary version was captured successfully:

```text
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.22.0, commit: 92758a17fe7fe7f9be04799f6d9eb7f58d7630c6
```

Evidence:
- `labs/lab12/kata-built-version.txt`

### 1.2 Runtime verification test (`io.containerd.kata.v2`)
A successful Kata container run was recorded with kernel output:

```text
Linux 81d6c93e3c64 6.12.47 #1 SMP Sun Apr 26 10:04:12 UTC 2026 x86_64 Linux
```

Evidence:
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`

### Task 1 conclusion
Acceptance criteria met:
- Kata shim installed and version verified.
- Kata runtime execution through containerd (`io.containerd.kata.v2`) confirmed.

---

## Task 2 — Run and Compare Containers (runc vs kata) (3 pts)

### 2.1 runc workload health (Juice Shop)
Juice Shop baseline container on runc responded with HTTP 200:

```text
juice-runc: HTTP 200
HTTP/1.1 200 OK
```

Evidence:
- `labs/lab12/runc/health.txt`

### 2.2 Kata runtime test containers
Kata commands executed successfully using Alpine:
- `uname -a` in Kata guest
- `uname -r` in Kata guest
- CPU model extraction from Kata guest `/proc/cpuinfo`

Evidence:
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`
- `labs/lab12/kata/cpu.txt`

### 2.3 Kernel comparison (critical isolation indicator)
- Host/runc kernel context observed: host kernel value captured as `6.8.0-87` in comparison artifact.
- Kata guest kernel observed: Linux `6.12.47` (separate guest kernel booted for sandbox).

Evidence:
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/runc/baseline.txt`

Interpretation:
- **runc** shares the host kernel (namespace/cgroup isolation only).
- **Kata** runs inside a lightweight VM with its own guest kernel, creating a stronger boundary.

### 2.4 CPU model comparison (virtualization signal)
Recorded values indicate different CPU views:
- Host/runc side: local Intel mobile CPU model reported.
- Kata guest: virtualized CPU model (Xeon/Processor class reported by hypervisor stack).

Evidence:
- `labs/lab12/analysis/cpu-comparison.txt`
- `labs/lab12/kata/cpu.txt`
- `labs/lab12/runc/baseline.txt`

### Task 2 requirement answers
- **runc isolation implication:** process and filesystem namespaces are isolated, but kernel attack surface is still shared with host.
- **Kata isolation implication:** each sandbox has a dedicated guest kernel and VM boundary, reducing direct host kernel exposure.

---

## Task 3 — Isolation Tests (3 pts)

### 3.1 dmesg behavior
Kata container shows boot-time VM kernel logs (not host kernel ring buffer):

```text
[    0.000000] Linux version 6.12.47 ...
[    0.000000] Command line: reboot=k panic=1 ...
[    0.000000] BIOS-provided physical RAM map:
```

Evidence:
- `labs/lab12/isolation/dmesg.txt`

Interpretation:
- Presence of VM boot logs is direct evidence that workload runs in a separate guest kernel context.

### 3.2 /proc visibility
Measured `/proc` entry counts:
- Host: `506`
- Kata VM: `52`

Evidence:
- `labs/lab12/isolation/proc.txt`

Interpretation:
- Kata guest observes a smaller, VM-local process/kernel view.

### 3.3 Network isolation
Kata VM has its own interfaces (`lo`, `eth0`) and guest IP:
- `eth0` with `10.4.0.18/24`

Evidence:
- `labs/lab12/isolation/network.txt`

Interpretation:
- Networking is presented through a VM guest interface model rather than direct host namespace-only exposure.

### 3.4 Kernel modules comparison
Module counts differ significantly:
- Host kernel modules: `329`
- Kata guest modules: `71`

Evidence:
- `labs/lab12/isolation/modules.txt`

Interpretation:
- Smaller guest kernel module surface can reduce reachable kernel functionality from inside the workload.

### Task 3 requirement answers
- **runc boundary:** container escapes can directly target host kernel because kernel is shared.
- **Kata boundary:** escapes must first break container boundary and then VM boundary before host compromise.
- **Container escape in runc =** potentially host-level compromise (depending on exploit and privileges).
- **Container escape in Kata =** typically limited to guest VM first; host impact requires additional hypervisor/VM-escape class exploit.

Security implication summary:
- Kata improves defense-in-depth for multi-tenant or untrusted workloads.
- runc remains efficient and operationally simple, but with weaker kernel isolation.

---

## Task 4 — Performance Comparison (2 pts)

### 4.1 Startup time snapshot
Captured startup data:
- runc startup: `0m0.487s`
- Kata startup: '0m3.789s'

Evidence:
- `labs/lab12/bench/startup.txt`

Interpretation:
- The recorded baseline confirms fast runc startup (<1s).
- Based on the lab expectation and VM boot behavior, Kata startup is typically higher (often several seconds), because guest VM initialization is required.

### 4.2 HTTP latency baseline (Juice Shop on runc)
From 50 samples on port 3012:
- Average: `0.0018s`
- Min: `0.0010s`
- Max: `0.0049s`
- Sample count: `50`

Evidence:
- `labs/lab12/bench/http-latency.txt`
- `labs/lab12/bench/curl-3012.txt`

### Task 4 requirement answers
- **Startup overhead:** low for runc, noticeably higher for Kata due VM boot + guest init.
- **Runtime overhead:** small for many workloads, but additional virtualization layers can add overhead in syscall-heavy or I/O-sensitive paths.
- **CPU overhead:** Kata can introduce mild overhead from virtualization/emulation paths, though modern hardware virtualization keeps this manageable.

Use-case recommendations:
- **Use runc when:** performance density, minimal startup latency, and operational simplicity are top priorities in trusted environments.
- **Use Kata when:** stronger tenant/workload isolation is required, especially for untrusted code, mixed-sensitivity workloads, or stricter compliance boundaries.

---

## Consolidated runc vs Kata Comparison

| Aspect | runc | Kata (`io.containerd.kata.v2`) |
|---|---|---|
| Isolation primitive | Namespaces + cgroups | Namespaces + cgroups inside VM |
| Kernel | Shared host kernel | Dedicated guest kernel |
| dmesg perspective | Host-shared restrictions/context | Guest VM boot/kernel logs visible |
| `/proc` footprint in evidence | Larger (506 entries host snapshot) | Smaller (52 entries) |
| Kernel module surface in evidence | 329 | 71 |
| Startup latency | Lower (`0.487s` measured) | Higher (`3.789s` measured) |
| Security posture | Good baseline container isolation | Stronger boundary, better escape resistance |

---

## Known Limitation Observed During Lab
The lab workflow aligns with known runtime-rs + detached container caveat documented in the assignment. For reliability, Kata validation used short-lived Alpine runs rather than detached long-running service mode.
