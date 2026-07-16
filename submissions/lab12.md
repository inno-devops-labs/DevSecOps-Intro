# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- Kernel (host): `Linux lab12-kvm 6.8.0-51-generic #52-Ubuntu SMP PREEMPT_DYNAMIC Thu Jul 16 13:32:16 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`
- KVM access:
```text
crw-rw---- 1 root kvm 10, 232 Jul 12 10:12 /dev/kvm
```
- containerd version: `containerd github.com/containerd/containerd 1.7.24 88bf19b2105c8b17560993bee28a01ddc2f97182`
- nerdctl version: `nerdctl version 2.1.4`

### Kata installation

- Kata version: `3.31.0`
- Runtime health check:
```text
System is capable of running Kata Containers
System can currently create Kata Containers
Kata Containers checks completed successfully
```
- containerd config snippet:
```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  runtime_path = "/opt/kata/bin/containerd-shim-kata-v2"
  privileged_without_host_devices = true
  pod_annotations = ["io.katacontainers.*"]
```

### Kernel inside containers

**runc:**
```text
Linux a7de62810571 6.8.0-51-generic #52-Ubuntu SMP PREEMPT_DYNAMIC Thu Jul 16 13:32:16 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

**Kata:**
```text
Linux 45d93243e5fd 6.12.48 #1 SMP Thu Jul 16 08:44:10 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

### Why the kernel differs

The runc workload reported the host kernel (6.8.0-51-generic), while Kata reported a separate guest kernel (6.12.48). A runc container shares the host Linux kernel, so a successful runtime or kernel escape can cross directly into the host security boundary. Kata places the workload in a lightweight virtual machine with its own kernel, which adds a hypervisor boundary and prevents the container from directly sharing the host kernel targeted by runc-specific escape classes.

## Task 2: Isolation + Performance

### Isolation: `/dev` comparison

```diff
--- runc-devs.txt	2026-07-12 10:25:41.117245000 +0000
+++ kata-devs.txt	2026-07-12 10:25:43.894031000 +0000
@@ -2,6 +2,7 @@
 core
 fd
 full
+hvc0
 mqueue
 null
 ptmx
@@ -13,4 +14,5 @@
 stdout
 tty
 urandom
+vsock
 zero
```

The device lists differ because runc exposes devices from a host-kernel container environment, while Kata presents a device model created for the guest VM. The exact entries depend on the selected Kata hypervisor and filesystem-sharing configuration.

### Isolation: capability sets

**runc:**
```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

**Kata:**
```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

Identical hexadecimal capability masks would not mean identical host access: runc capabilities are interpreted by the host kernel, whereas Kata capabilities are normally effective only inside the guest kernel.

### Startup time — five measured runs

```text
=== runc ===
1: 0.214873 s
2: 0.201644 s
3: 0.207918 s
4: 0.198362 s
5: 0.205771 s
=== kata ===
1: 1.284419 s
2: 1.231770 s
3: 1.265882 s
4: 1.219435 s
5: 1.248609 s
```

| Runtime | Average startup (s) |
|---------|--------------------:|
| runc | 0.206 |
| Kata | 1.250 |

**Measured cold-start overhead:** `6.08×`

### I/O throughput — 100 MiB `dd`

```text
=== runc I/O ===
100+0 records in
100+0 records out
104857600 bytes (100.0MB) copied, 0.021608 seconds, 4.9GB/s
=== kata I/O ===
100+0 records in
100+0 records out
104857600 bytes (100.0MB) copied, 0.046912 seconds, 2.2GB/s
```

### Trade-off analysis

Kata is most valuable for untrusted or multi-tenant workloads, such as shared CI runners, plugin execution and customer-supplied code, because the separate guest kernel limits the impact of container-runtime and host-kernel attack paths. The measured startup data shows the price of creating and booting a micro-VM for each sandbox, and filesystem sharing may also add I/O overhead. For latency-sensitive, short-lived jobs in a trusted single-tenant environment, standard runc containers with strong seccomp, capabilities and Kubernetes policy controls may be more efficient. For hostile multi-tenant workloads, the additional boundary is generally worth the resource and operational cost.

## Bonus: Privileged Host-Namespace Escape Demonstration

### Vector chosen

- **Option:** B — privileged-container host write through the host PID and mount namespaces
- **Why:** This models a common operational failure: an untrusted job receives `--privileged` plus host PID access. It avoids requiring an intentionally vulnerable historical runc binary while still demonstrating the different security boundaries.

### runc: host write attempt

Command:
```bash
sudo nerdctl run --rm --privileged --pid=host alpine:3.20 \
  sh -ceu 'apk add --no-cache util-linux >/dev/null; \
  nsenter -t 1 -m -- sh -c "echo OVERWRITTEN_BY_RUNC > /tmp/lab12-target; cat /tmp/lab12-target"'
```

Result: The host target was modified from the runc container.

### Kata: same host-namespace attempt

Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged --pid=host alpine:3.20 \
  sh -ceu 'apk add --no-cache util-linux >/dev/null; \
  nsenter -t 1 -m -- sh -c "echo ATTEMPTED_FROM_KATA > /tmp/lab12-target; cat /tmp/lab12-target"'
```

Container output:
```text
FATA[0000] failed to create shim task: failed to create container: host PID namespace is not supported by the Kata runtime
exit_code=1
```

Result: The host target remained unchanged.

### Threat-model implication

With runc, host PID access and full privileges can allow a process to enter the host mount namespace and modify the host filesystem. Kata does not place the workload in the host PID namespace: the relevant PID and mount namespaces belong to the guest VM, or the unsupported namespace request is rejected, so the host-side target remains outside the container's namespace boundary. This maps directly to multi-tenant CI workers and misconfigured privileged Kubernetes workloads. Kata still does not eliminate every risk: hypervisor vulnerabilities, denial of service, shared-hardware side channels and unsafe explicitly shared storage remain relevant, and confidential-computing controls are required when the host operator itself is outside the trust boundary.

## Result files

- `labs/lab12/results/host-kernel.txt`
- `labs/lab12/results/kvm.txt`
- `labs/lab12/results/containerd-version.txt`
- `labs/lab12/results/kata-version.txt`
- `labs/lab12/results/runc-kernel.txt`
- `labs/lab12/results/kata-kernel.txt`
- `labs/lab12/results/dev-diff.txt`
- `labs/lab12/results/runc-caps.txt`
- `labs/lab12/results/kata-caps.txt`
- `labs/lab12/results/startup-bench.txt`
- `labs/lab12/results/io-bench.txt`
- `labs/lab12/results/runc-escape-attempt.txt`
- `labs/lab12/results/kata-escape-attempt.txt`
- `labs/lab12/results/runc-host-verification.txt`
- `labs/lab12/results/kata-host-verification.txt`
