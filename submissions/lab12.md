# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): Linux StefFashkaLap 6.18.33.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Fri Jun 5 01:12:21 UTC 2026 x86_64 GNU/Linux
- KVM accessible: `/dev/kvm` is not present. `ls: cannot access '/dev/kvm': No such file or directory`
- containerd version: Docker Desktop reports containerd `v2.2.4` (`193637f7ee8ae5f5aa5248f49e7baa3e6164966e`). Direct `containerd --version` and `nerdctl` were unavailable in WSL.

### Kata installation
- Kata version: NOT INSTALLED. Kata did not start because `/dev/kvm` was not exposed in WSL2 during the lab run, so the KVM-backed Kata runtime could not boot its micro-VM.
- containerd config snippet:
```toml
# NOT CONFIGURED ON THIS HOST
# Required runtime block for a KVM-enabled Linux host:
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
```
Linux 77abcded1711 6.18.33.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Fri Jun  5 01:12:21 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 26
```

**kata:**
```
NOT RUN: Kata requires a Linux host with /dev/kvm and a registered containerd runtime.
This local host is Windows + WSL2/Docker Desktop; /dev/kvm is absent in WSL and in privileged Docker containers.
See labs/lab12/results/preflight.txt.
```

### Why the kernel differs (Reading 12)
Reading 12 explains that runc containers are ordinary Linux processes sharing the host kernel, while Kata starts the workload inside a separate micro-VM with its own guest kernel. For attack classes such as runc CVE-2024-21626, a successful container escape from a Kata workload should land inside the throwaway guest VM boundary instead of the host kernel boundary. This could not be observed locally because the required KVM device is unavailable.

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
diff --git a/labs/lab12/results/runc-devs.txt b/labs/lab12/results/kata-devs.txt
index c42a695..315c466 100644
--- a/labs/lab12/results/runc-devs.txt
+++ b/labs/lab12/results/kata-devs.txt
@@ -1,15 +1 @@
-core
-fd
-full
-mqueue
-null
-ptmx
-pts
-random
-shm
-stderr
-stdin
-stdout
-tty
-urandom
-zero
+NOT RUN: Kata /dev inventory was blocked by missing KVM and unavailable nerdctl/containerd runtime registration.
```

### Isolation: capability sets
runc:
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```
kata:
```
NOT RUN: Kata capability capture was blocked by missing KVM and unavailable nerdctl/containerd runtime registration.
```

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.572 |
| kata | N/A |

**Overhead: N/A. Kata startup could not be measured because `/dev/kvm` is absent and `io.containerd.kata.v2` is not registered on this host.**

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 69.8 GB/s |
| kata | N/A |

### Trade-off analysis (3-4 sentences, Reading 12 framing)
Kata is worth the cost for untrusted multi-tenant workloads such as CI runners, code execution sandboxes, and SaaS jobs that run customer-controlled images or commands. The separate guest kernel directly reduces shared-kernel escape risk, which maps to the runc-CVE class discussed in Reading 12. It is not worth the added startup, memory, and I/O cost for trusted single-tenant services where the image supply chain and operators are controlled. For latency-sensitive short-lived jobs, gVisor or normal runc may be a better operational trade-off unless VM isolation is a hard requirement.

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B. Privileged-container host write
- **Why:** This vector demonstrates a common real-world misconfiguration: a privileged container with a writable host bind mount. It is simple, reproducible, and directly shows the isolation difference that Kata is intended to provide on a KVM-enabled host.

### runc: escape succeeds
Command:
```bash
docker run --rm --privileged --mount type=bind,source="C:\Users\stepa\Documents\Projects\DevSecOps-Intro\labs\lab12\results",target=/host_tmp alpine:3.20 sh -c 'echo OVERWRITTEN BY RUNC CONTAINER > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:
```
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:
```
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked
Command:
```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"'
```

Container output:
```
NOT RUN: The same Kata command requires io.containerd.kata.v2 and /dev/kvm. Both are unavailable on this host.
Expected security property on a KVM-enabled Kata host: the host-side verification remains "original" because the write lands inside the micro-VM filesystem boundary rather than the host filesystem.
```

Host verification:
```
NOT RUN: host verification for Kata cannot be produced without a KVM-backed Kata runtime on this machine.
```

### Threat model implication (3-4 sentences, Reading 12 framing)
Kata blocks what runc allows by placing the container process behind a micro-VM boundary with a separate guest kernel and virtualized filesystem path, commonly through virtio-fs or 9p. In the runc case, a privileged container with a writable host bind mount can modify the host-visible file directly. This maps to multi-tenant CI runners, code sandboxes, and misconfigured Kubernetes pods where user-controlled workloads may receive dangerous flags. Kata does not block pure side-channel attacks, cross-tenant timing attacks, or attacks that require confidential-computing protections for workload memory from the host.
