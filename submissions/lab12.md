# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

* Host kernel: `Linux zenbook 7.0.0-27-generic #27-Ubuntu SMP PREEMPT_DYNAMIC Thu Jun 18 19:13:49 UTC 2026 x86_64 GNU/Linux`
* KVM availability: `crw-rw----+ 1 root kvm 10, 232 Jul 15 12:55 /dev/kvm`
* containerd version: `containerd containerd v2.2.6 11ce9d5f3c68c941867e82890e93e815c1304f1b`

### Kata installation

* Kata version: `3.32.0`

* containerd runtime configuration:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
```

### Kernel inside containers

**runc**

```text
Linux 5d9b1c2f84ae 7.0.0-27-generic #27-Ubuntu SMP PREEMPT_DYNAMIC Thu Jun 18 19:13:49 UTC 2026 x86_64 Linux
processor    : 0
vendor_id    : GenuineIntel
cpu family   : 6
```

**kata**

```text
Linux a18c4d79e2fb 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor    : 0
vendor_id    : GenuineIntel
cpu family   : 6
```

### Why the kernel differs (Reading 12)

A container running with **runc** executes directly on the host kernel, so the kernel version reported from inside the container matches the host. **Kata Containers** starts a lightweight virtual machine for every container, therefore processes run on a separate guest kernel. This additional isolation significantly reduces the impact of runtime escape vulnerabilities such as the class represented by CVE-2024-21626, because compromising the guest environment does not immediately provide access to the host kernel.

## Task 2: Isolation + Performance

### Isolation: `/dev` comparison

```text
1d0
< core
```

The observed difference is expected because Kata exposes a virtualized device set inside its microVM rather than the host's complete `/dev` hierarchy.

### Capability sets

**runc**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

**kata**

```text
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

The capability masks are identical. Kata improves security primarily through kernel and VM isolation instead of reducing Linux capabilities by default.

### Startup benchmark

| Runtime | Average startup time (s) |
| ------- | -----------------------: |
| runc    |             0.641 |
| kata    |             2.281 |

Measured cold-start overhead is approximately **3.56×**.

Although Reading 12 mentions an overhead close to **5×**, actual values depend on hardware, virtualization support, and workload size.

### I/O benchmark

| Runtime |   Throughput |
| ------- | -----------: |
| runc    | 6.8 GB/s |
| kata    | 10.9 GB/s |

The benchmark writes data to `/dev/null`, so storage is not the bottleneck. The results therefore mainly reflect CPU and virtualization overhead rather than real disk performance.

### Trade-off analysis

Kata Containers are a strong choice when executing untrusted workloads, for example in shared CI/CD infrastructure or multi-tenant cloud platforms, where preventing container escapes is more important than minimizing startup latency. The VM boundary provides protection against attacks that rely on sharing the host kernel. For trusted applications running in dedicated environments, standard `runc` containers are usually more efficient because they start faster and introduce less virtualization overhead. The additional security provided by Kata comes at the cost of increased startup time and resource consumption.

## Bonus: Container-Escape PoC

### Selected escape vector

**Option:** B — privileged container with a bind mount.

**Reason:** This scenario is easy to reproduce and demonstrates a common real-world misconfiguration. It clearly highlights the behavioral difference between a traditional OCI runtime and a VM-based runtime.

### runc: escape succeeds

Command:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:

```text
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape attempt

Command:

```bash
sudo nerdctl run --rm \
  --runtime=io.containerd.kata.v2 \
  --privileged \
  -v /tmp:/host_tmp \
  alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target; cat /host_tmp/lab12-target'
```

Container output:

```text
time="2026-07-15T23:01:46+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-15T23:01:48+03:00" level=fatal msg="failed to create shim task: Creating container device LinuxDevice { path: \"/dev/full\", typ: C, major: 1, minor: 7, file_mode: Some(438), uid: Some(0), gid: Some(0) }\n\nCaused by:\n    EEXIST: File exists\n\nStack backtrace: ..."
```

In this environment the Kata container does not start successfully because the runtime fails while creating virtual devices inside the microVM. As a result, the overwrite operation is never performed against the host filesystem.

Host verification:

```text
original
```

### Threat model implication

Unlike `runc`, Kata executes the workload inside an isolated virtual machine. Even when a privileged container is requested, the process interacts with resources exposed to the guest VM rather than directly with the host operating system. This substantially limits the impact of configuration mistakes such as running privileged workloads in shared environments, including multi-tenant Kubernetes clusters and CI runners. However, Kata is not a universal defense: it does not eliminate hardware side-channel attacks or vulnerabilities in the underlying hypervisor, which require additional protection mechanisms such as Confidential Containers or hardware-backed trusted execution technologies.
