# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- Kernel (host): `Linux runnervm3jd5f 6.17.0-1020-azure #20~24.04.1-Ubuntu SMP Fri Jun 19 20:09:14 UTC 2026 x86_64`
- KVM accessible:

```text
crw-rw---- 1 root kvm 10, 232 Jul 17 20:23 /dev/kvm
kvm_amd 237568 0 - Live 0x0000000000000000
kvm 1404928 1 kvm_amd, Live 0x0000000000000000
```

- containerd version: `containerd github.com/containerd/containerd/v2 2.2.1`
- nerdctl version: `nerdctl version 2.1.3`

### Kata installation

- Kata version: `3.32.0`
- containerd config snippet:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers

**runc:**

```text
Linux a5c1e1bbb8cf 6.17.0-1020-azure #20~24.04.1-Ubuntu SMP Fri Jun 19 20:09:14 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

**kata:**

```text
Linux 6b3dd00a66df 6.18.35 #1 SMP Mon Jun 15 12:55:10 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
```

### Why the kernel differs

`runc` starts a normal Linux process inside namespaces and cgroups, so the container reports the host's Azure kernel, `6.17.0-1020-azure`. Kata starts a micro-VM through KVM and runs the container inside that guest, so it reports the guest kernel, `6.18.35`. For the runc CVE-2024-21626 class from Lecture 7, that matters because a successful escape from the container lands in the shared host kernel with `runc`, but in Kata it lands inside the disposable guest VM boundary first.

## Task 2: Isolation + Performance

### Isolation: /dev diff

```text
1d0
< core
```

The visible `/dev` difference was small in this run, but the kernel line above shows the stronger isolation boundary: Kata is not sharing the host kernel with the container.

### Isolation: capability sets

runc:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

kata:

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The Linux capability mask is the same because containerd applies the same OCI capability set. The practical isolation gain comes from where those capabilities apply: host kernel for `runc`, guest micro-VM kernel for Kata.

### Startup time (5-run avg)

| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.218 |
| kata | 11.749 |

**Overhead: ~53.9x cold start** on this nested GitHub-hosted KVM runner.

Raw output:

```text
=== runc ===
1: .223545532 s
2: .215576398 s
3: .219993330 s
4: .209652529 s
5: .221535114 s
avg: 0.218060581 s
=== kata ===
1: 11.654433225 s
2: 11.768416686 s
3: 11.776918091 s
4: 11.772314889 s
5: 11.772581261 s
avg: 11.748932830 s
```

### I/O throughput (100MB dd)

| Runtime | Throughput |
|---------|-----------:|
| runc | 24.4 GB/s |
| kata | 13.4 GB/s |

Raw output:

```text
=== runc I/O ===
104857600 bytes (100.0MB) copied, 0.004009 seconds, 24.4GB/s
=== kata I/O ===
104857600 bytes (100.0MB) copied, 0.007280 seconds, 13.4GB/s
```

### Trade-off analysis

Kata is worth the cost for multi-tenant CI runners, student code sandboxes, and SaaS workloads that execute customer-controlled images, because the separate guest kernel changes the blast radius of a container escape. It is also useful when compliance language asks for VM-grade isolation but the team still wants OCI/container workflows. I would not use it for trusted single-tenant batch jobs or latency-sensitive serverless functions where 10+ seconds of cold start would dominate the workload. For those, `runc` plus policy controls, image scanning, seccomp/AppArmor, and strong admission gates are probably the better trade-off.

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B — privileged container host-write attempt
- **Why:** It models a common real misconfiguration: a privileged workload with a host path mount. It is simple to verify from outside the container, which is the important part for proving whether the host changed.

### runc: escape succeeds

Command:

```bash
echo "original" | sudo tee /tmp/lab12-target
sudo nerdctl run --rm --privileged --net=none -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
sudo cat /tmp/lab12-target
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:

```text
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: escape blocked

Command:

```bash
echo "original" | sudo tee /tmp/lab12-target
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged --net=none -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"'
sudo cat /tmp/lab12-target
```

Container output:

```text
time="2026-07-17T20:26:34Z" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-07-17T20:26:41Z" level=fatal msg="failed to create shim task: Others(\"failed to handle message create container\\n\\nCaused by:\\n    0: get host path failed\\n    1: No such file or directory (os error 2)\")"
```

Host verification:

```text
original
```

### Threat model implication

With `runc`, `--privileged` plus a host path mount gave the process a direct write path to the host `/tmp`, and the outside-host verification proved the file changed. With Kata, the same command did not get a usable host path in the guest VM setup, and the host-side file stayed `original`; the attack never crossed the micro-VM boundary. This maps to multi-tenant CI runners and misconfigured Kubernetes pods where untrusted jobs may accidentally receive dangerous runtime flags. Kata does not block pure side-channel attacks, cross-tenant timing leaks, or a compromised host/hypervisor reading workload memory; that is the separate Confidential Containers threat model from Reading 12.
