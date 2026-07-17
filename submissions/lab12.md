# Lab 12 — BONUS — Submission



## Task 1: Install + Hello-World



### Host environment

\- Kernel (host): Linux lab12-host 6.5.0-14-generic #14-Ubuntu SMP PREEMPT\_DYNAMIC

\- KVM accessible: crw-rw---- 1 root kvm 10, 232 Jul 17 10:00 /dev/kvm

\- containerd version: containerd github.com/containerd/containerd v1.7.13



### Kata installation

\- Kata version: 3.2.0

\- containerd config snippet:

```toml

\[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]

&#x20; runtime\_type = 'io.containerd.kata.v2'

```



### Kernel inside containers

\*\*runc:\*\*

```

Linux 6f8a9b1c2d3e 6.5.0-14-generic #14-Ubuntu SMP PREEMPT\_DYNAMIC x86\_64 Linux

processor       : 0

vendor\_id       : GenuineIntel

```



\*\*kata:\*\*

```

Linux 0a1b2c3d4e5f 6.1.38 #1 SMP Tue Jul 17 10:00:00 UTC 2026 x86\_64 GNU/Linux

processor       : 0

vendor\_id       : GenuineIntel

```



### Why the kernel differs (Reading 12)

Reading 12 explains the model. Reference Lecture 7 slide 14 — runc CVE-2024-21626 ("Leaky Vessels").

With runc, containers share the host kernel, so a kernel exploit or runtime CVE like "Leaky Vessels" can directly escape to the host. Kata Containers runs each pod inside a lightweight VM with its own independent guest kernel, meaning an exploit against the container runtime hits the VM boundary, not the host kernel.



---



## Task 2: Isolation + Performance



### Isolation: /dev diff

```diff

< /dev/full

< /dev/fuse

< /dev/kvm

< /dev/mqueue

< /dev/net/tun

< /dev/ptmx

< /dev/random

< /dev/rtc

< /dev/rtc0

< /dev/sgx\_enclave

< /dev/sgx\_provision

< /dev/snapshot

< /dev/sockname

< /dev/tty

\---

> /dev/console

> /dev/kmsg

> /dev/null

> /dev/ptmx

> /dev/random

> /dev/tty

> /dev/urandom

> /dev/zero

```



### Isolation: capability sets

runc:

```

CapInh: 0000000000000000

CapPrm: 00000000a80425fb

CapEff: 00000000a80425fb

CapBnd: 00000000a80425fb

```

kata:

```

CapInh: 0000000000000000

CapPrm: 00000000a80425fb

CapEff: 00000000a80425fb

CapBnd: 00000000a80425fb

```


### Startup time (5-run avg)

| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.42 |
| kata | 2.15 |



\*\*Overhead: \~5.1x cold start (expected \~5x per Reading 12 table)\*\*



### I/O throughput (100MB dd)

| Runtime | Throughput |
|---------|-----------|
| runc | 12.4 GB/s |
| kata | 1.3 GB/s |



### Trade-off analysis (3-4 sentences, Reading 12 framing)

The security gain of a separate kernel is worth the cost for multi-tenant SaaS workloads or untrusted CI/CD runners where container escape CVEs pose a direct cross-tenant breach risk. It isn't worth the cost for single-tenant batch jobs or trusted internal microservices where the 5x startup latency and I/O overhead severely degrade performance without a proportional threat model justification.



---



## Bonus: Container-Escape PoC



### Vector chosen

\- \*\*Option:\*\* B (Privileged-container host write)

\- \*\*Why:\*\* It's the simplest to demonstrate, the underlying threat model is the most common (misconfigured --privileged in real workloads), and the contrast with Kata is the most visible.



### runc: escape succeeds

Command:

```bash

sudo nerdctl run --rm --privileged -v /tmp:/host\_tmp alpine:3.20 \\

&#x20; sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host\_tmp/lab12-target \&\& cat /host\_tmp/lab12-target'

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

sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host\_tmp alpine:3.20 \\

&#x20; sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host\_tmp/lab12-target 2>\&1 \&\& cat /host\_tmp/lab12-target; echo "---host view---"' 2>\&1 \\

&#x20; | tee labs/lab12/results/kata-escape-attempt.txt

```



Container output:

```

ATTEMPTED OVERWRITE FROM KATA

---host view---

```



Host verification:

```

original

```



### Threat model implication (3-4 sentences, Reading 12 framing)

Kata blocks what runc allows because Kata's micro-VM filesystem IS NOT the host filesystem — bind mounts are virtualized via virtio-fs/9p inside the VM, so writing to `/host\_tmp` only affects the VM's temporary view, not the actual host `/tmp`. This maps directly to multi-tenant CI runners running `--privileged` containers or misconfigured Kubernetes pods, where a compromised container could tamper with host binaries. This does NOT block pure side-channel attacks on the kernel itself or cross-tenant timing attacks; Reading 12's "Confidential Containers" section is where THOSE get defenses.

