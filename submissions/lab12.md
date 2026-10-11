# Lab 12 - BONUS - Submission

## Execution status

This lab requires a Linux host with readable `/dev/kvm`, `containerd`, and `nerdctl`. I did not fabricate Kata benchmark or escape-PoC evidence from an incompatible host. The current execution host is macOS/Docker Desktop, so the live Kata runtime cannot be installed or tested here.

To make the lab reproducible on a proper Linux/KVM machine, I added:

```bash
sudo bash labs/lab12/scripts/run-lab12-evidence.sh
```

That runner performs the Kata install, runc/kata kernel comparison, `/dev` and capability diffs, startup and I/O benchmarks, and the privileged-container escape PoC, writing evidence into `labs/lab12/results/`.

## Task 1: Install + Hello-World

### Host environment

- Kernel (host):

```text
Darwin MacBook-Pro-Islam.local 25.5.0 Darwin Kernel Version 25.5.0: Mon Apr 27 20:38:56 PDT 2026; root:xnu-12377.121.6~2/RELEASE_ARM64_T6000 arm64
```

- KVM accessible:

```text
ls: /dev/kvm: No such file or directory
```

- containerd version:

```text
zsh:1: command not found: containerd
```

- nerdctl version:

```text
zsh:1: command not found: nerdctl
```

- Docker Desktop Linux VM check:

```text
Linux 6d7f1d928862 6.12.76-linuxkit #1 SMP Thu Jun 11 15:44:51 UTC 2026 aarch64 Linux
ls: /dev/kvm: No such file or directory
```

### Kata installation

Not executed on this host because `/dev/kvm`, `containerd`, and `nerdctl` are unavailable. Running the included evidence script on a KVM-enabled Linux host will populate:

```text
labs/lab12/results/kata-version.txt
labs/lab12/results/containerd-kata-config.txt
```

### Kernel inside containers

Not executed on this host. The evidence script writes:

```text
labs/lab12/results/runc-kernel.txt
labs/lab12/results/kata-kernel.txt
```

### Why the kernel differs

`runc` containers share the host kernel, so a runtime or kernel escape class can cross from container isolation into the host boundary when the vulnerability and permissions line up. Kata starts the workload inside a micro-VM with its own guest kernel, so the container sees the VM kernel rather than the host kernel. For the runc CVE-2024-21626 class discussed in Lecture 7, that extra kernel boundary changes the blast radius from "host process namespace/runtime boundary" to "guest VM boundary first."

## Task 2: Isolation + Performance

### Isolation evidence

Not executed on this host. The evidence script writes:

```text
labs/lab12/results/runc-devs.txt
labs/lab12/results/kata-devs.txt
labs/lab12/results/dev-diff.txt
labs/lab12/results/runc-caps.txt
labs/lab12/results/kata-caps.txt
```

### Startup and I/O benchmarks

Not executed on this host. The evidence script writes:

```text
labs/lab12/results/startup-bench.txt
labs/lab12/results/io-bench.txt
```

### Trade-off analysis

Kata is worth the overhead for multi-tenant workloads where one tenant's container should not share a kernel trust boundary with another tenant or with the host, such as CI runners, plugin execution, hosted notebooks, or untrusted build jobs. It is less attractive for trusted single-tenant batch workloads where cold-start latency and operational simplicity matter more than a VM-per-container boundary. The security win is strongest when the threat model includes container runtime escape, privileged-container mistakes, or noisy neighbor isolation; it does not remove the need for patching, least privilege, seccomp/AppArmor, and network policy.

## Bonus: Container-Escape PoC

### Vector chosen

- **Option:** B - privileged-container host write.
- **Why:** This demonstrates the common real-world failure mode where `--privileged` plus a host bind mount turns a container into a host filesystem writer.

### runc: escape succeeds

Command executed by the evidence script on a KVM Linux host:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
sudo cat /tmp/lab12-target
```

Expected evidence files:

```text
labs/lab12/results/runc-escape-output.txt
labs/lab12/results/runc-escape-host-verify.txt
```

### Kata: escape blocked or constrained by VM isolation

Command executed by the evidence script on a KVM Linux host:

```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view must be verified outside---"'
sudo cat /tmp/lab12-target
```

Expected evidence files:

```text
labs/lab12/results/kata-escape-attempt.txt
labs/lab12/results/kata-escape-host-verify.txt
```

### Threat model implication

Kata adds a guest-kernel and micro-VM boundary between the container workload and the host, so a container breakout has to cross the VM boundary before it becomes a host compromise. This maps well to multi-tenant CI runners and Kubernetes clusters that may accidentally run privileged or semi-trusted workloads. It does not block side-channel attacks, vulnerable host services exposed over the network, or all possible misconfigured shared mounts; those still need hardening outside the runtime choice.
