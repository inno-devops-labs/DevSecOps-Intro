### Task 1

```bash
$ containerd-shim-kata-v2 --version
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 8534afb9e8de3a529a537185f0fd55b66d9bc5d5
```

```bash
$ sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
[sudo] password for bulatgazizov:
WARN[0000] cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"
Linux 329d9f7433ab 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```

### Task 2

Runc:

```
juice-runc: HTTP 000
```

Kernel versions:

* runc → 6.15.4
* Kata → 6.12.47

=== CPU Model Comparison ===

* Host CPU: 12th Gen Intel(R) Core(TM) i5-12450H
* Kata VM CPU: Intel(R) Xeon(R) Processor

| Feature               | runc                              | Kata Containers                |
| :-------------------- | :-------------------------------- | :----------------------------- |
| **Primary Isolation** | Namespaces & cgroups              | Hardware virtualization (VM)   |
| **Security Boundary** | Shared host kernel                | Hypervisor with its own kernel |
| **Architecture**      | Single kernel, isolated processes | Small VMs per pod              |
| **Performance**       | Native speed                      | Nearly native, slight overhead |
| **Attack Surface**    | Larger (shared syscalls)          | Smaller (VM isolation)         |

### Task 3

#### Kata dmesg output:

```
[    0.000000] Linux version 6.12.47 (@4bcec8f4443d) ...
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target ...
[    0.000000] BIOS-provided physical RAM map:
...
```

#### /proc filesystem entries count

* Host: 528
* Kata VM: 53

#### Kata VM network configuration

```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

#### Kernel module counts

* Host: 354
* Kata VM: 72

#### Isolation boundary explanation

* **runc:** All containers rely on the same host kernel, so a kernel failure or exploit affects the entire node. Process isolation is namespace-based, but the underlying kernel is shared.

* **Kata:** Each pod runs inside a lightweight VM with its own kernel. A crash or exploit inside a Kata guest doesn't impact the host or other pods. The VM's /proc, networking stack, and kernel modules are entirely separate.

* **runc networking:** Uses network namespaces with veth pairs, still tied to the host kernel’s networking subsystem.

* **Kata networking:** Uses a virtualized network device in a separate VM, with a completely independent TCP/IP stack.

* **runc kernel exposure:** Containers see the full set of host modules (354).

* **Kata kernel exposure:** Container sees only the trimmed, hardened guest kernel (72 modules).

#### Security implications

* **runc escape:** Requires breaking Linux namespaces/cgroups, then the attacker reaches the host kernel.
* **Kata escape:** Requires compromising the minimal guest kernel *and* escaping the hypervisor — far harder.

### Task 4

#### Startup time comparison

* runc → 0.6s
* Kata → 6.6s

#### Runc HTTP latency baseline

avg=0.0003s, min=0.0001s, max=0.0005s, n=50

#### Performance tradeoffs

* **Startup overhead:** ~10× slower because Kata must boot a VM and initialize a kernel, while runc just starts a process.
* **Runtime overhead:** Typically 1–5% slower for CPU-bound tasks.
* **CPU behavior:** Minor extra cost due to hypervisor virtualization.

#### When to choose each runtime

* **Use runc when:** You need high-density workloads, very fast startup, or serverless-style deployments on trusted code.
* **Use Kata when:** Workloads are untrusted, you need strong isolation, or kernel-level vulnerabilities could cause major impact.

