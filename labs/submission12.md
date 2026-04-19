# Lab 12 — Kata Containers: VM-backed Container Sandboxing

## Overview

This lab explores VM-backed container isolation using Kata Containers and compares it with the default `runc` runtime. The goal was to understand differences in isolation, security boundaries, and performance trade-offs.

## Task 1 — Install and Configure Kata

### Kata Shim Verification

```
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.28.0, commit: 880d4aa6445ba35b8c435abc27b399582758ea52
```

### Test Run with Kata Runtime

```
Linux 7f5b2a8e2e7b 6.12.47 #1 SMP Mon Mar 16 08:35:04 UTC 2026 x86_64 Linux
```

Kata runtime (`io.containerd.kata.v2`) is correctly installed and functional.

## Task 2 — Run and Compare Containers (runc vs kata)

### runc Container (Juice Shop)

```
juice-runc: HTTP 200
```

The application is reachable and working correctly.

### Kata Container Execution

```
uname -a:
Linux ... 6.12.47 ...

uname -r:
6.12.47

CPU:
Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz
```

### Kernel Comparison

```
Host kernel (runc uses this): 6.17.0-19-generic
Kata guest kernel: Linux version 6.12.47 ...
```

### Key Finding
- runc uses the host kernel directly
- Kata runs a separate guest kernel inside a VM

### CPU Comparison

```
Host CPU:
Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz

Kata VM CPU:
Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz
```

### Interpretation
- runc exposes real hardware CPU
- Kata exposes a virtualized CPU model

### Isolation Implications

**runc**
- Shares host kernel
- Uses namespaces and cgroups for isolation
- Processes rely on host OS security

**Kata**
- Each container runs inside a lightweight VM
- Has its own kernel and virtual hardware
- Stronger isolation boundary (hardware virtualization)

## Task 3 — Isolation Tests

### dmesg Output

```
[    0.000000] Linux version 6.12.47 ...
[    0.000000] Command line: ...
```

### Observation

Kata shows VM boot logs, proving it runs a separate kernel.

### /proc Filesystem Comparison

```
Host: 622 entries
Kata VM: 54 entries
```

### Interpretation
- runc exposes a large portion of host /proc
- Kata provides a minimal, isolated /proc

### Network Interfaces

```
lo (loopback)
eth0 (private VM interface)
```

### Interpretation
- Kata container has its own virtual network stack
- Fully isolated from host networking internals

### Kernel Modules

```
Host kernel modules: 312
Kata guest kernel modules: 72
```

### Interpretation
- Kata runs a minimal kernel
- Reduced attack surface compared to host kernel

### Isolation Boundary Differences
**runc**
- Isolation via:
  - namespaces
  - cgroups
- Shares kernel → weaker boundary

**Kata**
- Isolation via:
  - hardware virtualization (VM)
  - separate kernel
- Strong boundary between host and container

### Security Implications

**runc**
- Container escape -> direct access to host kernel
- High risk if kernel vulnerability exists

**Kata**
- Container escape -> must also break out of VM
- Adds an additional security layer
- Significantly reduces risk of host compromise

## Task 4 — Performance Comparison

### Startup Time

```
runc:
real 0m0.758s

Kata:
real 0m3.248s
```

### Interpretation
- runc starts almost instantly
- Kata has ~3–4x slower startup due to VM boot


### HTTP Latency (runc baseline)

```
avg = 0.0049s
min = 0.0031s
max = 0.0116s
n = 50
```

### Interpretation
- Very low latency
- No noticeable overhead for standard containers

### Performance Trade-offs

**Startup Overhead**
- runc: very fast (<1s)
- Kata: slower (3–5s due to VM initialization)

**Runtime Overhead**
- runc: minimal
- Kata: slight overhead due to virtualization

**CPU Overhead**
- runc: near-native performance
- Kata: minor overhead from hypervisor layer

### When to Use Each Runtime

**Use runc when:**
- Performance is critical
- Fast startup is required
- Workloads are trusted
- High density is needed

**Use Kata when:**
- Strong isolation is required
- Running untrusted or multi-tenant workloads
- Security is more important than performance
- Protecting host from container escape is critical

## Final Conclusion

Kata Containers provide significantly stronger isolation by introducing a VM boundary per container. This improves security but comes with increased startup time and slight runtime overhead.

- **runc** = performance & efficiency
- **Kata** = security & isolation

The choice depends on workload requirements and threat model.