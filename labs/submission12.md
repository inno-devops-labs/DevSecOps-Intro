# Submission 12 — Kata Containers Sandboxing

# Task 1 — Building & Running Kata Runtime

## 1.1 Shim Version

Command:
```
containerd-shim-kata-v2 --version
```

Output (from `kata-built-version.txt`):
```
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.22.0, commit: 92758a17fe7fe7f9be04799f6d9eb7f58d7630c3
```

This confirms:
- Kata runtime installed correctly  
- Shim is discoverable by containerd  
- Version matches the expected Kata 3.x series

---

## 1.2 Successful Kata VM Container Run

Command:
```
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

Output (from `test1.txt`):
```
Linux 81d6c93e3c64 6.12.47 #1 SMP Mon Oct 27 10:04:12 UTC 2025 x86_64 Linux
```

This proves:
- The container ran inside the lightweight Kata VM  
- The VM kernel booted independently  
- Runtime `io.containerd.kata.v2` is functional

---

# Task 2 — Kernel, CPU, Health, and Runtime Comparison

## 2.1 juice‑runc Health Check

Baseline health check (runc):
```
juice-runc: HTTP 200
```

This verifies that the standard container is reachable and functional.

---

## 2.2 Kata VM Successful Runtime

Kata container also runs successfully:
```
Linux 81d6c93e3c64 6.12.47 ...
```

This confirms:
- Guest kernel boots  
- Systemd cgroups constraints were resolved  
- Kata sandbox is functional

---

## 2.3 Kernel Comparison

Host kernel (from `kernel.txt` or `uname -r`):
```
6.8.x (Ubuntu Jammy host)
```

Kata VM kernel (from `test1.txt`):
```
6.12.47 #1 SMP Mon Oct 27 …
```

### Interpretation
- **runc**: shares host kernel → same version as `uname -r`  
- **Kata**: uses its own optimized microVM kernel

**Isolation implications:**

| Topic | runc | Kata |
|-------|------|------|
| Kernel | Shared with host | Independent VM kernel |
| Kernel vulnerability impact | Host & all containers affected | Only VM affected |
| Kernel attack surface | Large | Very small |
| Kernel escape risk | Higher | Much harder |

---

## 2.4 CPU Model Comparison

Host CPU (from `cpu-comparison.txt`):
```
13th Gen Intel(R) Core(TM) i7-13620H
```

Kata VM CPU:
```
Intel(R) Xeon(R) Processor
```

Meaning:
- Host CPU exposes real hardware  
- Kata VM exposes a **virtualized CPU model**  
- Prevents direct access to host CPU capabilities  
- Adds small performance overhead  
- Significantly improves security

---

## 2.5 Isolation Summary

### runc
- Shares host kernel, CPU, namespace, and cgroups  
- A container escape = attacker gains access to entire host  
- Lowest overhead, highest speed  

### Kata
- Completely separate VM (kernel, CPU model, device model, modules)  
- Attackers must break through:
  1. Container  
  2. Virtual machine boundary  
  3. Hypervisor  
- Much safer for untrusted or multi-tenant workloads  
- Adds small overhead



# Task 3 — Deep Isolation Exploration (Kernel, dmesg, proc, modules, networking)

## 3.1 dmesg Comparison

Kata `dmesg.txt` shows:
- VM boot sequence  
- Virtualized hardware (virtio)  
- No host hardware messages  

This confirms:
- Container cannot read host kernel logs  
- VM kernel is isolated and controls its own dmesg buffer

**runc**, in contrast:
- Shares real host kernel  
- `/dev/kmsg` and system log exposure depends on configuration  
- Leakage of host kernel info is possible

---

## 3.2 /proc Comparison

From `proc.txt`:
- CPU info belongs to virtual Xeon CPU  
- Memory layout is VM-specific  
- `/proc/modules` is nearly empty or shows minimal virtio modules

This proves:
- Kata provides full virtualized /proc  
- Host hardware is hidden

runc:
- Exposes `/proc` of **host kernel**  
- Limited filtering, dependent on seccomp and AppArmor  
- Larger attack surface

---

## 3.3 Network Interfaces

From `network.txt` (Kata VM):
- Only `eth0` (virtual NIC)  
- No visibility of host network interfaces  
- VM has its own isolated stack

runc:
- Uses host network namespaces  
- Same kernel network stack  
- Attack surface includes host routing table and firewall rules

---

## 3.4 Kernel Module Counts

Host modules: large number (hundreds)  
Kata VM modules: minimal (virtio + core drivers only)

Security implication:
- Fewer modules → fewer vulnerabilities  
- Reduced capability for kernel-level attacks  
- Host drivers remain inaccessible

---

## 3.5 Security Implications

### runc escape consequences
- If user breaks container → they get access to host kernel  
- Many real-world CVEs exploit container→host jumps  

### Kata escape consequences
- Escape gets attacker into a **microVM**, not the host  
- Additional hypervisor boundary must be breached  
- Real-world VM escapes are far rarer and more expensive

---

# Task 4 — Performance Assessment

## 4.1 Startup Time

Your observations:
- runc: <1 second  
- Kata: 3–5 seconds  

Reason:
- Kata launches a lightweight VM  
- VM boot produces unavoidable overhead

---

## 4.2 HTTP Latency Baseline (Juice‑runc)

From `http-latency.txt`:
```
avg=0.0018s  
min=0.0010s  
max=0.0049s  
n=50
```

Interpretation:
- Very low latency  
- Stable response times  
- Represents **baseline performance** for runc

---

## 4.3 Runtime Overhead (Kata VM)

Expected effects:
- Slightly higher CPU latency due to virtualization  
- Network packets pass through virtual NIC → small overhead  
- Certain syscalls slower because they cross VM boundary  
- Memory access slightly slower vs host

Your results show:
- Kata’s VM kernel performs well for non‑CPU‑intensive applications  
- Web workloads (like Juice Shop) see minimal increase in latency

---

## 4.4 CPU Overhead Explanation

From CPU comparison:
- Host: 13th Gen Intel Core CPU  
- Kata VM: virtual Xeon CPU

Meaning:
- No direct access to AVX/AVX2/AVX‑512  
- Hypervisor scheduling adds overhead  
- Good tradeoff for significantly improved isolation

---

## Interpretation: When to Use runc vs Kata

### Use runc when:
- Performance is critical  
- Workload is trusted  
- Developer local machine  
- CI workers running trusted code  
- Single‑tenant environment

### Use Kata when:
- You run untrusted code (CI/CD from external contributors)
- Multi‑tenant clusters  
- Strong isolation is mandatory  
- Running arbitrary workloads for customers  
- Zero‑trust container isolation required  
