# Submission 12 — Kata Containers: VM-backed Container Sandboxing

## Student
- Name: Stepan Dementev
- Date: 11.05.2026
- Course: DevSecOps Intro

---

## Environment
- Host OS: Linux (Ubuntu kernel 7.0.0-15-generic)
- Hypervisor: KVM
- Toolchain: containerd + nerdctl + Kata runtime (io.containerd.kata.v2)

---

## Task 1 — Install and Configure Kata (2 pts)

### 1.1 Kata shim build/install evidence
I built and installed the Kata shim for containerd and confirmed the installed version.

Evidence:
- labs/lab12/setup/kata-built-version.txt

Observed:
- containerd-shim-kata-v2 3.20.0
- Runtime: rust

### 1.2 containerd runtime configuration
I configured containerd to include Kata runtime type io.containerd.kata.v2.

Configuration script:
- labs/lab12/scripts/configure-containerd-kata.sh

Kata test run evidence:
- labs/lab12/setup/kata-test-run.txt

Task 1 conclusion:
- Kata shim is installed and version is verified.
- containerd runtime mapping for Kata is configured.
- Test command with --runtime io.containerd.kata.v2 returns expected Linux guest output.

---

## Task 2 — Run and Compare Containers (runc vs kata) (3 pts)

### 2.1 runc (Juice Shop) health
Evidence:
- labs/lab12/runc/health.txt

Result:
- juice-runc: HTTP 200

### 2.2 Kata Alpine tests
Evidence:
- labs/lab12/kata/test1.txt
- labs/lab12/kata/kernel.txt
- labs/lab12/kata/cpu.txt

Results:
- Kata containers run successfully with runtime io.containerd.kata.v2.
- Guest kernel: 6.12.47-52.
- CPU model is virtualized (QEMU Virtual CPU).

### 2.3 Kernel comparison
Evidence:
- labs/lab12/analysis/kernel-comparison.txt

Summary:
- runc uses host kernel (same as uname -r on host).
- Kata uses a separate guest kernel inside the VM sandbox.

### 2.4 CPU model comparison
Evidence:
- labs/lab12/analysis/cpu-comparison.txt

Summary:
- Host CPU model is physical AMD Ryzen.
- Kata guest CPU model appears as virtual CPU, indicating hardware virtualization boundary.

Isolation implications:
- runc: namespaces/cgroups isolation, but host kernel is shared.
- Kata: per-container lightweight VM with separate kernel boundary.

---

## Task 3 — Isolation Tests (3 pts)

### 3.1 dmesg behavior
Evidence:
- labs/lab12/isolation/dmesg.txt

Observation:
- dmesg output from Kata shows VM boot sequence lines, proving separate guest kernel lifecycle.

### 3.2 /proc visibility
Evidence:
- labs/lab12/isolation/proc.txt

Observation:
- Host /proc entry count is larger than inside Kata VM.
- Guest process/kernel surface is reduced compared to host view.

### 3.3 Network interfaces in Kata
Evidence:
- labs/lab12/isolation/network.txt

Observation:
- Kata VM shows isolated loopback and guest eth0 interface with bridged/container networking.

### 3.4 Kernel modules count
Evidence:
- labs/lab12/isolation/modules.txt

Observation:
- Guest kernel exposes fewer modules than host kernel.

Isolation boundary and security implications:
- runc:
  - Container escape can directly impact host kernel attack surface.
- Kata:
  - Escape from app/container lands in guest VM first.
  - Attacker needs an additional VM-escape step to compromise host.

---

## Task 4 — Performance Comparison (2 pts)

### 4.1 Startup time comparison
Evidence:
- labs/lab12/bench/startup.txt

Result:
- runc startup: 0.43s
- Kata startup: 3.88s

Interpretation:
- Kata has higher cold-start overhead due to microVM initialization.

### 4.2 HTTP latency baseline (juice-runc)
Evidence:
- labs/lab12/bench/curl-3012.txt
- labs/lab12/bench/http-latency.txt

Result:
- avg=0.0201s min=0.0170s max=0.0240s n=50

Trade-off analysis:
- Startup overhead:
  - runc is faster.
  - Kata is slower because of guest boot.
- Runtime overhead:
  - Usually moderate, workload-dependent.
- CPU overhead:
  - Kata may add virtualization overhead depending on syscall and I/O profile.

When to use each runtime:
- Use runc when:
  - startup speed and density are top priority.
  - workload trust level is high.
- Use Kata when:
  - stronger tenant isolation is required.
  - you run untrusted or mixed-trust workloads.

---

## Acceptance Checklist
- [x] Kata shim installed and version evidence captured
- [x] Runtime io.containerd.kata.v2 setup and test evidence included
- [x] runc vs Kata comparison documented
- [x] Isolation tests executed and summarized
- [x] Performance snapshot and recommendations included
- [x] Artifacts saved under labs/lab12/

---

## Final Recommendation
Kata Containers provides a significantly stronger isolation boundary than runc by introducing a guest kernel and microVM sandbox per workload. The practical cost is higher startup latency and some operational overhead.

Recommended policy:
- Default runtime: runc for trusted internal services.
- Security-sensitive runtime: Kata for untrusted, multi-tenant, or compliance-scoped workloads.
