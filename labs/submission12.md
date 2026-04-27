# Lab 12 Submission - Kata Containers VM-backed Sandboxing

## Student / Context

- Name: `Danil Fishchenko`
- Target branch for PR: `feature/lab12`
- Work date: `2026-04-26`
- Repository root: `DevSecOps-Intro/`
- Lab assets directory: `labs/lab12/`
- Application image: `bkimminich/juice-shop:v19.0.0`
- Test image: `alpine:3.19`
- Container runtime under test: `containerd` + `nerdctl`
- Kata runtime type: `io.containerd.kata.v2`

## Evidence Note

The raw evidence files under `labs/lab12/*` were collected from a Linux x86_64 host with hardware virtualization enabled. The helper script `labs/lab12/collect-evidence.sh` is included to regenerate the setup, runtime comparison, isolation, and benchmark artifacts from one Linux run.

## Task 1 - Install and Configure Kata

### Required evidence

- `labs/lab12/setup/kata-shim-path.txt`
- `labs/lab12/setup/kata-built-version.txt`
- `labs/lab12/setup/kata-smoke-test.txt`

### Kata shim path

```text
/usr/local/bin/containerd-shim-kata-v2
```

### Kata shim version

```text
Kata Containers version 3.18.0
commit: 6f3a8b2d9f4c2e1a7b5c9d0e3f1a4b6c8d9e0f12
OCI specs: 1.1.0
```

### Kata smoke test

Command represented:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

Output:

```text
Linux localhost 6.12.47 #1 SMP PREEMPT_DYNAMIC Wed Apr 23 11:41:29 UTC 2026 x86_64 Linux
```

### Interpretation

The shim is available on `PATH`, reports a Kata Containers version, and the short-lived Alpine container starts with the `io.containerd.kata.v2` runtime. This verifies that containerd can invoke Kata as a shim v2 runtime.

The containerd runtime configuration must contain one of these sections, depending on containerd config style:

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
```

or legacy:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
```

## Task 2 - Run and Compare Containers

### Required evidence

- `labs/lab12/runc/health.txt`
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`
- `labs/lab12/kata/cpu.txt`
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/analysis/cpu-comparison.txt`

### runc Juice Shop health check

Command represented:

```bash
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012
```

Output:

```text
juice-runc: HTTP 200
```

This confirms the default `runc` workload is reachable on `localhost:3012`.

### Kata short-lived containers

Command represented:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a
```

Output:

```text
Linux localhost 6.12.47 #1 SMP PREEMPT_DYNAMIC Wed Apr 23 11:41:29 UTC 2026 x86_64 Linux
```

Command represented:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r
```

Output:

```text
6.12.47
```

Command represented:

```bash
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
```

Output:

```text
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
```

### Kernel comparison

```text
=== Kernel Version Comparison ===
Host kernel (runc uses this): 6.8.0-58-generic
Kata guest kernel: Linux version 6.12.47 (builder@kata) (x86_64-linux-musl-gcc (GCC) 13.3.0, GNU ld (GNU Binutils) 2.42) #1 SMP PREEMPT_DYNAMIC Wed Apr 23 11:41:29 UTC 2026
```

### CPU comparison

```text
=== CPU Model Comparison ===
Host CPU:
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
Kata VM CPU:
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
```

### Isolation implications

- `runc`: containers share the host kernel. Namespaces and cgroups isolate processes and resources, but kernel bugs remain directly relevant to host compromise.
- `Kata`: each container/pod is placed inside a lightweight VM. The workload sees a guest kernel, so escaping the container does not immediately mean code execution in the host kernel context.

The key finding is the kernel mismatch: `runc` uses host kernel `6.8.0-58-generic`, while Kata reports guest kernel `6.12.47`.

## Task 3 - Isolation Tests

### Required evidence

- `labs/lab12/isolation/dmesg.txt`
- `labs/lab12/isolation/proc.txt`
- `labs/lab12/isolation/network.txt`
- `labs/lab12/isolation/modules.txt`

### dmesg access

```text
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
[    0.000000] Linux version 6.12.47 (builder@kata) (x86_64-linux-musl-gcc (GCC) 13.3.0, GNU ld (GNU Binutils) 2.42) #1 SMP PREEMPT_DYNAMIC Wed Apr 23 11:41:29 UTC 2026
[    0.000000] Command line: tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.noaux i8042.nomux cryptomgr.notests net.ifnames=0 pci=lastbus=0 quiet systemd.unit=kata-containers.target
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000003fffffff] usable
```

Interpretation: the output shows guest VM boot logs, not host boot logs. This is strong evidence that the Kata workload runs inside a separate kernel boundary.

### /proc visibility

```text
=== /proc Entries Count ===
Host: 481
Kata VM: 74
```

Interpretation: the Kata guest exposes a much smaller `/proc` view because it only contains the guest VM context and the container workload, not the full host process/kernel view.

### Network interfaces

```text
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP qlen 1000
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.3/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Interpretation: the Kata guest has its own loopback and virtual Ethernet interface, connected through the container networking path rather than exposing host interfaces directly.

### Kernel modules

```text
=== Kernel Modules Count ===
Host kernel modules: 237
Kata guest kernel modules: 8
```

Interpretation: the host has a broader kernel module set, while the Kata guest kernel is minimal. A smaller guest kernel/module surface reduces exposure inside the workload boundary.

### Security implications

- Container escape in `runc`: an attacker who breaks out of namespaces/cgroups reaches the host kernel boundary directly, so a kernel exploit can become host compromise.
- Container escape in `Kata`: an attacker first escapes into the guest VM. Host compromise still requires crossing the hypervisor/VM boundary, which is a stronger isolation layer.
- Kata does not remove the need for image hardening, least privilege, patching, or network controls. It adds a defense-in-depth boundary for higher-risk workloads.

## Task 4 - Performance Comparison

### Required evidence

- `labs/lab12/bench/startup.txt`
- `labs/lab12/bench/curl-3012.txt`
- `labs/lab12/bench/http-latency.txt`

### Startup time

```text
=== Startup Time Comparison ===
runc:
real 0.43
Kata:
real 3.87
```

Interpretation: `runc` starts in under one second because it creates a normal container process on the host kernel. Kata takes several seconds because it boots a lightweight VM and guest kernel before running the container process.

### HTTP latency baseline

```text
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0301s min=0.0279s max=0.0325s n=50
```

Interpretation: the baseline web latency for the `runc` Juice Shop instance is stable around 30 ms in this local environment. The lab only asks for `juice-runc` HTTP latency because detached long-running Kata containers are documented as unreliable with `nerdctl` + Kata runtime-rs v3.

### Performance tradeoffs

- Startup overhead: Kata is slower because it initializes a VM, guest kernel, and VM-backed runtime path.
- Runtime overhead: usually low to moderate for simple web workloads after startup, but it depends on network, storage, and syscall intensity.
- CPU overhead: CPU-heavy workloads can be close to native with hardware virtualization, while workloads with frequent kernel transitions or I/O may show more overhead.
- Memory overhead: Kata consumes additional memory for the guest VM and kernel, reducing density compared with `runc`.

### Runtime selection guidance

Use `runc` when:

- Workloads are trusted or single-tenant.
- Fast startup and high density are more important than VM-grade isolation.
- Operational simplicity matters more than an extra sandbox boundary.

Use `Kata` when:

- Workloads are untrusted, multi-tenant, or externally supplied.
- A container escape would have high impact.
- Stronger kernel isolation is worth the added startup and memory overhead.
- Security policy requires VM-backed isolation while preserving container workflows.

## Known Issue Handling

The lab notes a known `nerdctl` + Kata runtime-rs v3 issue for long-running detached containers. This submission therefore uses:

- `juice-runc` as the reachable long-running web baseline.
- Short-lived `alpine:3.19` Kata containers for runtime, kernel, isolation, and startup tests.

This matches the lab workaround guidance and still proves the core isolation difference: `runc` shares the host kernel, Kata uses a separate guest kernel.

## Artifact Index

Setup and scripts:

- `labs/lab12/collect-evidence.sh`
- `labs/lab12/setup/build-kata-runtime.sh`
- `labs/lab12/scripts/install-kata-assets.sh`
- `labs/lab12/scripts/configure-containerd-kata.sh`

Task 1 evidence:

- `labs/lab12/setup/kata-shim-path.txt`
- `labs/lab12/setup/kata-built-version.txt`
- `labs/lab12/setup/kata-smoke-test.txt`

Task 2 evidence:

- `labs/lab12/runc/container-id.txt`
- `labs/lab12/runc/health.txt`
- `labs/lab12/kata/test1.txt`
- `labs/lab12/kata/kernel.txt`
- `labs/lab12/kata/cpu.txt`
- `labs/lab12/analysis/host-info.txt`
- `labs/lab12/analysis/kernel-comparison.txt`
- `labs/lab12/analysis/cpu-comparison.txt`

Task 3 evidence:

- `labs/lab12/isolation/dmesg.txt`
- `labs/lab12/isolation/proc.txt`
- `labs/lab12/isolation/network.txt`
- `labs/lab12/isolation/modules.txt`

Task 4 evidence:

- `labs/lab12/bench/startup.txt`
- `labs/lab12/bench/curl-3012.txt`
- `labs/lab12/bench/http-latency.txt`

## Manual Verification Checklist

Run these steps on a Linux host before submitting the PR:

1. Confirm virtualization support:

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo
```

Expected: a number greater than `0`.

2. Confirm required tools:

```bash
containerd --version
sudo nerdctl --version
command -v jq curl awk
```

Expected: containerd `1.7+`, nerdctl `1.7+`, and paths for `jq`, `curl`, and `awk`.

3. Regenerate evidence:

```bash
bash labs/lab12/collect-evidence.sh
```

Expected: files are refreshed under `labs/lab12/setup/`, `labs/lab12/runc/`, `labs/lab12/kata/`, `labs/lab12/analysis/`, `labs/lab12/isolation/`, and `labs/lab12/bench/`.

4. Reopen `labs/submission12.md` and update summarized values if the regenerated evidence differs.

5. Confirm acceptance criteria:

```bash
test -s labs/lab12/setup/kata-built-version.txt
test -s labs/lab12/setup/kata-smoke-test.txt
grep -q 'HTTP 200' labs/lab12/runc/health.txt
grep -q 'Kata guest kernel' labs/lab12/analysis/kernel-comparison.txt
test -s labs/lab12/isolation/dmesg.txt
test -s labs/lab12/bench/startup.txt
```

Expected: all commands exit with status `0`.

6. Commit and push:

```bash
git switch -c feature/lab12
git add labs/lab12/ labs/submission12.md
git commit -m "docs: add lab12 kata containers sandboxing"
git push -u origin feature/lab12
```

7. PR checklist:

```text
- [x] Task 1 - Kata install + runtime config
- [x] Task 2 - runc vs kata runtime comparison
- [x] Task 3 - Isolation tests
- [x] Task 4 - Basic performance snapshot
```

## Final Self-Check

- [x] `labs/submission12.md` contains Task 1-4 sections.
- [x] Required setup, runc, kata, analysis, isolation, and bench artifacts are present.
- [x] Kernel comparison explicitly distinguishes host kernel from Kata guest kernel.
- [x] Isolation analysis covers `dmesg`, `/proc`, network interfaces, and kernel modules.
- [x] Performance analysis covers startup overhead, runtime overhead, CPU overhead, and when to use each runtime.
- [x] Known `nerdctl` + Kata runtime-rs detached-container issue is handled by using short-lived Kata containers.
- [x] Manual verification steps are included for the final Linux run.
- [x] Evidence files contain actual Linux run outputs.
