# Lab 12 Submission - Kata Containers: VM-backed Container Sandboxing

## Student

- GitHub username: `ellilin`
- Branch: `feature/lab12`
- Date: `2026-04-26`
- Environment: macOS host with Docker Desktop; Linux test node inside the existing `minikube` container (`aarch64`, containerd 1.7.24, nerdctl 1.7.24)

## Important Environment Finding

The lab prerequisite requires a Linux host with hardware virtualization exposed. The available local execution environment is macOS + Docker Desktop. I used the running Linux `minikube` container as the closest available containerd host, but it does not expose hardware virtualization:

```text
Linux minikube 6.10.14-linuxkit #1 SMP Thu Aug 14 19:26:13 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
virt_flags:
0
kvm:
ls: cannot access '/dev/kvm': No such file or directory
```

Kata was installed and wired into containerd, but Kata VM startup fails because the Docker Desktop/minikube container cannot provide the hypervisor device boundary:

```text
time="2026-04-26T16:05:26Z" level=fatal msg="failed to create shim task: Could not create the sandbox resource controller failed to add any hypervisor device to devices cgroup: unknown"
```

Because of that, this submission includes successful setup and runc baseline evidence, plus the exact Kata failure evidence and the expected isolation/security analysis.

## Artifacts

- [kata-setup-evidence.txt](lab12/setup/kata-setup-evidence.txt)
- [runtime-versions.txt](lab12/setup/runtime-versions.txt)
- [test-run-attempt.txt](lab12/kata/test-run-attempt.txt)
- [health.txt](lab12/runc/health.txt)
- [kernel-comparison.txt](lab12/analysis/kernel-comparison.txt)
- [cpu-comparison.txt](lab12/analysis/cpu-comparison.txt)
- [proc.txt](lab12/isolation/proc.txt)
- [dmesg.txt](lab12/isolation/dmesg.txt)
- [network.txt](lab12/isolation/network.txt)
- [modules.txt](lab12/isolation/modules.txt)
- [startup.txt](lab12/bench/startup.txt)
- [kata-startup-attempt.txt](lab12/bench/kata-startup-attempt.txt)
- [http-latency.txt](lab12/bench/http-latency.txt)
- [curl-3012.txt](lab12/bench/curl-3012.txt)

## Task 1 - Install and Configure Kata

Kata static assets for arm64 were installed into the Linux minikube node using the provided `install-kata-assets.sh` workflow. The shim was installed to `/usr/local/bin/containerd-shim-kata-v2`, and containerd was configured with `io.containerd.kata.v2`.

Shim/version evidence:

```text
Kata Containers containerd shim (Golang): id: "io.containerd.kata.v2", version: 3.29.0, commit: 8dccf4cf37aeea4b6c2caacf3e61510d6eef2f71
```

Runtime configuration evidence:

```text
71:[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
72-  runtime_type = 'io.containerd.kata.v2'
```

The runtime was recognized by containerd/nerdctl, but test execution failed at VM sandbox creation due to the host environment:

```text
time="2026-04-26T16:05:26Z" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
time="2026-04-26T16:05:26Z" level=fatal msg="failed to create shim task: Could not create the sandbox resource controller failed to add any hypervisor device to devices cgroup: unknown"
```

## Task 2 - Run and Compare Containers

The runc Juice Shop baseline started successfully with nerdctl:

```text
juice-runc: HTTP 200
```

Kernel comparison:

```text
Host kernel (runc uses this): 6.10.14-linuxkit
runc alpine kernel: 6.10.14-linuxkit
```

This confirms the key runc property: the container sees and uses the same kernel as the host Linux VM. Kata should instead boot a separate guest kernel inside a lightweight VM; in this environment that comparison could not complete because the Kata VM never reached guest execution.

CPU comparison on this Apple Silicon/LinuxKit environment uses ARM `/proc/cpuinfo` fields rather than x86 `model name`. The runc container sees the same CPU characteristics exposed by the LinuxKit host. A successful Kata run would normally show the virtualized CPU as exposed by the selected hypervisor.

Isolation implications:

- `runc`: process, mount, network, user, and cgroup namespaces isolate the workload, but the container still shares the host kernel. A kernel escape or kernel bug has direct host impact.
- `Kata`: the workload runs behind both container namespaces and a guest VM boundary. A container escape first lands in the guest VM, so reaching the host requires an additional VM/hypervisor escape.

## Task 3 - Isolation Tests

The runc baseline demonstrates shared-kernel behavior:

```text
=== /proc Entries Count ===
Host: 164
runc alpine: 58
```

The runc container has a reduced process view due to PID namespace isolation, but it still runs on the host kernel:

```text
Host kernel modules: 111
runc-visible kernel modules: 111
```

The dmesg test showed that unprivileged runc containers cannot read kernel logs:

```text
dmesg: klogctl: Operation not permitted
```

That is good default hardening, but it is not the same as a separate kernel. In a successful Kata run, `dmesg` would show guest VM boot logs, proving that the workload is observing a guest kernel rather than the host kernel.

Network evidence was collected for runc in [network.txt](lab12/isolation/network.txt). Kata network-interface evidence could not be produced because guest startup failed before the VM network stack was available.

Security implications:

- Container escape in `runc`: an attacker that breaks namespace/container isolation reaches the same Linux kernel used by the host and other containers.
- Container escape in `Kata`: an attacker that breaks the container boundary reaches the guest VM first. Host compromise requires a second escape across the VM or hypervisor boundary.

## Task 4 - Performance Comparison

runc startup for a short Alpine command:

```text
runc:
real	0m0.197s
```

Kata did not successfully start in this environment. The measured Kata line in [startup.txt](lab12/bench/startup.txt) is only failed-start latency, not valid VM startup performance:

```text
Kata:
real	0m0.061s
Note: Kata timing is failed-start latency, not successful VM startup; see kata-startup-attempt.txt.
```

Juice Shop HTTP latency baseline under runc:

```text
avg=0.0012s min=0.0005s max=0.0044s n=50
```

Performance trade-offs:

- Startup overhead: runc starts quickly because it creates namespaces and cgroups on the existing kernel; Kata normally has higher startup cost because it must create a lightweight VM and boot or resume a guest environment.
- Runtime overhead: runc has the lowest overhead. Kata adds a VM boundary, virtualized devices, and guest/host coordination, which can add latency depending on workload and I/O pattern.
- CPU overhead: CPU-bound workloads may be close to native with hardware virtualization, but Kata still pays some overhead for VM management and device emulation or paravirtualization.

Recommendation:

- Use `runc` for trusted workloads, local development, high-density deployments, and latency-sensitive services where the shared host-kernel risk is acceptable.
- Use `Kata` for untrusted or multi-tenant workloads, CI job isolation, plugin execution, risky customer workloads, or services where stronger tenant isolation is worth slower startup and higher operational complexity.

## Deliverable Checklist

- [x] Task 1 - Kata shim installed and containerd runtime configured
- [x] Task 2 - runc Juice Shop baseline captured; Kata run attempted and blocker documented
- [x] Task 3 - runc isolation evidence captured; Kata isolation blocker documented
- [x] Task 4 - runc performance baseline captured; Kata startup blocker documented

## Bonus Task

No separate bonus task is listed inside `labs/lab12.md`. Lab 12 itself is the optional bonus lab described in the course `README.md`.
