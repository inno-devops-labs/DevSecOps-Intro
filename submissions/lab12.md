# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux thornCrown 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`
- KVM accessible: `crw-rw---- 1 root kvm 10, 232 Jul 16 16:39 /dev/kvm` (modules `kvm_amd`, `kvm` loaded; nested virtualization exposed — `svm` flag present on all 12 CPU threads)
- containerd version: `containerd github.com/containerd/containerd/v2 v2.3.0-beta.2 8a5337317f3216cd920283334f69b2f9003f75b2`

### Kata installation
- Kata version: **3.32.0** (static assets in `/opt/kata`, QEMU hypervisor)
- containerd config snippet:
```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
```

### Kernel inside containers
**runc:**
Linux 24be7027aac7 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25

**kata:**
Linux ff7392101551 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 25

The runc container reports the host's kernel verbatim (`6.18.33.2-microsoft-standard-WSL2`, built
Jun 18) — it is the same kernel, just namespaced. The Kata container reports `6.18.35` (built Jun 15),
a completely different build with no `-microsoft-standard-WSL2` suffix: this is Kata's own guest
kernel, booted inside a QEMU/KVM micro-VM.

### Why the kernel differs (Reading 12)
runc containers are processes on the host kernel — namespaces and cgroups only *partition* that one
shared kernel, so a bug in it is a bug in every container's trust boundary. CVE-2024-21626 ("Leaky
Vessels") exploited exactly this: a leaked file descriptor pointing into the host filesystem let a
malicious image escape the namespace, because there was only one kernel and one filesystem namespace
tree to break out of. Kata changes the topology rather than patching the bug — each container boots
its own guest kernel (`6.18.35` above) inside a hardware-virtualized VM, so a container-escape
primitive of that class lands the attacker in a disposable micro-VM, not on the host; they would need
a second, far rarer exploit — a hypervisor/KVM escape — to reach `6.18.33.2-microsoft-standard-WSL2`.
That is the "two bugs instead of one" property Reading 12 describes, and it is why Kata is
positioned for untrusted multi-tenant workloads.

## Task 2: Isolation + Performance

### Isolation: /dev diff
1d0
< core
Only one difference: runc exposes `/dev/core` (a legacy symlink to `/proc/kcore`), Kata does not.
Every other device node is identical — Kata does not present a materially different device set to the
workload.

### Isolation: capability sets
runc:
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

kata:
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

Byte-for-byte identical — both runtimes grant the same default OCI capability set (`a80425fb`). This
is the instructive result: Kata's isolation is **invisible from inside the container**. It is not more
restrictive at the API level; the difference is one layer down — under runc those capabilities apply
to the host kernel, under Kata to a disposable guest kernel.

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | 0.818 |
| kata | 2.545 |

**Overhead: ~3.1× cold start** (Reading 12's table expects ~5×; the measured gap is smaller here,
though this run is under nested virtualization in WSL2 — on bare metal Kata usually boots faster
still). The 1.73 s delta is the micro-VM boot: QEMU initialises virtual hardware and boots the
6.18.35 guest kernel before the workload's first instruction, whereas runc only wires up namespaces
and cgroups around a process on the already-running host kernel.

### I/O throughput (100MB dd)
| Runtime | Throughput | Time |
|---------|-----------|-----:|
| runc | 26.3 GB/s | 0.003716 s |
| kata | 20.6 GB/s | 0.004736 s |

Kata reaches ~78% of runc's throughput (≈22% slower). The penalty is the virtio path — the guest
kernel's I/O traverses a virtualized device to the host instead of issuing syscalls directly against
the host kernel. This is a memory-to-memory test (`/dev/zero` → `/dev/null`), so it isolates the
virtualization tax itself; on real disk or network I/O the relative gap typically narrows because
physical device latency dominates.

### Trade-off analysis
The security gain is worth it wherever you run **code you did not write and cannot trust**:
multi-tenant SaaS, CI runners executing arbitrary PRs, or a serverless platform running customer
functions — there, a single runc-class CVE like Leaky Vessels means one hostile tenant owns every
other tenant on the box, and 1.7 s of extra boot plus 22% I/O is trivial next to that blast radius.
It is not worth it for **single-tenant workloads where you already trust the code**: an internal
batch job, your own microservice fleet, or a latency-critical service where cold start is the product
— there Kata pays a real cost to defend against an attacker who, by definition, is already inside
your trust boundary, and the same budget spent on patching, seccomp and dropping capabilities buys
more. The honest framing from Reading 12 is that Kata is not "more secure containers" but a different
answer to one question: *when the container's kernel is compromised, whose kernel was it?* — pay for
that answer only when the kernel is genuinely shared with someone hostile.

## Bonus: Container-Escape PoC

### Vector chosen
- **Option:** B — Privileged-container host write
- **Why:** It's the most common real-world misconfiguration (`--privileged` + a host bind-mount) and
  needs no CVE — the escape *is* the flag — so the runc-vs-Kata contrast is maximally visible.

### runc: escape succeeds
Command:
```bash
sudo touch /tmp/lab12-target
sudo chown root:root /tmp/lab12-target
echo "original" | sudo tee /tmp/lab12-target

sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```
Container output:
OVERWRITTEN BY RUNC CONTAINER

Host verification:
$ sudo cat /tmp/lab12-target
OVERWRITTEN BY RUNC CONTAINER

### Kata: escape blocked
Command:
```bash
echo "original" | sudo tee /tmp/lab12-target

sudo nerdctl run --rm --runtime=io.containerd.kata.v2 --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view---"'
```
Container output:
WARN cannot set cgroup manager to "systemd" for runtime "io.containerd.kata.v2"
FATA failed to create shim task: Creating container device
LinuxDevice { path: "/dev/full", typ: C, major: 1, minor: 7, ... }
Caused by:
EEXIST: File exists

Host verification:
$ sudo cat /tmp/lab12-target
original

The host file still reads `original` — the write never touched it. The Kata container never even
started: `--privileged` tries to project host device nodes into the sandbox, but Kata would have to
create them inside the guest VM where they already exist, so the runtime aborts (`EEXIST` on
`/dev/full`) at container creation.

### Threat model implication
**Why Kata blocks what runc allows:** under runc there is one shared kernel and one filesystem, so
`-v /tmp:/host_tmp` mounts the *real* host `/tmp` and `--privileged` strips the guards that would
stop the write. Under Kata the container runs in a micro-VM with its own kernel and root filesystem —
a host bind-mount is virtualized via virtio-fs/9p *inside* the VM, so `/host_tmp` is at most the
guest's view, never the host disk; reaching the host would require first escaping QEMU/KVM. Here the
attack failed even earlier, because privileged device passthrough is meaningless across a VM boundary.
**Real-world mapping:** this is the multi-tenant CI runner executing arbitrary PRs in `--privileged`
containers, or a misconfigured Kubernetes pod with `securityContext.privileged: true` and a
`hostPath` volume — on runc one hostile tenant owns the node; on Kata the same misconfiguration is
inert. **What it does NOT block:** Kata stops filesystem and kernel *escape*, but not pure side-
channel attacks against the CPU or hypervisor — cross-tenant timing/cache attacks (Spectre-class) or
leakage through shared microarchitectural state cross a VM boundary untouched. Those need the memory
encryption and attestation of Reading 12's Confidential Containers (AMD SEV-SNP / Intel TDX — note the
`qemu-system-x86_64-snp-experimental` and `-tdx-experimental` binaries already present in
`/opt/kata/bin`).
