# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment

- Kernel: `Linux wyrox 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:32:02 UTC 2 aarch64 aarch64 aarch64 GNU/Linux`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 Jul 16 14:52 /dev/kvm`
- containerd: `containerd containerd v2.2.6 11ce9d5f3c68c941867e82890e93e815c1304f1b`
- nerdctl: `nerdctl version 2.3.1`

### Kata installation

- Kata version: `3.32.0`
- Architecture: `arm64`
- Hypervisor: QEMU
- `kata-runtime kata-check`: `System can currently create Kata Containers`

containerd configuration:

```toml
[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
  privileged_without_host_devices = true
```

The static Kata bundle installed its binaries under `/opt/kata`. The shim was
made discoverable at `/usr/local/bin/containerd-shim-kata-v2`, and the standard
QEMU configuration was installed at `/etc/kata-containers/configuration.toml`.
On this ARM host, the optional `cpu_features = "pmu=off"` setting was disabled
because the bundled QEMU rejected that property; `kata-runtime kata-check`
still confirmed that the host could create Kata containers.

### Kernel inside containers

**runc:**

```text
Linux c1d1ef443e6c 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:32:02 UTC 2 aarch64 Linux
processor	: 0
BogoMIPS	: 48.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm sb paca pacg dcpodp flagm2 frint i8mm bf16 bti afp
```

**Kata:**

```text
Linux c76bc17abc37 6.18.35 #1 SMP Mon Jun 15 12:55:03 UTC 2026 aarch64 Linux
processor	: 0
BogoMIPS	: 48.00
Features	: fp asimd aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm sb dcpodp flagm2 frint i8mm bf16 afp
```

The runc container reports the host's `6.17.0-40-generic` kernel because OCI
containers share the host kernel. Kata reports its own `6.18.35` guest kernel
because the workload runs inside a micro-VM. For attacks such as
CVE-2024-21626, this extra runtime boundary means a container-runtime or
shared-kernel escape class can be contained by the guest VM rather than
directly exposing the host, provided the host has not deliberately shared the
target resource into that VM.

## Task 2: Isolation + Performance

### Isolation: `/dev` diff

```diff
1d0
< core
```

The tested runc container exposed the additional `/dev/core` entry. Otherwise,
the basic device lists were the same:

```text
fd full mqueue null ptmx pts random shm stderr stdin stdout tty urandom zero
```

The small device-list difference should not be overstated: the meaningful
isolation evidence is the separate guest kernel and virtualized device model.

### Isolation: capability sets

**runc:**

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

**Kata:**

```text
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

The capability masks were identical. Kata does not automatically reduce the
OCI capability set; it changes what those capabilities can reach by placing
the container and its capabilities inside a separate guest kernel.

### Startup time

```text
=== runc ===
1: .445792357 s
2: .445852535 s
3: .416185024 s
4: .452104337 s
5: .465813837 s
=== kata ===
1: 64.056078259 s
2: 74.087136806 s
3: 45.440728953 s
4: 79.793650898 s
5: 71.807288199 s
```

| Runtime | Five-run average |
|---------|-----------------:|
| runc | 0.445150 s |
| Kata | 67.036977 s |

The measured Kata cold-start overhead was approximately **150.59×**. This is
far above Reading 12's typical estimate and appears specific to this ARM64
QEMU setup: guest boots repeatedly took 45–80 seconds. These are the observed
values rather than substituted expected values.

### I/O throughput

The required command writes 100 MB from `/dev/zero` to `/dev/null`. It mainly
measures memory-copy and guest execution overhead, not persistent storage.

| Runtime | Time | Reported throughput |
|---------|-----:|--------------------:|
| runc | 0.004152 s | 23.5 GB/s |
| Kata | 0.092748 s | 1.1 GB/s |

Kata was approximately **21.36× slower** in reported throughput for this
microbenchmark. The result is consistent with an additional VM boundary, but
it should not be generalized to disk or application I/O without a workload
that actually uses a filesystem or network device.

### Trade-off analysis

I would deploy Kata for long-lived, multi-tenant services or CI runners that
execute customer-controlled code, where containing a kernel/runtime escape is
worth additional memory, operational complexity, and slower startup. I would
not use this measured configuration for short-lived FaaS jobs or trusted,
single-tenant batch tasks because a roughly 67-second cold start dominates
their useful work. CPU-heavy, longer-running services are better candidates
than highly ephemeral or latency-sensitive workloads. Production selection
should therefore be based on representative workload measurements rather than
the microbenchmarks alone.

## Bonus: Privileged Host Bind-Mount Test

### Vector chosen

- **Option:** B — privileged container with an explicit host bind mount.
- **Why:** It is reproducible on the current patched host and tests the exact
  command recommended by the lab without installing a deliberately vulnerable
  runc or kernel.

### runc: host write succeeds

Command:

```bash
sudo nerdctl run --rm --privileged -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
OVERWRITTEN BY RUNC CONTAINER
```

Host verification:

```text
OVERWRITTEN BY RUNC CONTAINER
```

### Kata: observed behavior

The identical `--privileged` Kata command did not start successfully with Kata
3.32.0 on this host. It failed while creating an already-existing guest device:

```text
failed to create shim task: Creating container device LinuxDevice {
  path: "/dev/full", typ: C, major: 1, minor: 7, ...
}
Caused by:
  EEXIST: File exists
```

The recommended containerd CRI setting
`privileged_without_host_devices = true` was then enabled and containerd was
restarted. The failure still occurred because `nerdctl run` uses containerd's
direct task API rather than the CRI runtime path where that option is applied.
This nerdctl version does not expose an equivalent per-command flag.

The installed `ctr` CLI does expose the required direct-task option. The
following workaround successfully started a privileged Kata container:

```bash
sudo ctr run --rm --runtime io.containerd.kata.v2 \
  --privileged --privileged-without-host-devices \
  docker.io/library/alpine:3.20 lab12-kata-privileged-test \
  echo 'privileged kata works'
```

```text
privileged kata works
```

This confirms that nested virtualization and privileged Kata can work on the
host when automatic host-device injection is disabled. It does not make the
lab's exact nerdctl command equivalent, because nerdctl 2.3.1 lacks that flag.

The host target remained `original` after that failed start. This is not
presented as proof that Kata blocked the filesystem write, because the
container process never ran.

To isolate the bind-mount behavior from the unrelated privileged-device error,
I repeated the same mount and write without `--privileged`:

```bash
sudo nerdctl run --rm --runtime=io.containerd.kata.v2 \
  -v /tmp:/host_tmp alpine:3.20 \
  sh -c 'echo "KATA BIND WRITE" > /host_tmp/lab12-target && cat /host_tmp/lab12-target'
```

Container output:

```text
KATA BIND WRITE
```

Host verification:

```text
KATA BIND WRITE
```

### Threat-model implication and limitation

Kata's separate kernel blocks attacks that depend on directly reaching the
host kernel from an ordinary container. It does **not** make an explicitly
shared host directory private: with the tested virtio-fs configuration,
`-v /tmp:/host_tmp` exports the host path into the micro-VM, and writes are
propagated back to the host. Therefore, the lab's expected claim that this bind
mount targets only a micro-VM-local filesystem was not true in this test.

For multi-tenant CI, Kata remains useful when tenant jobs do not receive
privileged host resources, but it cannot compensate for deliberately granting
a writable host bind mount. It also does not eliminate hypervisor flaws,
side-channel attacks, cross-tenant timing leakage, or risks from devices and
directories intentionally passed through to the guest. A true runc-CVE
comparison would require a disposable VM with a deliberately vulnerable runc
version and must not be inferred from this bind-mount test.
